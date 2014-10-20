#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if_arp.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#include "ipscan.h"
#include "zhuxi_debug.h"

static int 				arpsock;
char 					devname[16];
char 					outfile[64];
char 					configfile[64];
static struct in_addr	ipaddr,netmask;
static unsigned short	add=0;				
sigset_t				g_ns;
struct devinfo			*devinfo_list = NULL;
struct scanaddr			*scanaddr_list = NULL;
struct ipmac			*ipmac_list[256];
static int				recv_pkt = 0;
static int				idle = 0;
static int				scan_max_time = 0;
static char 			exphosts[IPMAC_EXPHOST_MAX][32];

static int pack_count = 1;
static int time_out = 3;

typedef struct IpPool{
	char *name;
	struct IpPool *next;
}T_IpPool, *PT_IpPool;

typedef struct IpScanAddr{
	struct in_addr start_ip;
	struct in_addr end_ip;
	struct IpScanAddr *next;
}T_IpScanAddr, *PT_IpScanAddr;

PT_IpPool IpPoolHead;
PT_IpScanAddr IpScanAddrHead;

static void usage()
{
	printf("usage:  ipscan < -i ip_pool > [-c pack_count] [-w timeval] [ -d devname ] [-o outputfile]\n");
    exit(1);
}

int main(int argc,char **argv)
{
	struct sockaddr_ll		arpfrom,arpto;
	struct timeval			tv_out;
	socklen_t				alen=sizeof(struct sockaddr_ll);
	unsigned char			buf[128];
	ETH_HEADER 				*ethh=(ETH_HEADER *)buf;
	ARP_HEADER 				*arph=(ARP_HEADER *)(ethh+1);
	uint32_t				cur,max;
	PT_IpScanAddr 				si;
	/*pthread_t 				tid = 0;*/

	int						i,j,on=1,count = 0;
	
	parse_args(argc,argv);

	if(!(arpsock=create_arpsock(devname,&arpfrom)))
		return 1;

	for(i=0;i<256;i++)
		ipmac_list[i] = NULL;
	get_devinfo(devname);
	/*get_scan_list();*/
	get_exphost();
	/*if(add)*/
		/*read_macband_list();*/
	
 	tv_out.tv_sec=TIMEOUT_SEC;
 	tv_out.tv_usec=TIMEOUT_USEC;
	setsockopt(arpsock,SOL_SOCKET,SO_RCVTIMEO,&tv_out,sizeof(tv_out));

	if(getsockname(arpsock,(struct sockaddr *)&arpfrom,&alen) == -1){
		ZHUXI_DBGP(("getsockname failed !\n"));
		return 1;
	}
	memcpy(&arpto,&arpfrom,sizeof(struct sockaddr_ll));
	memset(arpto.sll_addr, -1,arpto.sll_halen);
	
	
	memset(buf,0,sizeof(buf));
	memcpy(ethh->d_mac,arpto.sll_addr,ETH_ALEN);
	memcpy(ethh->s_mac,arpfrom.sll_addr,ETH_ALEN);
	ethh->proto_type = htons(ETH_P_ARP);

	arph->hw_type = htons(ARPHRD_ETHER);
	arph->proto_type = htons(ETH_P_IP);
	arph->mac_len = ETH_ALEN;
	arph->ip_len = 4;
	arph->opcode = htons(ARPOP_REQUEST);
	
	memcpy(arph->s_mac,arpfrom.sll_addr,ETH_ALEN);
	memcpy(arph->d_mac,arpto.sll_addr,ETH_ALEN);
	
	if(!(si=IpScanAddrHead))
		return 1;

	alen = sizeof(struct sockaddr_ll);

	signal(SIGIO,recv_arp_pkt);
	fcntl(arpsock,F_SETOWN,getpid());
	ioctl(arpsock,FIOASYNC,&on);
	ioctl(arpsock,FIONBIO,&on);
	sigemptyset(&g_ns);
	sigaddset(&g_ns,SIGIO);

	while(j <= pack_count)
	{
		si=IpScanAddrHead;
		while(si){
			cur = ntohl(si->start_ip.s_addr);
			max = ntohl(si->end_ip.s_addr);
			for(cur;cur<=max;cur++){
				if(count++ > MAX_SCAN_IP)
					break;
				if(!(cur & 0xFF) || (cur & 0xFF) == 0xFF)
					continue;
				if(!(get_sendip(cur,(struct in_addr *)arph->s_ip)))
					continue;
				if(htonl(cur) == ((struct in_addr *)arph->s_ip)->s_addr)
					continue;

				((struct in_addr *)arph->d_ip)->s_addr = htonl(cur);
				sendto(arpsock,buf,ETH_LEN+ARPH_LEN,0,(struct sockaddr*)&arpto,alen);
				usleep(1000);
			}
		si = si->next;
			if(count > MAX_SCAN_IP)
				break;
		}
		j++;
	}
	sleep(time_out);
	signal(SIGALRM,stop_recv_arp);
	alarm(1);
	while(1){
		sleep(100);
	};
	return 0;
}
static void parse_args( int argc, char** argv )
{
	int				c;
	char *token = NULL, *tmp[2];
	int i = 0;
	int length = 0;
	int token_flag = 0;
	struct in_addr	startip,endip;
	PT_IpPool ptmp, psave;
	PT_IpPool IpPoolTmp;
	PT_IpScanAddr pIpScanAddrtmp, pIpScanAddrSave;
	PT_IpScanAddr IpScanAddrTmp;

	if(argc < 3)
		usage();

	memset(devname,0,sizeof(devname));
	memset(&ipaddr,0,4);
	startip.s_addr = 0;
	endip.s_addr = 0;
	while((c=getopt(argc,argv,"c:w:d:i:o:")) != -1){
		switch(c){
			case 'c':
				pack_count = atoi(optarg);
			  	break;
			case 'w':
				time_out= atoi(optarg);
			  	break;

			case 'i':
				if (IpPoolHead != NULL)
				{
					IpPoolHead = NULL;
				}
				if (!(IpPoolTmp = (PT_IpPool)malloc(sizeof(struct IpPool))))
				{
					ZHUXI_DBGP(("malloc failed !\n"));
					return;
				}
				IpPoolTmp->name = strtok(optarg, ",");
				IpPoolHead = IpPoolTmp;
				IpPoolTmp->next = NULL;
				while((token = strtok(NULL, ",")) != NULL)
				{
					if (!(IpPoolTmp= (PT_IpPool)malloc(sizeof(struct IpPool))))
					{
						ZHUXI_DBGP(("malloc failed !\n"));
						return;
					}
					IpPoolTmp->name = token;
					if (IpPoolHead == NULL)
					{
						IpPoolHead = psave;
					}
					else
					{
						ptmp = IpPoolHead;
						while (ptmp->next)
						{
							ptmp = ptmp->next;
						}
						ptmp->next = IpPoolTmp;
						IpPoolTmp->next = NULL;
					}
				}

				ptmp = IpPoolHead;

				while(ptmp)
				{
					tmp[0] = strtok(ptmp->name, "-");
					/*printf("tmp[0] = %s\n", tmp[0]);*/

					while((token = strtok(NULL, "-")) != NULL)
					{
						tmp[1] = token;
						token_flag = 1;
					}

					if (!token && token_flag == 0)
					{
						tmp[1] = tmp[0];
					}

					if(!inet_aton(tmp[0], &startip)){
						 ZHUXI_DBGP(("%s : bad IP address format !\n",tmp[0]));
						 usage();
					 }
					if(!inet_aton(tmp[1], &endip)){
						 ZHUXI_DBGP(("%s : bad IP address format !\n",tmp[0]));
						 usage();
					 }

					/*IpScanAddrTmp.start_ip.s_addr = startip.s_addr;*/
					/*IpScanAddrTmp.end_ip.s_addr = endip.s_addr;*/
					if (!(IpScanAddrTmp = (PT_IpScanAddr)malloc(sizeof(struct IpScanAddr))))
					{
						ZHUXI_DBGP(("malloc failed !\n"));
						return;
					}
					IpScanAddrTmp->start_ip = startip;
					IpScanAddrTmp->end_ip = endip;
					if (IpScanAddrHead == NULL)
					{
						IpScanAddrHead = IpScanAddrTmp;
						IpScanAddrTmp->next = NULL;
					}	
					else
					{
						pIpScanAddrtmp = IpScanAddrHead;
						while(pIpScanAddrtmp->next)
						{
							pIpScanAddrtmp = pIpScanAddrtmp->next;
						}
						pIpScanAddrtmp->next = IpScanAddrTmp;
						IpScanAddrTmp->next = NULL;
					}
					ptmp = ptmp->next;
				}
				/*pIpScanAddrtmp = IpScanAddrHead;*/
#if 0
				while(pIpScanAddrtmp)
				{
					length++;
					pIpScanAddrtmp = pIpScanAddrtmp->next;
				}
				printf("length = %d\n", length);
#endif
				break;
			case 'd':
				strncpy(devname,optarg,sizeof(devname));
			  	break;
			case 'o':
				strncpy(outfile,optarg,sizeof(outfile));
				break;
			default :
				usage();
		}
	}
	if (optind != argc) 
		usage();

	if(!strlen(devname))
		strncpy(devname,DEFDEV,sizeof(devname));
	if(!strlen(outfile))
		strncpy(outfile,DEF_FILE,sizeof(outfile));
		
	/*ZHUXI_MSGP(("configfile=%s,ipaddr=%s,",configfile,inet_ntoa(ipaddr)));*/
}

static int create_arpsock(char *ifname,struct sockaddr_ll *from)
{
	struct ifreq 			ifr;
	int						ifindex;
	int						ret;
	int						sock;
	socklen_t				alen = sizeof(struct sockaddr_ll);

	if((sock = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ARP))) == -1){
		ZHUXI_DBGP(("create socket failed !\n"));
		return 0;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name,ifname, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		ZHUXI_DBGP(("interface %s not found !\n",ifname));
		return 0;
	}
	ifindex = ifr.ifr_ifindex;
	if (ioctl(sock, SIOCGIFFLAGS, (char *) &ifr)) {
		ZHUXI_DBGP(("SIOCGIFFLAGS !\n"));
		return 0;
	}
	if (!(ifr.ifr_flags & IFF_UP)) {
		ZHUXI_DBGP(("interface %s is down !\n",ifname));
		return 0;
	}
	if (ifr.ifr_flags & (IFF_NOARP | IFF_LOOPBACK)) {
		ZHUXI_DBGP(("interface  %s is not ARPable",ifname));
		return 0;
	}

	from->sll_family = AF_PACKET;
	from->sll_ifindex = ifindex;
	from->sll_protocol = htons(ETH_P_ARP);

	if((ret=bind(sock,(struct sockaddr*)from,alen)) == -1){
		ZHUXI_DBGP(("bind failed !\n"));
		return 0;
	}
	
	return sock;
}

#if 0
void read_macband_list(void)
{
	FILE					*fd;
	char					*str;
	struct ipmac			**mli[256];
	char					buf[256];
	char					notes[64];
	char					ipaddr[32];
	int						i;
	struct in_addr			ip;
    unsigned int 			a, b, c, d, e, f;

	if(!(fd=fopen(MACBAND_FILE,"r"))){
		ZHUXI_DBGP(("fopen %s failed !\n",MACBAND_FILE));
		return;
	}
	for(i=0;i<256;i++)
		mli[i] = &ipmac_list[i];

	while((str=fgets(buf,sizeof(buf),fd))){
		if(strlen(buf) < 20)
			continue;
		if((sscanf(str,"%s %X:%X:%X:%X:%X:%X %s",ipaddr,&a,&b,&c,&d,&e,&f,notes)) != 8 || !inet_aton(ipaddr,&ip))
			continue;
		if(check_exphost(ipaddr))
			continue;
		if(!((*mli[f])=malloc(sizeof(struct ipmac)))){
			ZHUXI_DBGP(("malloc failed !\n"));
			continue;
		}
		(*mli[f])->ip.s_addr = ip.s_addr;
		(*mli[f])->mac[0] = (unsigned char) a;
		(*mli[f])->mac[1] = (unsigned char) b;
		(*mli[f])->mac[2] = (unsigned char) c;
		(*mli[f])->mac[3] = (unsigned char) d;
		(*mli[f])->mac[4] = (unsigned char) e;
		(*mli[f])->mac[5] = (unsigned char) f;
		(*mli[f])->bind = 1;
		strcpy((*mli[f])->notes,notes);
		(*mli[f])->next = NULL;
		mli[f] = &(*mli[f])->next;
	}
	fclose(fd);
/*	
	struct ipmac			*mi;
	for(i=0;i<256;i++){
		mi = ipmac_list[i];
		while(mi){
			printf("ip=%s,mac=%02X:%02X:%02X:%02X:%02X:%02X,bind=%d=\n",inet_ntoa(mi->ip),\
				mi->mac[0],mi->mac[1],mi->mac[2],mi->mac[3],mi->mac[4],mi->mac[5],mi->bind);
			mi = mi->next;
		}
	}
*/
}

#endif
static void unpack_arp(char *buf,int sz,struct sockaddr_ll *ans, long int seconds)
{
	int						chk = 0;
	ETH_HEADER *ethh = (ETH_HEADER *)buf;
	ARP_HEADER *arph = (ARP_HEADER *)(ethh + 1);
	struct ipmac			**mli;
	struct devinfo			*di=devinfo_list;
	uint8_t					ins = 0;
	struct net_dev			*net_dev_tmp;

	if (sz < 42) 	/* ETH_LEN+ARPH_LEN = 42 */
		return;

	if (ans->sll_pkttype != PACKET_HOST &&
		ans->sll_pkttype != PACKET_BROADCAST &&
		ans->sll_pkttype != PACKET_MULTICAST)
		return;

	if((ethh->proto_type != htons(ETH_P_ARP)) || (arph->opcode != htons(ARPOP_REPLY)))
		return;
		
	if (arph->hw_type != htons(ans->sll_hatype) &&
		(ans->sll_hatype != ARPHRD_FDDI
		 || arph->hw_type != htons(ARPHRD_ETHER)))
		return;

	if((arph->proto_type != htons(ETH_P_IP)) || (arph->mac_len != ETH_ALEN) || (arph->ip_len != 4))
		return;

	while(di){
		if(di->ipaddr.s_addr == *(uint32_t *)arph->s_ip)
			return;
		if((*(uint32_t *)arph->s_ip & di->netmask.s_addr) == di->netaddr.s_addr)
			chk = 1;
		di = di->next;
	}
	if(!chk)
		return;
	mli = &ipmac_list[arph->s_mac[5]]; /*hash func*/
	while(*mli){
		if(!(memcmp((char *)(*mli)->net_dev.mac,(char *)arph->s_mac,6))){
			net_dev_tmp = &(*mli)->net_dev;
			while(net_dev_tmp)
			{
				if(net_dev_tmp->ip.s_addr == *(uint32_t *)arph->s_ip)
					return;
				if(!(net_dev_tmp->bind)){
					memcpy(&net_dev_tmp->ip,arph->s_ip,4);
					ins = 1;
					break;
			}
				net_dev_tmp = net_dev_tmp->next;
			}
				}
		}
		mli = &(*mli)->next;
	}
	if(!ins){
		if(check_exphost(inet_ntoa(*(struct in_addr *)arph->s_ip)))
			return;
		if(!(*mli=malloc(sizeof(struct ipmac)))){
			ZHUXI_DBGP(("malloc failed !\n"));
			return;
		}
		net_dev_tmp = &(*mli)->net_dev;
		while(net_dev_tmp->next)
		{
			net_dev_tmp = net_dev_tmp->next;
		}
		memcpy(&net_dev_tmp->ip,arph->s_ip,4);
		memcpy(&net_dev_tmp->mac,arph->s_mac,6);
		net_dev_tmp->bind = 0;
		net_dev_tmp->seconds = seconds;
		strcpy(net_dev_tmp->notes,"NONE");
		(*mli)->next = NULL;
		mli = &(*mli)->next;
	}

	recv_pkt = 1;
}
void recv_arp_pkt()
{
	int					ret;
	struct sockaddr_ll	ans_addr;
	socklen_t			alen=sizeof(ans_addr);
	char				data[256];
	long int seconds;

	memset(&ans_addr,0,alen);
	memset(data,0,sizeof(data));
	sigprocmask(SIG_BLOCK,&g_ns,NULL);
	while(1){
		if((ret=recvfrom(arpsock,data,sizeof(data),0,(struct sockaddr*)&ans_addr,&alen)) < 0){
			break;
		}
		seconds = time((time_t*)NULL);	
		/*printf("time = %ld\n", seconds);*/
		unpack_arp(data,ret,&ans_addr, seconds);
		seconds = 0;
	}
	sigprocmask(SIG_UNBLOCK,&g_ns,NULL);
}

static void get_devinfo(char *ifname)
{
	struct ifconf			ifconf;
	struct ifreq 			ifr;
	struct ifreq 			*ifreq;
	int						i;
	int						sockfd;
	char					buf[512];	
	struct devinfo			**dl=&devinfo_list;
	struct devinfo			*di;

	if((sockfd = socket(AF_INET,SOCK_DGRAM,0)) == -1){
		ZHUXI_DBGP(("create socket failed !\n"));
		exit(1);
	}

	ifconf.ifc_len = sizeof(buf);
	ifconf.ifc_buf = buf;
	memset(buf,0,sizeof(buf));
	if(ioctl(sockfd,SIOCGIFCONF,&ifconf)){
		ZHUXI_DBGP(("ioctl : SIOCGIFCONF failed!\n"));
		exit(1);
	}
	ifreq=(struct ifreq *)buf;
	for(i=(ifconf.ifc_len/sizeof(struct ifreq));i>0;i--){
		if(ifreq->ifr_flags == AF_INET){
			if(strncmp(ifreq->ifr_name,ifname,strlen(ifname))){
				ifreq++;
				continue;
			}else if(strlen(ifreq->ifr_name) > strlen(ifname)){
				if(ifreq->ifr_name[strlen(ifname)] != ':'){
					ifreq++;
					continue;
				}
			}
			if(!((*dl)=malloc(sizeof(struct devinfo)))){
				ZHUXI_DBGP(("malloc failed !\n"));
				exit(1);
			}
			strncpy((*dl)->ifname,ifreq->ifr_name,sizeof((*dl)->ifname));
			(*dl)->ipaddr.s_addr = ((struct sockaddr_in *)&(ifreq->ifr_addr))->sin_addr.s_addr;
			(*dl)->next=NULL;
			dl=&(*dl)->next;
		}
		ifreq++;
	}

	di=devinfo_list;
	while(di){
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name,di->ifname,IFNAMSIZ - 1);
		if(ioctl(sockfd,SIOCGIFNETMASK,&ifr)){
			ZHUXI_DBGP(("ioctl : SIOCGIFNETMASK failed,ifr_name=%s=!\n",ifr.ifr_name));
			exit(1);
		}
		di->netmask.s_addr = ((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr.s_addr;
		if(ioctl(sockfd,SIOCGIFBRDADDR,&ifr)){
			ZHUXI_DBGP(("ioctl : SIOCGIFBRDADDR failed!\n"));
			exit(1);
		}
		di->brdaddr.s_addr = ((struct sockaddr_in *)&(ifr.ifr_broadaddr))->sin_addr.s_addr;
		di->netaddr.s_addr = di->ipaddr.s_addr & di->netmask.s_addr;
		di=di->next;
	}
	shutdown(sockfd,SHUT_RDWR);
/*	
	di=devinfo_list;
	while(di){
		ZHUXI_MSGP(("ifname=%s,ipaddr=%s,",di->ifname,inet_ntoa(di->ipaddr)));
		ZHUXI_MSGP(("netmask=%s,",inet_ntoa(di->netmask)));
		ZHUXI_MSGP(("netaddr=%s,",inet_ntoa(di->netaddr)));
		ZHUXI_MSGP(("brdaddr=%s=\n",inet_ntoa(di->brdaddr)));
		di=di->next;
	}
*/
}

#if 0
static void get_scan_list(void)
{
	struct scanaddr			**sl=&scanaddr_list;
	FILE					*fd;
	char					buf[256];
	char					*str;
	char					lanip[32];
	char					lanmask[32];
	struct in_addr			ip,mask;

	if(strlen(configfile)){
		if(!(fd=fopen(configfile,"r"))){
			ZHUXI_DBGP(("fopen %s failed !\n",configfile));
			exit(1);
		}
		while((str=fgets(buf,sizeof(buf),fd))){
			if(strlen(buf) < 15)
				continue;
			sscanf(str,"%s %s ",lanip,lanmask);
			if(!(*sl=malloc(sizeof(struct scanaddr)))){
				ZHUXI_DBGP(("malloc failed !\n"));
				exit(1);
			}
		  	if(!inet_aton(lanip,&ip)){
				ZHUXI_DBGP(("%s : bad IP address format !\n",lanip));
				usage();
		  	}
		  	if(!inet_aton(lanmask,&mask)){
				ZHUXI_DBGP(("%s : bad IP address format !\n",lanmask));
				usage();
		  	}
			(*sl)->start_ip.s_addr = ip.s_addr & mask.s_addr;
			(*sl)->end_ip.s_addr = ip.s_addr & mask.s_addr | ~mask.s_addr;
			(*sl)->next = NULL;
			sl = &(*sl)->next;
		}
		fclose(fd);
	}else if(startip.s_addr != 0 && endip.s_addr != 0){
		if(!(*sl=malloc(sizeof(struct scanaddr)))){
			ZHUXI_DBGP(("malloc failed !\n"));
			exit(1);
		}
		(*sl)->start_ip.s_addr = startip.s_addr;
		(*sl)->end_ip.s_addr = endip.s_addr;
		(*sl)->next = NULL;
		sl = &(*sl)->next;
	}else {
		if(!(*sl=malloc(sizeof(struct scanaddr)))){
			ZHUXI_DBGP(("malloc failed !\n"));
			exit(1);
		}
		(*sl)->start_ip.s_addr = ipaddr.s_addr & netmask.s_addr;
		(*sl)->end_ip.s_addr = ipaddr.s_addr & netmask.s_addr | ~netmask.s_addr;
		(*sl)->next = NULL;
		sl = &(*sl)->next;		
	}
/*	
	struct scanaddr		*si = scanaddr_list;
	while(si){		
		ZHUXI_MSGP(("start_ip=%s,",inet_ntoa(si->start_ip)));
		ZHUXI_MSGP(("end_ip=%s=\n",inet_ntoa(si->end_ip)));
		si = si->next;
	}
*/
}
#endif
int get_sendip(uint32_t recvip,struct in_addr *sendip)
{
	struct devinfo			*di=devinfo_list;
	uint32_t				res = 0;
	uint32_t				n,b;
	while(di){
		n = ntohl(di->netaddr.s_addr);
		b = ntohl(di->brdaddr.s_addr);
		if(recvip>=n && recvip<=b){
			sendip->s_addr = di->ipaddr.s_addr;
			res = 1;
			break;
		}
		di = di->next;
	}
	return res;
}
void stop_recv_arp()
{
	FILE					*fd;
	struct ipmac			*mi;
	int						i;
	char					cpy_cmd[128];
	char					*str = NULL;
	struct net_dev			*net_dev_tmp;

	if(scan_max_time++ < SCAN_MAX_TIME){
		if(recv_pkt){
			recv_pkt = 0;
			idle = 0;
			alarm(1);
			return;
		}else if(idle++ < RECV_WAITTIME){
			alarm(1);
			return;		
		}
	}

	signal(SIGIO,SIG_IGN);
	shutdown(arpsock,SHUT_RDWR);

	if(!(fd=fopen(outfile,"w+"))){
		ZHUXI_DBGP(("fopen %s failed !\n",outfile));
		exit(1);
	}
	for(i=0;i<256;i++){
		mi = ipmac_list[i];
		while(mi){
//			fprintf(fd,"%s %02X:%02X:%02X:%02X:%02X:%02X %d %s\n",inet_ntoa(mi->ip),\
//				mi->mac[0],mi->mac[1],mi->mac[2],mi->mac[3],mi->mac[4],mi->mac[5],mi->bind,mi->notes);
			if(add){
				if(!mi->net_dev.bind)
					printf("%ld %02X:%02X:%02X:%02X:%02X:%02X %s * *\n", mi->net_dev.seconds,\
						mi->net_dev.mac[0],mi->net_dev.mac[1],mi->net_dev.mac[2],mi->net_dev.mac[3],mi->net_dev.mac[4],mi->net_dev.mac[5], inet_ntoa(mi->net_dev.ip));
			}else{
				net_dev_tmp = &mi->net_dev;
				while(net_dev_tmp)
				{
					fprintf(fd, "%ld %02X:%02X:%02X:%02X:%02X:%02X %s * *\n", net_dev_tmp->seconds,\
						net_dev_tmp->mac[0],net_dev_tmp->mac[1],net_dev_tmp->mac[2],net_dev_tmp->mac[3],net_dev_tmp->mac[4],net_dev_tmp->mac[5], inet_ntoa(net_dev_tmp->ip));
					net_dev_tmp = net_dev_tmp->next;
				}
			}
			mi = mi->next;
		}
	}
//	fclose(fd);
	exit(0);
}
void get_exphost(void)
{
  FILE *fp;
  int i=0;
  char buf[256];
  char *str,*find;
  char enable[32],notes[64];

  memset(exphosts,0,sizeof(exphosts[0]) * IPMAC_EXPHOST_MAX);

  if(!(fp=fopen(IPMAC_EXPHOST_FILE,"r")))
	return;
  while(str=fgets(buf,sizeof(buf),fp)){
	if(strncmp(buf,"ENABLE",6))
	  continue;
	if((sscanf(buf,"%s %s %s",enable,exphosts[i],notes)) != 3)
		continue;
	i++;
	if(i == IPMAC_EXPHOST_MAX)
	    break;
  }
  fclose(fp);
/*  
  for(i=0;i<IPMAC_EXPHOST_MAX;i++){
	if((strlen(exphosts[i]) == 0))
	    break;
	printf("ipaddr=%s=\n",exphosts[i]);
  }	
*/
}

int check_exphost(char *ip)
{
  int i,res=0;
  for(i=0;i<IPMAC_EXPHOST_MAX;i++){
	if(strlen(exphosts[i]) == 0)
	  break;
	if(!(strcmp(exphosts[i],ip))){
		res=1;
		break;
	}
  }
  return res;
}
