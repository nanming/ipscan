#ifndef _MACSACN_H
#define _MACSACN_H

#define DEFDEV					"eth2.1"
#define	DEF_FILE				"/tmp/macscan.tmp"
#define	MACBAND_FILE			"/etc/kingcan/macband_list.cfg"
#define IPMAC_EXPHOST_FILE		"/etc/kingcan/macband_exphost.cfg"
#define IPMAC_EXPHOST_MAX		10
#define VERSION					"v2.00"
#define	SCAN_MAX_TIME			5
#define	TIMEOUT_SEC			0
#define	TIMEOUT_USEC		500000
#define	RECV_WAITTIME		2

#define ETH_LEN 			14
#define ARPH_LEN			28
#define MAX_SCAN_IP			2048
#define	MAX(a,b) 			(((a)>(b))?(a):(b))
#define NIPQUAD(addr) \
	&(((unsigned char *)&addr)[0]), \
	&(((unsigned char *)&addr)[1]), \
	&(((unsigned char *)&addr)[2]), \
	&(((unsigned char *)&addr)[3])

typedef struct eth_hdr
{
	uint8_t			d_mac[6];
	uint8_t			s_mac[6];
	uint16_t		proto_type;
}ETH_HEADER;

typedef struct arp_hdr
{
   uint16_t 	hw_type;		/* Format of hardware address.  */
   uint16_t 	proto_type;		/* Format of protocol address.  */
   uint8_t 		mac_len;			/* Length of hardware address.  */
   uint8_t 		ip_len;		/* Length of protocol address.  */
   uint16_t 	opcode;			/* ARP opcode (command).  */
   
   uint8_t 		s_mac[6];		/* Sender hardware address.  */
   uint8_t 		s_ip[4];			/* Sender IP address.  */
   uint8_t 		d_mac[6];		/* Target hardware address.  */
   uint8_t	 	d_ip[4];			/* Target IP address.  */
}ARP_HEADER;

struct ipmac
{
	struct ipmac		*next;
	struct in_addr	 	ip;
	unsigned char 		mac[6];
	unsigned short		bind;
	char				notes[64];
};

struct devinfo
{
	struct devinfo			*next;
	char 					ifname[16];
	struct in_addr			ipaddr;
	struct in_addr			netmask;
	struct in_addr			netaddr;
	struct in_addr			brdaddr;	
};
struct scanaddr
{
	struct scanaddr			*next;
	struct in_addr			start_ip;
	struct in_addr			end_ip;
};
static void parse_args( int argc, char** argv);
static void get_devinfo(char *ifname);
void read_macband_list(void);
void recv_arp_pkt();
void stop_recv_arp();
static int create_arpsock(char *ifname,struct sockaddr_ll *from);
static void get_scan_list(void);
void get_exphost(void);
int check_exphost(char *ip);

#endif
