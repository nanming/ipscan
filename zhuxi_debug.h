#ifndef _ZHUXI_DEBUG_H
#define _ZHUXI_DEBUG_H

#define ZHUXI_DBG	1
#define ZHUXI_MSG	1

#if	ZHUXI_DBG
#define ZHUXI_DBGP(_x_) do{	\
    printf("===%s->%s(%d)=== \n",__FILE__,__func__,__LINE__);	\
    printf _x_;	\
}while(0)
#else
#define ZHUXI_DBGP(_x_)
#endif

#if	ZHUXI_MSG
#define ZHUXI_MSGP(_x_) do{	\
    printf _x_;	\
}while(0)
#else
#define ZHUXI_MSGP(_x_)
#endif

#if	ZHUXI_DBG
#define ZHUXI_DBGMP(x,s,n) do{	\
    int i;	\
    printf("===%s->%s(%d)=== \n",__FILE__,__func__,__LINE__);	\
    printf(x);	\
    for(i=0;i<n;i++)	\
        printf("%02X ",s[i]);	\
    printf("\n");	\
}while(0)
#else
#define ZHUXI_DBGMP(x,s,n)
#endif

#endif
