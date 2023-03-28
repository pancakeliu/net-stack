#ifndef _NETSATCK_PROTO_UDP_H_
#define _NETSATCK_PROTO_UDP_H_

#include <rte_mbuf.h>

int udp_process(struct rte_mbuf *udpmbuf);

#endif // _NETSATCK_PROTO_UDP_H_