#ifndef _NETSATCK_PROTO_NS_TCP_H_
#define _NETSATCK_PROTO_NS_TCP_H_

#include <rte_mbuf.h>

int tcp_process(struct rte_mbuf *tcp_mbuf);

#endif // _NETSATCK_PROTO_NS_TCP_H_