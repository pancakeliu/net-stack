#ifndef _NETSATCK_PROTO_UDP_H_
#define _NETSATCK_PROTO_UDP_H_

#include <rte_mbuf.h>

#include <proto/ns_offload.h>

int udp_parse_header(struct rte_mbuf *udp_mbuf, ns_offload_t *offload);

#endif // _NETSATCK_PROTO_UDP_H_