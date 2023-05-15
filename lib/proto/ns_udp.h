#ifndef _NETSATCK_PROTO_UDP_H_
#define _NETSATCK_PROTO_UDP_H_

#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_udp.h>
#include <rte_ip.h>

#include <proto/ns_offload.h>

typedef struct ns_udp_offload {
    char src_ether_addr[RTE_ETHER_ADDR_LEN];
    char dst_ether_addr[RTE_ETHER_ADDR_LEN];

    ns_offload_t offload;
} ns_udp_offload_t;

int udp_decode_packet(struct rte_mbuf *udp_mbuf, ns_udp_offload_t *offload);

int udp_encode_packet(struct rte_mbuf *udp_mbuf, ns_udp_offload_t *offload);

#endif // _NETSATCK_PROTO_UDP_H_