#include <stdint.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <proto/ns_tcp.h>
#include <base/ns_print.h>
#include <error/ns_error.h>

int tcp_process(struct rte_mbuf *tcp_mbuf)
{
    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(
        tcp_mbuf,
        struct rte_ipv4_hdr *,
        sizeof(struct rte_ether_hdr)
    );
    struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(
        tcp_mbufk,
        struct rte_tcp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
    );

    uint16_t cksum = tcp_hdr->cksum;
    tcp_hdr->cksum = 0;
    if (rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr) != cksum) {
        return NS_ERROR_CHECKSUM_MISMATCH;
    }

    
}