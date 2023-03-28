#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include <proto/ns_udp.h>

int udp_process(struct rte_mbuf *udp_mbuf)
{
    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(
        udp_mbuf, struct rte_ipv4_hdr *,
        sizeof(struct rte_ether_hdr)
    );
    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(
        udp_mbuf, struct rte_udp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
    );
}