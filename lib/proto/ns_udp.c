#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include <proto/ns_udp.h>
#include <error/ns_error.h>
#include <base/ns_print.h>

int udp_decode_packet(struct rte_mbuf *udp_mbuf, ns_offload_t *offload)
{
    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(
        udp_mbuf, struct rte_ipv4_hdr *,
        sizeof(struct rte_ether_hdr)
    );
    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(
        udp_mbuf, struct rte_udp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
    );
    char *data = rte_pktmbuf_mtod_offset(
        udp_mbuf, char *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr)
    )

    // fill offload
    int rc = fill_five_tuple(
        offload,
        ipv4_hdr->src_addr, ipv4_hdr->dst_addr,
        udp_hdr->src_port, udp_hdr->dst_port,
        IPPROTO_UDP
    )
    if (rc != NS_OK) {
        NS_PRINT("fill five tuple failed. err:%s", ns_strerror(rc));
        return NS_ERROR_UDP_PROCESS_FAILED;
    }
    rc = fill_data(
        offload,
        data,
        htons(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr)
    );
    if (rc != NS_OK) {
        NS_PRINT("fill data failed. err:%s", ns_strerror(rc));
        return NS_ERROR_UDP_PROCESS_FAILED;
    }

    return NS_OK;
}

int udp_encode_packet(struct rte_mbuf *udp_mbuf, ns_offload_t *offload)
{

}