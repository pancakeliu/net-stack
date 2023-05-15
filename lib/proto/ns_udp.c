#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_mbuf_core.h>
#include <rte_memcpy.h>

#include <proto/ns_udp.h>
#include <error/ns_error.h>
#include <base/ns_print.h>

#define IPV4_HEADER_LEN 20
#define UDP_HEADER_LEN  8

int udp_decode_packet(struct rte_mbuf *udp_mbuf, ns_udp_offload_t *udp_offload)
{
    struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(udp_mbuf, struct rte_ether_hdr *);

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

    // fill ether address
    rte_memcpy(udp_offload->src_ether_addr, ether_hdr->src_addr, RTE_ETHER_ADDR_LEN);
    rte_memcpy(udp_offload->dst_ether_addr, ether_hdr->dst_addr, RTE_ETHER_ADDR_LEN);

    // fill offload
    int rc = fill_five_tuple(
        &udp_offload->pkg_offload,
        ipv4_hdr->src_addr, ipv4_hdr->dst_addr,
        udp_hdr->src_port, udp_hdr->dst_port,
        IPPROTO_UDP
    );
    if (rc != NS_OK) {
        NS_PRINT("fill five tuple failed. err:%s", ns_strerror(rc));
        return NS_ERROR_UDP_PROCESS_FAILED;
    }
    rc = fill_data(
        &udp_offload->pkg_offload,
        data,
        htons(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr)
    );
    if (rc != NS_OK) {
        NS_PRINT("fill data failed. err:%s", ns_strerror(rc));
        return NS_ERROR_UDP_PROCESS_FAILED;
    }

    return NS_OK;
}

int udp_encode_packet(struct rte_mbuf *udp_mbuf, ns_udp_offload_t *udp_offload)
{
    // total packet length
    uint16_t packet_total_len = offload->data_len + RTE_ETHER_HDR_LEN
        + IPV4_HEADER_LEN + UDP_HEADER_LEN;

    // ether header
    struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(udp_mbuf, struct rte_ether_hdr *);
    rte_memcpy(ether_hdr->src_addr, offload->src_ether_addr, RTE_ETHER_ADDR_LEN);
    rte_memcoy(ether_hdr->dst_addr, offload->dst_ether_addr, RTE_ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // ipv4 header
    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(
        udp_mbuf,
        struct rte_ipv4_hdr *,
        sizeof(struct rte_ether_hdr)
    );
    // ipv4 version
    ipv4_hdr->version = 0x4;
    // 0101 => 160 bits = 20 bytes ==> minimal value (header without data) [RFC 6274 - page 9]
    ipv4_hdr->ihl = 0x5;

    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->total_length    = htons(packet_total_len - RTE_ETHER_HDR_LEN);
    ipv4_hdr->packet_id       = 0;
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live    = 64;
    ipv4_hdr->next_proto_id   = IPPROTO_UDP;

    ipv4_hdr->src_addr  = udp_offload->offload.src_ip_addr;
    ipv4_hdr->dest_addr = udp_offload->offload.dest_ip_addr;

    // calculate ipv4 header checksum
    ipv4_hdr->checksum = 0;
    ipv4_hdr->checksum = rte_ipv4_cksum(ipv4_hdr);

    // udp header
    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(
        udp_mbuf, struct rte_udp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
    );
    udp_hdr->src_port  = udp_offload->offload.src_port;
    udp_hdr->dest_port = udp_offload->offload.dst_port;
    udp_hdr->dgram_len = htons(packet_total_len - RTE_ETHER_HDR_LEN - IPV4_HEADER_LEN);

    char *udp_data = rte_pktmbuf_mtod_offset(
        udp_mbuf, char *,
        sizeof(struct rte_ether_hdr) +
        sizeof(struct rte_ipv4_hdr) +
        sizeof(struct rte_udp_hdr)
    );
    rte_memcpy(udp_data, udp_offload->offload.data, udp_offload->offload.data_len);

    // calculate udp header checksum
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);

    return NS_OK;
}