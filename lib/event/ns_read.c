#include <stdio.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <event/ns_read.h>
#include <proto/ns_arp.h>
#include <proto/ns_udp.h>
#include <proto/ns_tcp.h>
#include <proto/ns_offload.h>
#include <error/ns_error.h>
#include <base/ns_print.h>

static int handle_read_event(ns_processor *processor, struct rte_mbuf *rx_pkt)
{
    // parse ethernet header
    struct rte_ehther_hdr *eth_hdr = rte_pktmbuf_mtod(
        rx_pkt, struct rte_ether_hdr *
    );
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        return NS_KNI;
    }

    // parse ipv4 header
    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(
        rx_pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr)
    );

    // record ip <-> mac address into arp table
    int rc = arp_entry_insert(
        processor->arp_table,
        ipv4_hdr->src_addr, ipv4_hdr->s_addr.addr_bytes
    );
    if (rc != NS_OK && rc != NS_ERROR_ARP_RECORD_ALREADY_EXISTS) {
        NS_PRINT("arp entry insert failed. err:%s..\n", ns_strerror(rc));
        return rc;
    }

    // transport layer protocol processing
    // tcp or udp
    // other transport layer protocols use kni

    if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        return process_tcp_read_event(processor, rx_pkt);
    }

    else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        return process_udp_read_event(processor, rx_pkt);
    }

    return NS_KNI;
}

void handle_read_events(
    struct ns_processor *processor,
    struct rte_mbuf **rx_pkts,
    uint16_t pkts_nb
)
{
    if (pkts_nb == 0) return;
    
    for (int i = 0; i < pkts_nb; i++) {
        int rc = handle_read_event(processor, rx_pkts[i]);
        if (rc == NS_KNI) {
            // TODO: kni handle
        }
        if (rc < NS_OK) {
            printf(
                "process_packets: process packet failed. err:%s..\n",
                ns_strerror(rc)
            );
        }
    }
}