#include <strings.h>
#include <stdio.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include <ns_process.h>
#include <error/ns_error.h>
#include <safety/ns_ddos.h>
#include <proto/ns_arp.h>

ns_processor *create_processor()
{
    ns_processor *processor = rte_malloc(
        "net-stack processor",
        sizeof(struct ns_processor),
        0
    )
    if (processor == NULL) {
        printf("create_processor: rte_malloc exec failed.\n");
        return NULL;
    }
    bzero(processor, sizeof(struct ns_processor));

    ns_arp_table *arp_table = create_arp_table();
    if (arp_table == NULL) {
        printf("create_processor: create arp table failed.\n");
        return NULL;
    }
    processor->arp_table = arp_table;

    return processor;
}

static int process_packet(ns_processor *processor, struct rte_mbuf *rx_pkt)
{
    // parse ethernet header
    struct rte_ehther_hdr *eth_hdr = rte_pktmbuf_mtod(
        rx_pkt, struct rte_ether_hdr *
    );
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        // TODO: return kni
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
        printf("packet_process: arp entry insert failed. err=%s..\n", ns_strerror(rc));
        return rc;
    }

    // transport layer protocol processing
    // tcp or udp
    // other transport layer protocols use kni

    if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        return ns_tcp_process(rx_pkt);
    }

    if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        return ns_udp_process(rx_pkt);
    }

    // TODO: return kni
}

void process_packets(ns_processor *processor, struct rte_mbuf **rx_pkts, uint16_t pkts_nb)
{
    if (pkts_nb == 0) return;
    
    for (int i = 0; i < pkts_nb; i++) {
        int rc = process_packet(processor, rx_pkts[i]);
        if (rc != NS_OK) {
            printf("process_packets: process packet failed. err:%s..\n", ns_strerror(rc));
        }
    }
}