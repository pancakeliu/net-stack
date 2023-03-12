#include <rte_byteorder.h>
#include <rte_ether.h>

#include "ns_process.h"
#include "ns_error.h"
#include "safety/ddos.h"

static int packet_process(struct rte_mbuf *rx_pkt)
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

    
}

int packets_process(struct rte_mbuf **rx_pkts, uint16_t pkts_nb)
{
    if (pkts_nb == 0) {
        return NS_ERROR_PROCESS_PACKETS_EMPTY;
    }
    
    for (int i = 0; i < pkts_nb; i++) {
        packet_process()
    }
}