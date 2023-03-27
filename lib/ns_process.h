#ifndef _NETSTACK_WORKER_H_
#define _NETSTACK_WORKER_H_

#include <rte_ethdev.h>

#include <proto/ns_arp.h>

typedef struct ns_processor {
    struct ns_arp_table *arp_table;
} ns_processor;

ns_processor *create_processor();

void process_packets(struct ns_processor *processor, struct rte_mbuf **rx_pkts, uint16_t pkts_nb);

#endif // _NETSTACK_WORKER_H_