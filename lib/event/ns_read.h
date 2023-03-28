#ifndef _NETSTACK_EVENT_READ_H_
#define _NETSTACK_EVENT_READ_H_

#include <rte_mbuf.h>

#include <event/ns_processor.h>

void handle_read_events(
    struct ns_processor *processor,
    struct rte_mbuf **rx_pkts,
    uint16_t pkts_nb
);

#endif // _NETSTACK_EVENT_READ_H_