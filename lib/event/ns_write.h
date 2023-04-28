#ifndef _NETSTACK_EVENT_WRITE_H_
#define _NETSTACK_EVENT_WRITE_H_

#include <stdint.h>

#include <rte_mbuf_core.h>

#include <event/ns_processor.h>

// Returns
//   Count of send rte_mbuf objects
uint32_t handle_write_events(
    ns_processor_t *processor, struct rte_mbuf **tx_pkts, uint32_t max_pkt_cnt
);

#endif // _NETSTACK_EVENT_WRITE_H_