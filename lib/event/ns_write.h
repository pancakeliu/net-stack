#ifndef _NETSTACK_EVENT_WRITE_H_
#define _NETSTACK_EVENT_WRITE_H_

#include <rte_mbuf_core.h>

#include <event/ns_processor.h>

int handle_write_events(ns_processor_t *processor, struct rte_mbuf *tx_pkts);

#endif // _NETSTACK_EVENT_WRITE_H_