#ifndef _NETSTACK_WORKER_H_
#define _NETSTACK_WORKER_H_

#include <rte_ethdev.h>

int packets_process(struct rte_mbuf **rx_pkts);

#endif // _NETSTACK_WORKER_H_