#ifndef _NETSTACK_CONFIG_H_
#define _NETSTACK_CONFIG_H_

#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ring.h>
#include <rte_ethdev.h>

typedef struct ns_config {
    char     *ip_address;
    uint16_t port;
    int      dpdk_port_id;
    unsigned dpdk_mempool_size;
    int      dpdk_rx_queues_nb;
    int      dpdk_tx_queues_nb;
    uint16_t dpdk_burst_size;
} ns_config;

typedef struct ns_dpdk_meta {
    char                *ip_address;
    uint16_t            port;
    uint8_t             mac_address[RTE_ETHER_ADDR_LEN];
    int                 port_id;
    struct rte_mempool  *mempool;
    struct rte_eth_conf port_cfg;
    int                 rx_queues_nb;
    int                 tx_queues_nb;
    struct rte_ring*    in_ring;
    struct rte_ring*    out_ring;
    uint16_t            burst_size;
} ns_dpdk_meta;

void ns_config_default(ns_config *cfg);

#endif // _NETSTACK_CONFIG_H_