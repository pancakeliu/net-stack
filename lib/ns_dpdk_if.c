
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <strings.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <ns_dpdk_if.h>
#include <ns_config.h>
#include <ns_process.h>
#include <error/ns_error.h>

#define NS_MBUF_CACHE_SIZE 0
#define NS_MBUF_PRIV_SIZE  0
// 	The number of receive descriptors to allocate for the receive ring.
#define NS_RX_DESC_NUMBER  1024
// 
#define NS_TX_DESC_NUMBER  1024
#define NS_RX_QUEUE_ID     0
#define NS_TX_QUEUE_ID     0

#define NS_IN_RING_BUFFER_SIZE  1024
#define NS_OUT_RING_BUFFER_SIZE 1024

// ns boolean types
#define NS_TRUE  1
#define NS_FALSE 0

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static int start_port(ns_dpdk_meta *dpdk_meta)
{
    uint16_t ports_nb = rte_eth_dev_count_avail();
    if (ports_nb == 0) {
        printf("dpdk: no available ports\n");
        return NS_ERROR_NO_AVALIABLE_ETH_DEV;
    }

    struct rte_eth_dev_info port_info;
    int ret = rte_eth_dev_info_get(
        dpdk_meta->port_id, &port_info
    );
    if (ret != 0) {
        printf(
            "dpdk: get port info failed. err:%d, port_id:%d\n",
            ret, dpdk_meta->port_id
        );
        return NS_ERROR_PORT_INFO_GET_FAILED;
    }

    dpdk_meta->port_cfg = port_conf_default;
    ret = rte_eth_dev_configure(
        dpdk_meta->port_id,
        dpdk_meta->rx_queues_nb,
        dpdk_meta->tx_queues_nb,
        &dpdk_meta->port_cfg
    );
    if (ret != 0) {
        printf("dpdk: port configure faield. err:%d\n", ret);
        return NS_ERROR_PORT_CONFIGURE_FAILED;
    }

    // setup rx and tx queue
    ret = rte_eth_rx_queue_setup(
        dpdk_meta->port_id,
        NS_RX_QUEUE_ID,
        NS_RX_DESC_NUMBER,
        rte_eth_dev_socket_id(dpdk_meta->port_id),
        NULL,
        dpdk_meta->mempool
    );
    if (ret != 0) {
        printf("dpdk: rx queue setup failed. err:%d\n", ret);
        return NS_ERROR_PORT_RX_QUEUE_SETUP_FAILED;
    }

    struct rte_eth_txconf txq_conf = port_info.default_txconf;
    txq_conf.offloads = dpdk_meta->port_cfg.rxmode.offloads;
    ret = rte_eth_tx_queue_setup(
        dpdk_meta->port_id,
        NS_TX_QUEUE_ID,
        NS_TX_DESC_NUMBER,
        rte_eth_dev_socket_id(dpdk_meta->port_id),
        &txq_conf
    );
    if (ret != 0) {
        printf("dpdk: tx queue setup failed. err:%d\n", ret);
        return NS_ERROR_PORT_TX_QUEUE_SETUP_FAILED;
    }

    ret = rte_eth_dev_start(dpdk_meta->port_id);
    if (ret != 0) {
        printf(
            "dpdk: port start failed. err:%d, port_id:%d\n",
            ret, dpdk_meta->port_id
        );
        return NS_ERROR_PORT_START_FAILED;
    }

    return NS_OK;
}

int ns_dpdk_init(int argc, char **argv, ns_config *cfg, ns_dpdk_meta* dpdk_meta)
{
    bzero(dpdk_meta, sizeof(ns_dpdk_meta));

    int ret = rte_eal_init(argc, argv);
    if (ret != 0) {
        printf("dpdk: eal init failed. err:%s\n", rte_strerror(rte_errno));
        return NS_ERROR_EAL_INIT_FAILED;
    }

    dpdk_meta->mempool = rte_pktmbuf_pool_create(
        "mbuffer_pool",
        cfg->dpdk_mempool_size,
        NS_MBUF_CACHE_SIZE,
        NS_MBUF_PRIV_SIZE,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_eth_dev_socket_id(cfg->dpdk_port_id)
    );
    if (dpdk_meta->mempool == NULL) {
        printf("dpdk: membuf pool create failed. err:%s\n", rte_strerror(rte_errno));
        return NS_ERROR_MEMPOOL_CREATE_FAILED;
    }

    // fill dpdk meta
    dpdk_meta->port_id      = cfg->dpdk_port_id;
    dpdk_meta->rx_queues_nb = cfg->dpdk_rx_queues_nb;
    dpdk_meta->tx_queues_nb = cfg->dpdk_tx_queues_nb;
    dpdk_meta->burst_size   = cfg->dpdk_burst_size;

    // start dpdk port
    ret = start_port(dpdk_meta);
    if (ret != NS_OK) {
        printf("dpdk: start port failed. err:%s\n", ns_strerror(ret));
        return ret;
    }

    // fill mac address
    ret = rte_eth_macaddr_get(
        dpdk_meta->port_id,
        (struct rte_ether_addr *)dpdk_meta->mac_address
    );
    if (ret != 0) {
        printf(
            "dpdk: get port mac address failed. err:%d, port_id:%d",
            ret, dpdk_meta->port_id
        );
        return NS_ERROR_GET_PORT_MAC_ADDRESS_FAILED;
    }

    // dpdk i/o ring buffer
    dpdk_meta->in_ring = rte_ring_create(
        "in_ring", NS_IN_RING_BUFFER_SIZE,
        rte_eth_dev_socket_id(dpdk_meta->port_id),
        RING_F_SP_ENQ | RING_F_SC_DEQ
    );
    dpdk_meta->out_ring = rte_ring_create(
        "out_ring", NS_OUT_RING_BUFFER_SIZE,
        rte_eth_dev_socket_id(dpdk_meta->port_id),
        RING_F_SP_ENQ | RING_F_SC_DEQ
    );

    return NS_OK;
}

int ns_dpdk_start(ns_dpdk_meta* dpdk_meta)
{
    // create net-stack processor
    ns_processor *processor = create_processor();
    if (processor == NULL) {
        printf("ns_dpdk_start: create processor failed..\n");
        return NS_ERROR_CREATE_PROCESSOR_FAILED;
    }

    struct rte_mbuf *rx_pkts[dpdk_meta->burst_size];
    while (NS_TRUE) {
        uint16_t recvd_nb = rte_eth_rx_burst(
            dpdk_meta->port_id,
            0,
            (struct rte_mbuf **)rx_pkts,
            dpdk_meta->burst_size
        );
        if (recvd_nb > 0) {
            process_packets(processor, rx_pkts, recvd_nb);
        }
    }

    return NS_OK;
}
