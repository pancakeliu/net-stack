#include <ns_config.h>

void ns_config_default(ns_config *cfg)
{
    cfg->port              = 9527;
    cfg->dpdk_port_id      = 0;
    cfg->dpdk_mempool_size = 4096 - 1;
    cfg->dpdk_rx_queues_nb = 1;
    cfg->dpdk_tx_queues_nb = 1;
    cfg->dpdk_burst_size   = 1024;
}