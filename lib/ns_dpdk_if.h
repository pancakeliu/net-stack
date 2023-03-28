#ifndef _NETSTACK_DPDK_IF_H_
#define _NETSTACK_DPDK_IF_H_

#include <ns_config.h>
#include <event/ns_processor.h>

int ns_dpdk_init(int argc, char **argv, ns_config *cfg, ns_dpdk_meta* dpdk_meta);
int ns_dpdk_start(ns_dpdk_meta* dpdk_meta, ns_processor *processor);

#endif // _NETSTACK_DPDK_IF_H_