#ifndef _NETSTACK_DPDK_IF_H_
#define _NETSTACK_DPDK_IF_H_

#include "ns_config.h"

int ns_dpdk_init(int argc, char **argv, ns_config *cfg, ns_dpdk_meta* dpdk_meta);
int ns_dpdk_start(ns_dpdk_meta* dpdk_meta);

#endif // _NETSTACK_DPDK_IF_H_