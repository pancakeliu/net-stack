#ifndef _NS_STACK_SAFETY_NS_DDOS_H_
#define _NS_STACK_SAFETY_NS_DDOS_H_

#include <rte_ethdev.h>

int ddos_detect(struct rte_mbuf *pkt);

#endif // _NS_STACK_SAFETY_DDOS_H_