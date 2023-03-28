#ifndef _NETSATCK_PROTO_NS_ARP_H_
#define _NETSATCK_PROTO_NS_ARP_H_

#include <stdint.h>

#include <rte_ether.h>

typedef struct ns_arp_entry {
    uint32_t ip;
    uint8_t  mac[RTE_ETHER_ADDR_LEN];
    uint8_t  type;

    struct ns_arp_entry *next;
    struct ns_arp_entry *prev;
} ns_arp_entry_t;

// Each worker thread has a separate arp table
typedef struct ns_arp_table {
    struct ns_arp_entry *entries;
    int                  count;
} ns_arp_table_t;

ns_arp_table_t *create_arp_table();

uint8_t *find_dst_macaddr(ns_arp_table_t *arp_table, uint32_t ip);

// arp table
int arp_entry_insert(ns_arp_table_t *arp_table, uint32_t ip, uint8_t *mac);

#endif // _NETSATCK_PROTO_ARP_H_