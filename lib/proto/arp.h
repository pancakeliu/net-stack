#ifndef _NETSATCK_PROTO_ARP_H_
#define _NETSATCK_PROTO_ARP_H_

#include <stdint.h>

#include <rte_ether.h>

struct arp_entry {
    uint32_t ip;
    uint8_t  mac[RTE_ETHER_ADDR_LEN];
    uint8_t  type;

    struct arp_entry *next;
    struct arp_entry *prev;
}

struct arp_table {
    struct arp_entry *entries;
    int               count;
};

static arp_table *arp_table_ptr = NULL;

struct arp_table *arp_table_instance()

// arp table
int arp_entry_insert(uint32_t ip, uint8_t *mac);

#endif // _NETSATCK_PROTO_ARP_H_