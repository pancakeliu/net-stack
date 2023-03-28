#include <strings.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_ether.h>

#include <proto/ns_arp.h>
#include <base/ns_list.h>
#include <error/ns_error.h>

ns_arp_table_t *create_arp_table()
{
    ns_arp_table_t *arp_table = rte_malloc(
        "net-stack arp table",
        sizeof(struct ns_arp_table),
        0
    );
    if (arp_table == NULL) return NULL;
    bzero(arp_table, sizeof(struct ns_arp_table));

    return arp_table;
}

uint8_t *find_dst_macaddr(ns_arp_table *arp_table, uint32_t dst_ip)
{
    struct ns_arp_entry *iter;
    int count = arp_table->count;

    for (iter = arp_table->entries; count-- != 0 && iter != NULL; iter = iter->next) {
        if (iter->ip == dst_ip) {
            return iter->mac;
        }
    }

    return NULL;
}

int arp_entry_insert(ns_arp_table_t *arp_table, uint32_t ip, uint8_t *mac)
{
    if (find_dst_macaddr(arp_table, ip) != NULL) {
        return NS_ERROR_ARP_RECORD_ALREADY_EXISTS;
    }

    struct arp_entry *entry = rte_malloc(
        "net-stack arp entry",
        sizeof(struct ns_arp_entry),
        0
    )
    if (entry == NULL) {
        return NS_ERROR_RTE_MALLOC_FAILED;
    }
    bzero(entry, sizeof(struct ns_arp_entry));

    entry->ip = ip;
    rte_memcpy(entry->mac, mac, RTE_ETHER_ADDR_LEN);
    entry->type = 0;

    NS_LIST_ADD(entry, arp_table->entries);
    arp_table->count++;

    return NS_OK;
}