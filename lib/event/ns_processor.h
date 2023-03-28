#ifndef _NETSTACK_EVENT_PROCESSOR_H_
#define _NETSTACK_EVENT_PROCESSOR_H_

#include <rte_ethdev.h>

#include <proto/ns_arp.h>
#include <server/ns_server.h>

typedef struct ns_server_entry {
    ns_server_t *server;

    struct ns_server_entry *next;
    struct ns_server_entry *prev;
} ns_server_entry_t;

typedef struct ns_processor {
    struct ns_arp_table    *arp_table;
    struct ns_server_entry *server_entries;
    uint32_t                server_count;
} ns_processor_t;

ns_processor_t *new_processor();

int register_server(ns_processor_t *processor, ns_server_t *server);

// Notice: service cancellation function is not supported

#endif // _NETSTACK_EVENT_PROCESSOR_H_