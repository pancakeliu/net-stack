#ifndef _NETSTACK_EVENT_PROCESSOR_H_
#define _NETSTACK_EVENT_PROCESSOR_H_

#include <rte_ethdev.h>

#include <proto/ns_arp.h>
#include <proto/ns_offload.h>
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

ns_processor_t *ns_new_processor();

int ns_register_server(ns_processor_t *processor, ns_server_t *server);

int exec_udp_read_cb(ns_processor_t *processor, ns_offload_t *offload);
int exec_udp_write_cb(ns_processor_t *processsor, ns_offload_t *offload);

int exec_tcp_read_cb(ns_processor_t *processor, ns_offload_t *offload);
int exec_tcp_write_cb(ns_processor_t *processor, ns_offload_t *offload);

// Notice: service cancellation function is not supported

#endif // _NETSTACK_EVENT_PROCESSOR_H_