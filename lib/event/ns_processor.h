#ifndef _NETSTACK_EVENT_PROCESSOR_H_
#define _NETSTACK_EVENT_PROCESSOR_H_

#include <rte_ethdev.h>

#include <proto/ns_arp.h>
#include <proto/ns_offload.h>
#include <server/ns_server.h>

typedef struct ns_udp_server_entry {
    ns_udp_server_t *server;

    struct ns_udp_server_entry *next;
    struct ns_udp_server_entry *prev;
} ns_udp_server_entry_t;

typedef struct ns_tcp_server_entry {
    ns_tcp_server_t *server;

    struct ns_tcp_server_entry *next;
    struct ns_tcp_server_entry *prev;
} ns_tcp_server_entry_t;

typedef struct ns_other_server_entry {
    ns_other_server_t *server;

    struct ns_other_server_entry *next;
    struct ns_other_server_entry *prev;
} ns_other_server_entry_t;

typedef struct ns_processor {
    ns_arp_table            *arp_table;

    ns_udp_server_entry_t   *udp_server_entries;
    uint32_t                 udp_server_count;

    ns_tcp_server_entry_t   *tcp_server_entries;
    uint32_t                 tcp_server_count;

    ns_other_server_entry_t *other_server_entries;
    uint32_t                 other_server_count;
} ns_processor_t;

ns_processor_t *ns_new_processor();

int ns_register_udp_server(ns_processor_t *processor, ns_udp_server_t *server);
int ns_register_tcp_server(ns_processor_t *processor, ns_tcp_server_t *server);
int ns_register_other_server(ns_processor_t *processor, ns_other_server_t *server);

int process_udp_read_event(ns_processor_t *processor, struct rte_mbuf *rx_pkt);
int process_tcp_read_event(ns_processor_t *processor, struct rte_mbuf *rx_pkt);
int process_other_read_event(ns_processor_t *processor, struct rte_mbuf *rx_pkt);

// Notice: service cancellation function is not supported

#endif // _NETSTACK_EVENT_PROCESSOR_H_