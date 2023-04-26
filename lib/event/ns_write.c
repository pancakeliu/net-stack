#include <event/ns_write.h>
#include <proto/ns_tcp.h>
#include <proto/ns_udp.h>

int handle_write_events(ns_processor_t *processor, struct rte_mbuf *tx_pkts)
{
    // tcp write events
    ns_tcp_server_entry_t *tcp_server_iter = processor->tcp_server_entries;
    for (; tcp_server_iter; tcp_server_iter = tcp_server_iter->next) {
        
    }

    // udp write events
    ns_udp_server_entry_t *udp_server_iter = processor->udp_server_entries;
    for (; udp_server_iter; udp_server_iter = udp_server_iter->next) {

    }
}