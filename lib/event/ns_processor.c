#include <string.h>
#include <stdio.h>

#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <event/ns_processor.h>
#include <proto/ns_arp.h>
#include <proto/ns_tcp.h>
#include <base/ns_print.h>
#include <base/ns_list.h>
#include <base/ns_common.h>
#include <error/ns_error.h>

ns_processor *ns_create_processor(struct rte_mempool *mem_pool)
{
    ns_processor *processor = rte_malloc(
        "net-stack processor",
        sizeof(struct ns_processor),
        0
    )
    if (processor == NULL) {
        NS_PRINT("rte_malloc exec failed.\n");
        return NULL;
    }
    bzero(processor, sizeof(struct ns_processor));

    ns_arp_table *arp_table = create_arp_table();
    if (arp_table == NULL) {
        NS_PRINT("create arp table failed.\n");
        return NULL;
    }
    processor->arp_table = arp_table;
    processor->mem_pool  = mem_pool;

    return processor;
}

int ns_register_udp_server(ns_processor_t *processor, ns_udp_server_t *server)
{
    if (processor == NULL || server == NULL) {
        return NS_ERROR_CODE;
    }
    ns_udp_server_entry_t *server_entry = rte_malloc(
        "net-stack udp server entry",
        sizeof(struct ns_udp_server_entry),
        0
    );
    if (server_entry == NULL) {
        return NS_ERROR_RTE_MALLOC_FAILED;
    }

    bzero(server_entry, sizeof(struct ns_udp_server_entry));
    server_entry->server = server;

    NS_LIST_ADD(server_entry, processor->udp_server_entries);

    return NS_OK;
}

int ns_register_tcp_server(ns_processor_t *processor, ns_tcp_server_t *server)
{
    if (processor == NULL || server == NULL) {
        return NS_ERROR_CODE;
    }
    ns_tcp_server_entry_t *server_entry = rte_malloc(
        "net-stack tcp server entry",
        sizeof(struct ns_tcp_server_entry),
        0
    );
    if (server_entry == NULL) {
        return NS_ERROR_RTE_MALLOC_FAILED;
    }

    bzero(server_entry, sizeof(struct ns_tcp_server_entry));
    server_entry->server = server;

    NS_LIST_ADD(server_entry, processor->tcp_server_entries);

    return NS_OK;
}

// UDP Processor

static int exec_udp_read_cb(ns_processor_t *processor, ns_offload_t *offload)
{
    ns_udp_server_entry_t *server_iter = processor->udp_server_entries;
    for (; server_iter; server_iter = server_iter->next) {
        int match = udp_server_match(
            server_iter->server,
            offload->dst_ip_addr, offload->dst_port
        );
        if (match != NS_SERVER_MATCH) {
            continue;
        }

        if (server_iter->server->udp_on_read_cb) {
            return server_iter->server->udp_on_read_cb(
                server_iter->server->send_buffer, offload
            );
        }
    }

    // not match server
    return NS_KNI;
}

int process_udp_read_event(ns_processor_t *processor, struct rte_mbuf *rx_pkt)
{
    ns_offload_t *offload = create_offload();
    if (offload == NULL) {
        NS_PRINT("new offload failed..\n");
        return NS_ERROR_RTE_MALLOC_FAILED;
    }
    int rc = udp_decode_packet(rx_pkt, offload);
    if (rc != NS_OK) {
        NS_PRINT("decode udp packet failed. err:%s...\n", ns_strerror(rc));
        free_offload(offload);
        return rc;
    }
    rc = exec_udp_read_cb(processor, offload);
    free_offload(offload);
    
    return rc;
}

int exec_udp_write_cb(ns_processor_t *processsor, ns_offload_t *offload)
{
    ns_server_entry_t *server_iter = processor->server_entries;
    for (; server_iter != NULL; server_iter = server_iter->next) {
        int match = server_match(
            server_iter->server,
            offload->dst_ip_addr, offload->dst_port, offload->protocol
        );
        if (match != NS_SERVER_MATCH) {
            continue;
        }

        if (server_iter->server->udp_on_write_cb != NULL) {
            return server_iter->server->udp_on_write_cb();
        }
    }

    // not match server
    return NS_KNI;
}

int process_udp_write_event(ns_offload_t *udp_packet, struct rte_mbuf *tx_pkt)
{

}

// TCP Processor

static ns_tcp_server_t *search_tcp_server(
    ns_processor_t *processor,
    struct rte_ipv4_hdr *ipv4_hdr, struct rte_tcp_hdr *tcp_hdr
)
{
    ns_tcp_server_entry_t *server_iter = processor->tcp_server_entries;
    for (; server_iter; server_iter = server_iter) {
        int match = tcp_server_match(
            server_iter->server,
            ipv4_hdr->dst_addr, tcp_hdr->dst_port
        );
        if (match == NS_SERVER_MATCH) {
            return server_iter->server;
        }
    }

    return NULL;
}

static int exec_tcp_read_cb(
    ns_tcp_server_t *server, ns_tcp_entry_t *tcp_entry, ns_offload_t *offload
)
{
    // Execute the on_read callback function
    if (server->tcp_on_read_cb) {
        return server->tcp_on_read_cb(tcp_entry, offload);
    }

    return NS_OK;
}

int process_tcp_read_event(ns_processor_t *processor, struct rte_mbuf *rx_pkt)
{
    struct rte_ether_hdr *ether_hdr = NULL;
    struct rte_ipv4_hdr  *ipv4_hdr  = NULL;
    struct rte_tcp_hdr   *tcp_hdr   = NULL;
    int rc = tcp_parse_header(rx_pkt, &ether_hdr, &ipv4_hdr, &tcp_hdr);
    if (rc != NS_OK) {
        NS_PRINT("tcp parse header exec failed. err:%s...\n", ns_strerror(rc));
        return rc;
    }

    // find server
    ns_tcp_server_t *server = search_tcp_server(processor, ipv4_hdr, tcp_hdr);
    if (server == NULL) return NS_KNI;

    // find tcp entry
    ns_tcp_entry_t *tcp_entry = search_tcp_entry(
        server->tcp_table,
        ipv4_hdr->src_addr, ipv4_hdr->dst_addr,
        tcp_hdr->src_port, tcp_hdr->dst_port
    );
    if (tcp_entry == NULL) return NS_KNI;

    // tcp state machine
    ns_offload_t *offload = NULL;
    rc = tcp_state_machine_exec(
        NS_TRUE,
        server->tcp_table,
        tcp_entry,
        ether_hdr, ipv4_hdr, tcp_hdr,
        &offload
    );
    if (rc != NS_OK) return rc;

    // PSH packet received
    if (*offload != NULL) {
        rc = exec_tcp_read_cb(server, tcp_entry, offload);
        free_offload(offload);
        if (rc != NS_OK) return rc;
    }

    // Extract packets from the tcp entry's send queue to the server send queue
    if (tcp_entry->packet_counts == 0) return NS_OK;

    ns_tcp_packet_t **tcp_packets = rte_malloc(
        ns_tcp_packet_t **, tcp_entry->packet_counts, 0
    );
    if (tcp_packets == NULL) return NS_ERROR_RTE_MALLOC_FAILED;

    uint32_t packet_cnt = dequeue_all_tcp_packets(tcp_entry, tcp_packets);
    if (packet_cnt == 0) return NS_OK;

    // enqueue into the server send queue
    uint32_t en_packet_cnt = rte_ring_enqueue_burst(
        server->snd_queue,
        tcp_packets,
        packet_cnt,
        NULL
    );

    // Determine if all packets have been stuffed into the server send queue
    packet_cnt -= en_packet_cnt;
    if (packet_cnt == 0) {
        rte_free(tcp_packets);
        return NS_OK;
    }

    // server queue full, some packets 
    en_packet_cnt = enqueue_all_tcp_packets(tcp_entry, tcp_packets+en_packet_cnt, packet_cnt);
    rte_free(tcp_packets);
    if (en_packet_cnt != packet_cnt) {
        NS_PRINT("refill tcp packets into tcp entry send queue failed.");
        return NS_ERROR_CODE;
    }

    return NS_OK;
}

int exec_tcp_write_cb(ns_processor_t *processor, ns_offload_t *offload)
{
    ns_server_entry_t *server_iter = processor->server_entries;
    for (; server_iter != NULL; server_iter = server_iter->next) {
        int match = server_match(
            server_iter->server,
            offload->dst_ip_addr, offload->dst_port, offload->protocol
        );
        if (match != NS_SERVER_MATCH) {
            continue;
        }

        if (server_iter->server->tcp_on_write_cb != NULL) {
            return server_iter->server->tcp_on_write_cb();
        }
    }

    // not match server
    return NS_KNI;
}

int process_tcp_write_event(ns_tcp_packet_t *tcp_packet, struct rte_mbuf *tx_pkt)
{

}