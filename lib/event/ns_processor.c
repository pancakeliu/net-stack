#include <string.h>
#include <stdio.h>

#include <rte_malloc.h>

#include <event/ns_processor.h>
#include <proto/ns_arp.h>
#include <base/ns_print.h>
#include <base/ns_list.h>
#include <error/ns_error.h>

ns_processor *ns_new_processor()
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

    return processor;
}

int ns_register_server(ns_processor_t *processor, ns_server_t *server)
{
    if (processor == NULL || server == NULL) {
        return NS_ERROR_CODE;
    }
    ns_server_entry_t *server_entry = rte_malloc(
        "net-stack server entry",
        sizeof(struct ns_server_entry),
        0
    );
    if (server_entry == NULL) {
        return NS_ERROR_RTE_MALLOC_FAILED;
    }

    bzero(server_entry, sizeof(struct ns_server_entry));
    server_entry->server = server;

    NS_LIST_ADD(server_entry, processor->server_entries);

    return NS_OK;
}

int exec_udp_read_cb(ns_processor_t *processor, ns_offload_t *offload)
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

        if (server_iter->server->udp_on_read_cb != NULL) {
            return server_iter->server->udp_on_read_cb();
        }
    }

    // not match server
    return NS_KNI;
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

int exec_tcp_read_cb(ns_processor_t *processor, ns_offload_t *offload)
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

        if (server_iter->server->tcp_on_read_cb != NULL) {
            return server_iter->server->tcp_on_read_cb();
        }
    }

    // not match server
    return NS_KNI;
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