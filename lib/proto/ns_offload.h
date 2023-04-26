#ifndef _NETSTACK_PROTO_OFFLOAD_H_
#define _NETSTACK_PROTO_OFFLOAD_H_

#include <stdint.h>
#include <netinet/in.h>

typedef struct ns_offload {
    // network five tuple
    uint32_t src_ip_addr;
    uint32_t dst_ip_addr;
    uint16_t src_port;
    uint16_t dst_port;
    int      protocol;

    char    *data;
    uint16_t data_len;
} ns_offload_t;

ns_offload_t *create_offload();
void free_offload(ns_offload_t *offload);

int fill_five_tuple(
    ns_offload_t *offload,
    uint32_t src_ip_addr, uint32_t dst_ip_addr,
    uint16_t src_port, uint16_t dst_port,
    int protocol
);

int fill_data(ns_offload_t *offload, char *data, uint16_t data_len);

// functions available to users
uint32_t ns_offload_src_ip_addr_get(ns_offload_t *offload);
void ns_offload_src_ip_addr_get_string(ns_offload_t *offload, char ip_str[INET_ADDRSTRLEN]);

uint32_t ns_offload_dst_ip_addr_get(ns_offload_t *offload);
void ns_offload_dst_ip_addr_get_string(ns_offload_t *offload, char ip_str[INET_ADDRSTRLEN]);

uint16_t ns_offload_src_port_get(ns_offload_t *offload);
uint16_t ns_offload_dst_port_get(ns_offload_t *offload);

int ns_offload_protocol_get(ns_offload_t *offload);

char *ns_offload_data_get(ns_offload_t *offload);
uint16_t ns_offload_data_len(ns_offload_t *offload);

#endif // _NETSTACK_PROTO_OFFLOAD_H_