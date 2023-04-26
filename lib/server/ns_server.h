#ifndef _NETSTACK_SERVER_SERVER_H_
#define _NETSTACK_SERVER_SERVER_H_

#include <stdint.h>

#include <rte_ring.h>

#include <server/ns_callback.h>
#include <proto/ns_tcp.h>

typedef struct ns_udp_server {
    char    *server_name;
    uint32_t ip_address;
    uint16_t listen_port;

    // udp packet delivery queue
    struct rte_ring *send_buffer;

    ns_udp_on_read_callback  udp_on_read_cb;
    ns_udp_on_write_callback udp_on_write_cb;
} ns_udp_server_t;

ns_udp_server_t *ns_new_udp_server(
    const char *server_name,
    uint32_t ip_address, uint16_t listen_port
);
void ns_free_udp_server(ns_udp_server_t *server);

typedef struct ns_tcp_server {
    char    *server_name;
    uint32_t ip_address;
    uint16_t listen_port;

    ns_tcp_table_t *tcp_table;

    ns_tcp_on_read_callback  tcp_on_read_cb;
    ns_tcp_on_write_callback tcp_on_write_cb;
} ns_tcp_server_t;

ns_tcp_server_t *ns_new_tcp_server(
    const char *server_name,
    uint32_t ip_address, uint16_t listen_port
);
void ns_free_tcp_server(ns_tcp_server_t *server);

typedef struct ns_other_server {
    char    *server_name;
    uint32_t ip_address;
    uint16_t listen_port;
    int      protocol;

    ns_tcp_on_read_callback  other_on_read_cb;
    ns_tcp_on_write_callback other_on_write_cb;
} ns_other_server_t;

ns_other_server_t *ns_new_other_server(
    const char *server_name,
    uint32_t ip_address, uint16_t listen_port, int protocol
);
void ns_free_other_server(ns_other_server_t *server);

#define NS_SERVER_MATCH     1
#define NS_SERVER_NOT_MATCH 0

int udp_server_match(
    ns_udp_server_t *server,
    uint32_t ip_address, uint16_t listen_port
);

int tcp_server_match(
    ns_tcp_server_t *server,
    uint32_t ip_address, uint16_t listen_port
);

int other_server_match(
    ns_other_server_t *server,
    uint32_t ip_address, uint16_t listen_port, int protocol
);

int ns_udp_callbacks_set(
    ns_udp_server_t *server,
    ns_udp_on_read_callback  udp_on_read_cb,
    ns_udp_on_write_callback udp_on_write_cb
);

int ns_tcp_callbacks_set(
    ns_tcp_server_t *server,
    ns_tcp_on_read_callback  tcp_on_read_cb,
    ns_tcp_on_write_callback tcp_on_write_cb
);

int ns_other_callbacks_set(
    ns_other_server_t *server,
    ns_other_on_read_callback  other_on_read_cb,
    ns_other_on_write_callback other_on_write_cb
);

#endif // _NETSTACK_SERVER_SERVER_H_