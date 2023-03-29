#ifndef _NS_STACK_SERVER_SERVER_H_
#define _NS_STACK_SERVER_SERVER_H_

#include <stdint.h>

#include <server/ns_callback.h>

typedef struct ns_server {
    char    *server;
    uint32_t ip_address;
    uint16_t listen_port;
    int      protocol;

    ns_udp_on_read_callback  udp_on_read_cb;
    ns_udp_on_write_callback udp_on_write_cb;

    ns_tcp_on_read_callback  tcp_on_read_cb;
    ns_tcp_on_write_callback tcp_on_write_cb;

    ns_other_on_read_callback  other_on_read_cb;
    ns_other_on_write_callback other_on_write_cb;
} ns_server_t;

ns_server_t *ns_new_server(
    char *server_name,
    uint32_t ip_address, uint16_t listen_port, int protocol
);

void ns_free_server(ns_server_t *server);

#define NS_SERVER_MATCH     1
#define NS_SERVER_NOT_MATCH 0

int server_match(
    ns_server_t *server,
    uint32_t ip_address, uint16_t listen_port, int protocol
);

int set_udp_callbacks(
    ns_server_t *server,
    ns_udp_on_read_callback  udp_on_read_cb,
    ns_udp_on_write_callback udp_on_write_cb
);

int set_tcp_callbacks(
    ns_server_t *server,
    ns_tcp_on_read_callback  tcp_on_read_cb,
    ns_tcp_on_write_callback tcp_on_write_cb
);

int set_other_callbacks(
    ns_server_t *server,
    ns_other_on_read_callback  other_on_read_cb,
    ns_other_on_write_callback other_on_write_cb
);

#endif // _NS_STACK_SERVER_SERVER_H_