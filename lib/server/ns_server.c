#include <netinet/in.h>
#include <strings.h>

#include <rte_malloc.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include <server/ns_server.h>
#include <error/ns_error.h>

#define UDP_RING_SIZE 4096

ns_udp_server_t *ns_new_udp_server(
    const char *server_name,
    uint32_t ip_address, uint16_t listen_port
)
{
    ns_udp_server_t *server = rte_malloc(
        server_name,
        sizeof(struct ns_udp_server),
        0
    );
    if (server == NULL) return NULL;
    bzero(server, sizeof(struct ns_udp_server));

    server->snd_queue = rte_ring_create(
        "udp server send queue ring",
        UDP_RING_SIZE,
        rte_socket_id(),
        NULL
    );

    server->server_name = server_name;
    server->ip_address  = ip_address;
    server->listen_port = listen_port;

    return server;
}

void ns_free_udp_server(ns_udp_server_t *server)
{
    rte_ring_free(server->send_buffer);
    rte_free(server);
}

ns_tcp_server_t *ns_new_tcp_server(
    const char *server_name,
    uint32_t ip_address, uint16_t listen_port
)
{
    ns_tcp_table_t *tcp_table = new_tcp_table();
    if (tcp_table == NULL) return NULL;

    ns_tcp_server_t *server = rte_malloc(
        server_name,
        sizeof(struct ns_tcp_server),
        0
    );
    if (server == NULL) return NULL;
    bzero(server, sizeof(struct ns_tcp_server));

    server->server_name = server_name;
    server->ip_address  = ip_address;
    server->listen_port = listen_port;
    server->tcp_table   = tcp_table;

    return server;
}

void ns_free_tcp_server(ns_tcp_server_t *server)
{
    rte_free(server);
}

int udp_server_match(
    ns_udp_server_t *server,
    uint32_t ip_address, uint16_t listen_port
)
{
    if (
        server->ip_address == ip_address &&
        server->listen_port == listen_port
    ) {
        return NS_SERVER_MATCH;
    }

    return NS_SERVER_NOT_MATCH;
}

int tcp_server_match(
    ns_tcp_server_t *server,
    uint32_t ip_address, uint16_t listen_port
)
{
    if (
        server->ip_address == ip_address &&
        server->listen_port == listen_port
    ) {
        return NS_SERVER_MATCH;
    }

    return NS_SERVER_NOT_MATCH;
}

int ns_udp_callbacks_set(
    ns_udp_server_t *server,
    ns_udp_on_read_callback  udp_on_read_cb,
    ns_udp_on_write_callback udp_on_write_cb
)
{
    if (server == NULL || server->protocol != IPPROTO_UDP) {
        return NS_ERROR_SET_SERVER_CALLBACKS_FAILED;
    }
    server->udp_on_read_cb  = udp_on_read_cb;
    server->udp_on_write_cb = udp_on_write_cb;

    return NS_OK;
}

int ns_tcp_callbacks_set(
    ns_tcp_server_t *server,
    ns_tcp_on_read_callback  tcp_on_read_cb,
    ns_tcp_on_write_callback tcp_on_write_cb
)
{
    if (server == NULL || server->protocol != IPPROTO_TCP) {
        return NS_ERROR_SET_SERVER_CALLBACKS_FAILED;
    }
    server->tcp_on_read_cb  = udp_on_read_cb;
    server->tcp_on_write_cb = udp_on_write_cb;

    return NS_OK;
}