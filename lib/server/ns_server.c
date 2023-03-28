#include <netinet/in.h>
#include <strings.h>

#include <rte_malloc.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#include <server/ns_server.h>
#include <error/ns_error.h>

ns_server_t *new_server(
    char *server_name,
    uint32_t ip_address, uint16_t listen_port, int protocol
)
{
    ns_server_t *server = rte_malloc(
        server,
        sizeof(struct ns_server),
        0
    );
    if (ns_server == NULL) return NULL;
    bzero(server, sizeof(struct ns_server));

    server->server     = server_name;
    server->ip_address = ip_address;
    server->port       = port;
    server->protocol   = protocol;

    return server;
}

void free_server(ns_server_t *server)
{
    rte_free(server);
}

int set_udp_callbacks(
    ns_server_t *server,
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

int set_tcp_callbacks(
    ns_server_t *server,
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

int set_other_callbacks(
    ns_server_t *server,
    ns_other_on_read_callback  other_on_read_cb,
    ns_other_on_write_callback other_on_write_cb
)
{
    if (server == NULL) return NS_ERROR_SET_SERVER_CALLBACKS_FAILED;
    if (server->protocol == IPPROTO_UDP || server->protocol == IPPROTO_TCP) {
        return NS_ERROR_SET_SERVER_CALLBACKS_FAILED;
    }

    server->other_on_read_cb  = other_on_read_cb;
    server->other_on_write_cb = other_on_write_cb;

    return NS_OK;
}