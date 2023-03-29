#include <strings.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#include <rte_malloc.h>

#include <proto/ns_offload.h>
#include <error/ns_error.h>

ns_offload_t *new_offload()
{
    ns_offload_t *offload = rte_malloc(
        "net-stack offload",
        sizeof(struct ns_offload),
        0
    );
    if (offload == NULL) return NULL;
    bzero(offload, sizeof(struct ns_offload));

    return offload;
}

void free_offload(ns_offload_t *offload)
{
    rte_free(offload);
}

int fill_five_tuple(
    ns_offload_t *offload,
    uint32_t src_ip_addr, uint32_t dst_ip_addr,
    uint16_t src_port, uint16_t dst_port,
    int protocol
)
{
    if (offload == NULL) {
        return NS_ERROR_CODE;
    }
    offload->src_ip_addr = src_ip_addr;
    offload->dst_ip_addr = dst_ip_addr;
    offload->src_port    = src_port;
    offload->dst_port    = dst_port;
    offload->protocol    = protocol;

    return NS_OK;
}

int fill_data(char *data, uint16_t data_len)
{
    if (offload == NULL) {
        return NS_ERROR_CODE;
    }
    // NOTICE: Here a shallow copy is used to improve performance. data is later released
    offload->data     = data;
    offload->data_len = data_len;

    return NS_OK;
}

uint32_t ns_offload_src_ip_addr_get(ns_offload_t *offload)
{
    return offload->src_ip_addr;
}

void ns_offload_src_ip_addr_get_string(ns_offload_t *offload, char ip_str[INET_ADDRSTRLEN])
{
    inet_ntop(AF_INET, &(offload->src_ip_addr), ip_str, INET_ADDRSTRLEN);
}

uint32_t ns_offload_dst_ip_addr_get(ns_offload_t *offload)
{
    return offload->dst_ip_addr;
}

void ns_offload_dst_ip_addr_get_string(ns_offload_t *offload, char ip_str[INET_ADDRSTRLEN])
{
    inet_ntop(AF_INET, &(offload->dst_ip_addr), ip_str, INET_ADDRSTRLEN);
}

uint16_t ns_offload_src_port_get(ns_offload_t *offload)
{
    return offload->src_port;
}

uint16_t ns_offload_dst_port_get(ns_offload_t *offload)
{
    return offload->dst_port;
}

int ns_offload_protocol_get(ns_offload_t *offload)
{
    return offload->protocol;
}

char *ns_offload_data_get(ns_offload_t *offload)
{
    return offload->data;
}

uint16_t ns_offload_data_len(ns_offload_t *offload)
{
    return offload->data_len;
}