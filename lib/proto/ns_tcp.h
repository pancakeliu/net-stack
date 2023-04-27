#ifndef _NETSATCK_PROTO_NS_TCP_H_
#define _NETSATCK_PROTO_NS_TCP_H_

#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ring.h>
#include <rte_tcp.h>
#include <rte_ip.h>

#include <proto/ns_offload.h>

typedef enum NS_TCP_STATUS {
    NS_TCP_STATUS_CLOSED      = 0,
    NS_TCP_STATUS_ESTABLISHED = 1,

    NS_TCP_STATUS_LISTEN      = 2,
    NS_TCP_STATUS_SYN_RCVD    = 3,
    NS_TCP_STATUS_CLOSE_WAIT  = 4,
    NS_TCP_STATUS_LAST_ACK    = 5,

    NS_TCP_STATUS_SYN_SENT    = 6,
    NS_TCP_STATUS_FIN_WAIT1   = 7,
    NS_TCP_STATUS_FIN_WAIT2   = 8,
    NS_TCP_STATUS_CLOSING     = 9,
    NS_TCP_STATUS_TIME_WAIT   = 10,
} NS_TCP_STATUS;

typedef struct ns_tcp_entry {
    int sock_fd; // socket descriptor

    // five tuple fields
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int      protocol;

    uint8_t  local_mac_address[RTE_ETHER_ADDR_LEN];

    uint32_t snd_nxt; // seq number
    uint32_t rcv_nxt; // rcv number

    NS_TCP_STATUS tcp_status;

    // send buffer
    rte_ring *snd_buffer;
    rte_ring *rcv_buffer;

    struct ns_tcp_entry *prev;
    struct ns_tcp_entry *next;
} ns_tcp_entry_t;

typedef struct ns_tcp_table {
    uint32_t count;
    ns_tcp_entry_t *tcp_entries;
    // TODO: epoll
} ns_tcp_table_t;

#define NS_MAX_TCP_OPTIONS_NUM 10
typedef struct ns_tcp_packet {
    struct rte_tcp_hdr tcp_hdr;

    uint32_t  opt_length;
    uint32_t *options;
    uint32_t  data_length;
    char     *data;
} ns_tcp_packet_t;

ns_tcp_table_t *create_tcp_table();
// NOTICE: Since server recycling is not supported at the moment
// tcp table objects do not need to be recycled either.

ns_tcp_entry_t *create_tcp_entry(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t *src_mac_address
);

void free_tcp_entry(ns_tcp_entry_t *tcp_entry);

void tcp_entry_set_status(ns_tcp_entry_t *tcp_entry, NS_TCP_STATUS status);

ns_tcp_packet_t *create_tcp_packet();
void free_tcp_packet(ns_tcp_packet_t *tcp_packet);

ns_tcp_entry_t *search_tcp_entry(
    ns_tcp_table_t *tcp_table,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port
);

int tcp_parse_header(
    struct rte_mbuf *tcp_mbuf,
    struct rte_ether_hdr **ether_hdr,
    struct rte_ipv4_hdr **ipv4_hdr,
    struct rte_tcp_hdr **tcp_hdr
);

int tcp_state_machine_exec(
    int is_server,
    ns_tcp_table_t *tcp_table,
    ns_tcp_entry_t *tcp_entry,
    struct rte_ether_hdr *ether_hdr,
    struct rte_ipv4_hdr *ipv4_hdr, struct rte_tcp_hdr *tcp_hdr,
    ns_offload_t **offload
);

#endif // _NETSATCK_PROTO_NS_TCP_H_