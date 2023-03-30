#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <arpa/inet.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_memcpy.h>

#include <proto/ns_tcp.h>
#include <proto/ns_offload.h>
#include <base/ns_print.h>
#include <error/ns_error.h>

#define RING_NAME_SIZE 32
#define RING_SIZE      1024
#define TCP_WINDOW     25600

// tcp server status handler functions
static int tcp_handle_listen_status_packet(
    ns_tcp_table_t *tcp_table,
    ns_tcp_entry_t *tcp_entry,
    struct rte_ether_hdr *ether_hdr,
    struct rte_ipv4_hdr *ipv4_hdr,
    struct rte_tcp_hdr *tcp_hdr
);
static int tcp_handle_syn_recv_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
);
static int tcp_handle_close_wait_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
);
static int tcp_handle_last_ack_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
);

// tcp established status handler function
static int tcp_handle_established_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr,
    ns_offload_t *offload
);

ns_tcp_table_t *create_tcp_table()
{
    ns_tcp_table_t *tcp_table = rte_malloc(
        "net-stack tcp table",
        sizeof(struct ns_tcp_table),
        0
    );
    if (tcp_table == NULL) return NULL;
    bzero(tcp_table, sizeof(struct ns_tcp_table));

    return tcp_table;
}

ns_tcp_entry_t *create_tcp_entry(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t *src_mac_address
)
{
    ns_tcp_entry_t *tcp_entry = rte_malloc(
        "net-stack tcp entry",
        sizeof(struct ns_tcp_entry),
        0
    );
    if (tcp_entry == NULL) return NULL;
    bzero(tcp_entry, sizeof(struct ns_tcp_entry));

    tcp_entry->src_ip   = src_ip;
    tcp_entry->dst_ip   = dst_ip;
    tcp_entry->src_port = src_port;
    tcp_entry->dst_port = dst_port;
    tcp_entry->protocol = IPPROTO_TCP;
    tcp_entry->sock_fd  = -1;

    // tcp entry initialized to NS_TCP_STATUS_CLOSED
    tcp_entry->tcp_status = NS_TCP_STATUS_CLOSED;

    char sbuf_name[RING_NAME_SIZE] = {};
    snprintf(sbuf_name, RING_NAME_SIZE, "sndbuf:%x%d", src_ip, src_port);
    tcp_entry->snd_buffer = rte_ring_create(
        sbuf_name, RING_SIZE, rte_socket_id(), NULL
    );

    char rbuf_name[RING_NAME_SIZE] = {};
    snprintf(rbuf_name, RING_NAME_SIZE, "rcvbuf:%x%d", src_ip, src_port);
    tcp_entry->rcv_buffer = rte_ring_create(
        rbuf_name, RING_SIZE, rte_socket_id(), NULL
    );

    // In a typical implementation of the TCP protocol,
    // the snd_next field of tcp is usually initialized to a random number
    // However, if this random number is initialised too large,
    // the snd_next field is susceptible to rewinding,
    // so it is important to ensure consistent packet rewinding during the implementation of the tcp protocol.
    // Let's simplify the process here for now and initialise snd_next to 0
    tcp_entry->snd_nxt = 0;

    rte_memcpy(tcp_entry->local_mac_address, src_mac_address, RTE_ETHER_ADDR_LEN);

    return tcp_entry;
}

void tcp_entry_set_status(ns_tcp_entry_t *tcp_entry, NS_TCP_STATUS status)
{
    tcp_entry->status = status;
}

ns_tcp_packet_t *create_tcp_packet()
{
    ns_tcp_packet_t *tcp_packet = rte_malloc(
        "net-stack tcp packet",
        sizeof(struct ns_tcp_packet),
        0
    );
    if (tcp_packet == NULL) return NULL;
    bzero(tcp_packet, sizeof(struct ns_tcp_packet));

    return tcp_packet;
}

ns_tcp_entry_t *search_tcp_entry(
    ns_tcp_table_t *tcp_table,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port
)
{
    struct ns_tcp_entry *iter;
    // established tcp entries
    for (iter = tcp_table->entries; iter != NULL; iter = iter->next) {
        if (
            iter->src_ip == src_ip && iter->dst_ip == dst_ip &&
            iter->src_port == src_port && iter->dst_port == dst_port
        ) {
            return iter;
        }
    }

    // listen tcp entries
    // TODO: A list of tcp listen states can be distinguished here
    for (iter = tcp_table->entries; iter != NULL; iter = iter->next) {
        if (iter->dst_port == dst_port && iter->tcp_status == NS_TCP_STATUS_LISTEN) {
            return iter;
        }
    }

    return NULL;
}

int tcp_parse_header(
    struct rte_mbuf *tcp_mbuf,
    struct rte_ether_hdr **ether_hdr,
    struct rte_ipv4_hdr **ipv4_hdr,
    struct rte_tcp_hdr **tcp_hdr
)
{
    *ipv4_hdr = rte_pktmbuf_mtod_offset(
        tcp_mbuf,
        struct rte_ipv4_hdr *,
        sizeof(struct rte_ether_hdr)
    );
    *tcp_hdr = rte_pktmbuf_mtod_offset(
        tcp_mbufk,
        struct rte_tcp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
    );

    uint16_t cksum = (*tcp_hdr)->cksum;
    (*tcp_hdr)->cksum = 0;
    if (rte_ipv4_udptcp_cksum(*ipv4_hdr, *tcp_hdr) != cksum) {
        return NS_ERROR_CHECKSUM_MISMATCH;
    }
    (*tcp_hdr)->cksum = cksum;

    return NS_OK;
}

int tcp_server_state_machine_exec(
    struct rte_mbuf *tcp_mbuf,
    ns_tcp_table_t *tcp_table,
    ns_tcp_entry_t *tcp_entry,
    struct rte_ether_hdr *ether_hdr,
    struct rte_ipv4_hdr *ipv4_hdr, struct rte_tcp_hdr *tcp_hdr,
    ns_offload_t **offload
)
{
    if (*offload != NULL) return NS_ERROR_CODE;

    int rc = NS_OK;
    switch (tcp_entry->tcp_status) {
        case NS_TCP_STATUS_CLOSED:
            break;

        // Server TCP Status
        case NS_TCP_STATUS_ESTABLISHED:
            int tcp_length = ntohs(ipv4_hdr->tcp_length) - sizeof(struct rte_ipv4_hdr);
            rc = tcp_handle_established_status_packet(
                tcp_entry, tcp_hdr, tcp_length
            );
            break;

        case NS_TCP_STATUS_LISTEN:
            rc = tcp_handle_listen_status_packet(
                tcp_table, tcp_entry, ether_hdr, tcp_hdr, ipv4_hdr
            );
            break;

        case NS_TCP_STATUS_SYN_RCVD:
            // TODO: handle syn_recv packet
            break;

        case NS_TCP_STATUS_CLOSE_WAIT:
            // TODO: handle close_wait packet
            break;

        case NS_TCP_STATUS_LAST_ACK:
            // TODO: handler last_ack packet
            break;

        // Client TCP Status
        case NS_TCP_STATUS_SYN_SENT:
        case NS_TCP_STATUS_FIN_WAIT1:
        case NS_TCP_STATUS_FIN_WAIT2:
        case NS_TCP_STATUS_CLOSING:
        case NS_TCP_STATUS_TIME_WAIT:
            break;
    }

    return rc;
}

// tcp server status handler functions
static int tcp_handle_listen_status_packet(
    ns_tcp_table_t *tcp_table,
    ns_tcp_entry_t *tcp_entry,
    struct rte_ether_hdr *ether_hdr,
    struct rte_ipv4_hdr *ipv4_hdr,
    struct rte_tcp_hdr *tcp_hdr
)
{
    if (!(tcp_hdr->tcp_flas & RTE_TCP_SYN_FLAG) || tcp_entry->status != NS_TCP_STATUS_LISTEN) {
        return NS_OK;
    }
    ns_tcp_entry_t *tcp_entry = create_tcp_entry(
        ipv4_hdr->src_addr, ipv4_hdr->dst_addr,
        tcp_hdr->src_port, tcp_hdr->dst_port,
        ether_hdr->dst_addr,
    );
    if (tcp_entry == NULL) {
        return NS_ERROR_RTE_MALLOC_FAILED;
    }

    ns_tcp_packet_t *tcp_packet = create_tcp_packet();
    if (tcp_packet == NULL) {
        return NS_ERROR_RTE_MALLOC_FAILED;
    }
    tcp_packet->tcp_hdr.src_port = tcp_entry->dst_port;
    tcp_packet->tcp_hdr.dst_port = tcp_entry->src_port;

    tcp_packet->tcp_hdr.sent_seq = tcp_entry->snd_nxt;
    tcp_packet->tcp_hdr.recv_ack = ntohl(tcp_hdr->sent_seq) + 1;
    tcp_entry->rcv_nxt           = tcp_packet->tcp_hdr.recv_ack;

    tcp_packet->tcp_hdr.data_off  = 0x50;
    tcp_packet->tcp_hdr.tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    tcp_packet->tcp_hdr.rx_win    = TCP_WINDOW;

    tcp_packet->data_length = 0;
    tcp_packet->data        = NULL;

    rte_ring_mp_enqueue(tcp_entry->snd_buffer, tcp_packet);
    tcp_entry->tcp_status = NS_TCP_STATUS_SYN_RCVD;

    return NS_OK;
}

static int tcp_handle_syn_recv_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{

}

static int tcp_handle_close_wait_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{

}

static int tcp_handle_last_ack_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{

}

// tcp established status handler function
static int tcp_handle_established_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr,
    ns_offload_t *offload
)
{
    
}