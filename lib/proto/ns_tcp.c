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
#include <base/ns_list.h>
#include <error/ns_error.h>

#define RING_NAME_SIZE 32
#define RING_SIZE      1024
#define TCP_WINDOW     25600

#define IPV4_HEADER_LEN 20
#define TCP_HEADER_LEN  20

// TODO: Retransmission packet handling
// TODO: Disordered packet handling

static int tcp_handle_listen_status_packet(
    ns_tcp_table_t *listen_tcp_table,
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
    ns_tcp_entry_t *tcp_entry,
    struct rte_ipv4_hdr *ipv4_hdr, struct rte_tcp_hdr *tcp_hdr,
    ns_offload_t **offload
);

static int tcp_handle_syn_sent_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
);

static int tcp_handle_fin_wait_1_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
);

static int tcp_handle_fin_wait_2_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_ring *snd_queue,
    struct rte_tcp_hdr *tcp_hdr
);

static int tcp_handle_closing_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
);

static int tcp_handle_time_wait_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
);

// Update recv serial number
static void update_recv_seq_number(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
);

// tcp send packet to peer
static int tcp_send_packet(
    ns_tcp_entry_t *tcp_entry,
    struct rte_tcp_hdr *tcp_hdr, uint8_t tcp_flag,
    uint32_t data_len, char *data
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
    if (!snd_queue) return NS_ERROR_CODE;

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

void free_tcp_entry(ns_tcp_entry_t *tcp_entry)
{
    rte_ring_free(tcp_entry->snd_queue);
    rte_free(tcp_entry);
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

void free_tcp_packet(struct ns_tcp_packet_t *tcp_packet)
{
    rte_free(tcp_packet);
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
        tcp_mbuf,
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

int tcp_state_machine_exec(
    int is_server,
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

        case NS_TCP_STATUS_ESTABLISHED:
            rc = tcp_handle_established_status_packet(
                tcp_entry, ipv4_hdr, tcp_hdr, offload
            );
            break;

        // Server TCP Status
        case NS_TCP_STATUS_LISTEN:
            if (!is_server) {
                return NS_ERROR_TCP_PROTOCOL_ILLEGAL;
            }
            rc = tcp_handle_listen_status_packet(
                tcp_table, tcp_entry, ether_hdr, tcp_hdr, ipv4_hdr
            );
            break;

        case NS_TCP_STATUS_SYN_RCVD:
            rc = tcp_handle_syn_recv_status_packet(tcp_entry, tcp_hdr);
            break;

        // TCP passive disconnection state
        case NS_TCP_STATUS_CLOSE_WAIT:
            rc = tcp_handle_close_wait_packet(tcp_entry, tcp_hdr);
            break;

        case NS_TCP_STATUS_LAST_ACK:
            rc = tcp_handle_last_ack_status_packet(tcp_entry, tcp_hdr);
            break;

        // Client TCP Status
        case NS_TCP_STATUS_SYN_SENT:
            if (is_server) {
                return NS_ERROR_TCP_PROTOCOL_ILLEGAL;
            }
            rc = tcp_handle_syn_sent_status_packet(tcp_entry, tcp_hdr);
            break;

        // TCP active disconnection status
        case NS_TCP_STATUS_FIN_WAIT1:
            rc = tcp_handle_fin_wait_1_status_packet(tcp_entry, tcp_hdr);
            break;

        case NS_TCP_STATUS_FIN_WAIT2:
            rc = tcp_handle_fin_wait_2_status_packet(tcp_entry, tcp_hdr);
            break;

        case NS_TCP_STATUS_CLOSING:
            rc = tcp_handle_closing_status_packet(tcp_entry, tcp_hdr);

        case NS_TCP_STATUS_TIME_WAIT:
            rc = tcp_handle_time_wait_status_packet(tcp_entry, tcp_hdr);
            break;
    }

    return rc;
}

uint32_t dequeue_all_tcp_packets(ns_tcp_entry_t *tcp_entry, ns_tcp_packet_t **tcp_pakcets)
{
    if (tcp_entry->packet_counts == 0) return 0;

    uint32_t cnt = rte_ring_dequeue_burst(
        tcp_entry->snd_queue,
        tcp_pakcets,
        tcp_entry->packet_counts,
        NULL
    );

    // zeroing packet counts
    tcp_entry->packet_counts -= cnt;

    return cnt;
}

uint32_t enqueue_all_tcp_packets(
    ns_tcp_entry_t *tcp_entry, ns_tcp_packet_t **tcp_pakcets, int packet_cnt
)
{
    if (packet_cnt == 0) return 0;

    uint32_t cnt = rte_ring_enqueue_burst(
        tcp_entry->snd_queue,
        tcp_pakcets,
        packet_cnt,
        NULL
    );

    // fill packet counts
    tcp_entry->packet_counts += cnt;

    return cnt;
}

// tcp server status handler functions
static int tcp_handle_listen_status_packet(
    ns_tcp_table_t *tcp_table,
    ns_tcp_entry_t *listen_tcp_entry,
    struct rte_ether_hdr *ether_hdr,
    struct rte_ipv4_hdr *ipv4_hdr,
    struct rte_tcp_hdr *tcp_hdr
)
{
    if (!(tcp_hdr->tcp_flas & RTE_TCP_SYN_FLAG)) {
        return NS_ERROR_TCP_PROTOCOL_ILLEGAL;
    }
    ns_tcp_entry_t *syn_tcp_entry = create_tcp_entry(
        ipv4_hdr->src_addr, ipv4_hdr->dst_addr,
        tcp_hdr->src_port, tcp_hdr->dst_port,
        ether_hdr->dst_addr,
    );
    if (syn_tcp_entry == NULL) {
        return NS_ERROR_RTE_MALLOC_FAILED;
    }

    update_recv_seq_number(syn_tcp_entry, tcp_hdr);
    // Send back SYN + ACK packet
    int rc = tcp_send_packet(
        syn_tcp_entry,
        tcp_hdr, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG,
        0, NULL
    );
    if (rc != NS_OK) return rc;

    tcp_entry->tcp_status = NS_TCP_STATUS_SYN_RCVD;

    // Add tcp entry to tcp table
    NS_LIST_ADD(tcp_table->tcp_entries, syn_tcp_entry);

    return NS_OK;
}

static int tcp_handle_syn_recv_status_packet(
    ns_tcp_entry_t *syn_tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{
    if (!(tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG)) {
        return NS_ERROR_TCP_PROTOCOL_ILLEGAL;
    }

    update_recv_seq_number(syn_tcp_entry, tcp_hdr);
    tcp_entry->tcp_status = NS_TCP_STATUS_ESTABLISHED;

    return NS_OK;
}

static int tcp_handle_close_wait_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{
    return NS_ERROR_TCP_PROTOCOL_ILLEGAL;
}

static int tcp_handle_last_ack_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{
    if (!(tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG)) {
        return NS_ERROR_TCP_PROTOCOL_ILLEGAL;
    }

    tcp_entry->tcp_status = NS_TCP_STATUS_CLOSED;
    free_tcp_entry(tcp_entry);

    // REMOVE tcp entry to tcp table
    NS_LIST_DEL(tcp_table->tcp_entries, syn_tcp_entry);

    return NS_OK;
}

// tcp established status handler function
static int tcp_handle_established_status_packet(
    ns_tcp_entry_t *tcp_entry,
    struct rte_ipv4_hdr *ipv4_hdr, struct rte_tcp_hdr *tcp_hdr,
    ns_offload_t **offload
)
{
    if (!(tcp_hdr->tcp_flags & RTE_TCP_PSH_FLAG)) {
        if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) {
            return NS_OK;
        }
        return NS_ERROR_TCP_PROTOCOL_ILLEGAL;
    }

    *offload = create_offload();
    if (*offload == NULL) {
        return NS_ERROR_RTE_MALLOC_FAILED;
    }

    char *data = rte_pktmbuf_mtod_offset(
        tcp_hdr, char *,
        sizeof(struct rte_tcp_hdr)
    );

    // fill offload
    int rc = fill_five_tuple(
        *offload,
        ipv4_hdr->src_addr, ipv4_hdr->dst_addr,
        tcp_hdr->src_port, tcp_hdr->dst_port,
        IPPROTO_TCP
    )
    if (rc != NS_OK) {
        NS_PRINT("fill five tuple failed. err:%s", ns_strerror(rc));
        return NS_ERROR_TCP_PROCESS_FAILED;
    }
    rc = fill_data(
        *offload,
        data,
        ntohs(ipv4_hdr->tcp_length) - sizeof(struct rte_ipv4_hdr)
    );
    if (rc != NS_OK) {
        NS_PRINT("fill data failed. err:%s", ns_strerror(rc));
        return NS_ERROR_TCP_PROCESS_FAILED;
    }

    return NS_OK;
}

static int tcp_handle_syn_sent_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{
    // When a tcp connection is in SYN-SENT phase, only SYN + ACK packets
    // from the Server side are processed in reply
    if (!(tcp_hdr->tcp_flag & RTE_TCP_SYN_FLAG) ||
        !(tcp_hdr->tcp_flag & RTE_TCP_ACK_FLAG))
    {
        return NS_ERROR_TCP_PROCESS_FAILED;
    }

    update_recv_seq_number(tcp_entry, tcp_hdr);
    int rc = tcp_send_packet(
        tcp_entry
        tcp_hdr, RTE_TCP_ACK_FLAG,
        0, NULL
    );
    if (rc != NS_OK) {
        return rc;
    }
    tcp_entry->tcp_status = NS_TCP_STATUS_ESTABLISHED;

    return NS_OK;
}

static int tcp_handle_fin_wait_1_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{
    if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) {
        // NOTICE: TCP 4 waves may be simplified to 3 waves back
        // After that, the active disconnected party state will transition directly to TIME_WAIT
        if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) {
            update_recv_seq_number(tcp_entry, tcp_hdr);
            int rc = tcp_send_packet(
                tcp_entry,
                tcp_hdr, RTE_TCP_ACK_FLAG,
                0, NULL
            );
            if (rc != NS_OK) {
                return rc;
            }
            tcp_entry->tcp_status = NS_TCP_STATUS_TIME_WAIT;

            return NS_OK;
        }

        update_recv_seq_number(tcp_entry, tcp_hdr);
        tcp_entry->tcp_status = NS_TCP_STATUS_FIN_WAIT2;

        return NS_OK;
    }

    // NOTICE: If a FIN packet is received in the FIN_WAIT_1 state,
    // it changes its state to CLOSING and sends an ACK packet to the other end
    if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) {
        update_recv_seq_number(tcp_entry, tcp_hdr);
        tcp_entry->tcp_status = NS_TCP_STATUS_CLOSING;

        return tcp_send_packet(
            tcp_entry,
            tcp_hdr, RTE_TCP_ACK_FLAG,
            0, NULL
        );
    }

    return NS_ERROR_TCP_PROCESS_FAILED;
}

static int tcp_handle_fin_wait_2_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{
    if (tcp_hdr->flags ~ RTE_TCP_FIN_FLAG) {
        return NS_ERROR_TCP_PROCESS_FAILED;
    }

    update_recv_seq_number(tcp_entry, tcp_hdr);
    tcp_entry->tcp_status = NS_TCP_STATUS_TIME_WAIT;

    return tcp_send_packet(
        tcp_entry,
        tcp_hdr, RTE_TCP_ACK_FLAG,
        0, NULL
    );
}

static int tcp_handle_closing_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{
    if (tcp_hdr->tcp_flags ~ RTE_TCP_ACK_FLAG) {
        return NS_ERROR_TCP_PROCESS_FAILED;
    }

    update_recv_seq_number(tcp_entry, tcp_hdr);
    tcp_entry->tcp_status = NS_TCP_STATUS_TIME_WAIT;

    return NS_OK;
}

static int tcp_handle_time_wait_status_packet(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{
    // TODO: Wait 2MSL to recycle the connectionWait 2MSL to recycle the connection
    return NS_OK;
}

static void update_recv_seq_number(
    ns_tcp_entry_t *tcp_entry, struct rte_tcp_hdr *tcp_hdr
)
{
    tcp_entry->rcv_nxt = ntohl(tcp_hdr->sent_seq) + 1;
}

static int tcp_send_packet(
    ns_tcp_entry_t *tcp_entry,
    struct rte_tcp_hdr *tcp_hdr, uint8_t tcp_flag,
    uint32_t data_len, char *data
)
{
    if (!(tcp_flag & RTE_TCP_PSH_FLAG) && data_len > 0) {
        NS_PRINT("tcp data not empty, but has no RTE_TCP_PSH_FLAG..\n");
        return NS_ERROR_TCP_PROTOCOL_ILLEGAL;
    }

    ns_tcp_packet_t *tcp_packet = create_tcp_packet();
    if (tcp_packet == NULL) {
        return NS_ERROR_RTE_MALLOC_FAILED;
    }
    tcp_packet->tcp_hdr.src_port = tcp_entry->dst_port;
    tcp_packet->tcp_hdr.dst_port = tcp_entry->src_port;

    tcp_packet->tcp_hdr.sent_seq = tcp_entry->snd_nxt;
    tcp_packet->tcp_hdr.recv_ack = tcp_entry->rcv_nxt;

    // NOTICE: TCP Options is not supported at this time
    // Data offset (4 bits)
    //   Specifies the size of the TCP header in 32-bit words.
    //   The minimum size header is 5 words and the maximum is 15 words thus giving
    //   the minimum size of 20 bytes and maximum of 60 bytes,
    //   allowing for up to 40 bytes of options in the header.
    //   This field gets its name from the fact that it is also the offset from
    //   the start of the TCP segment to the actual data.
    // 
    // Reserved (4 bits)
    // For future use and should be set to zero.
    // From 2003–2017, the last bit (bit 103 of the header) was defined as the NS (Nonce Sum) flag by the experimental RFC 3540,
    // ECN-nonce. ECN-nonce never gained widespread use and the RFC was moved to Historic status.
    tcp_packet->tcp_hdr.data_off  = 0x50;
    tcp_packet->tcp_hdr.tcp_flags = tcp_flag;

    // NOTICE: ARQ is not supported at this stage
    tcp_packet->tcp_hdr.rx_win = TCP_WINDOW;

    // NOTICE: TCP Segmentation is not supported at this stage
    tcp_packet->data_length = data_len;
    tcp_packet->data        = data;

    int rc = rte_ring_enqueue(tcp_entry->snd_queue, tcp_packet);
    if (rc != 0) {
        free_tcp_packet(tcp_packet);
        return NS_ERROR_RING_ENQUEUE_FAILED;
    }
    tcp_entry->packet_counts++;

    return NS_OK;
}

// TODO: TCP Segmentation is not supported
int tcp_encode_packet(struct rte_mbuf *tcp_mbuf, ns_offload_t *offload)
{
    // total packet length
    uint16_t packet_total_len = offload->data_len + RTE_ETHER_HDR_LEN
        + IPV4_HEADER_LEN + TCP_HEADER_LEN;
    
    // ether header
    struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(tcp_mbuf, struct rte_ether_hdr *);
    rte_memcpy(ether_hdr->src_addr, offload->src_ether_addr, RTE_ETHER_ADDR_LEN);
    rte_memcoy(ether_hdr->dst_addr, offload->dst_ether_addr, RTE_ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // ipv4 header
    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(
        tcp_mbuf,
        struct rte_ipv4_hdr *,
        sizeof(struct rte_ether_hdr)
    );
    // ipv4 version
    ipv4_hdr->version = 0x4;
    // 0101 => 160 bits = 20 bytes ==> minimal value (header without data) [RFC 6274 - page 9]
    ipv4_hdr->ihl = 0x5;

    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->total_length    = htons(packet_total_len - RTE_ETHER_HDR_LEN);
    ipv4_hdr->packet_id       = 0;
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live    = 64;
    ipv4_hdr->next_proto_id   = IPPROTO_TCP;

    ipv4_hdr->src_addr  = offload->src_ip_addr;
    ipv4_hdr->dest_addr = offload->dest_ip_addr;

    // calculate ipv4 header checksum
    ipv4_hdr->checksum = 0;
    ipv4_hdr->checksum = rte_ipv4_cksum(ipv4_hdr);

    // tcp header
    struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(
        tcp_mbuf,
        struct rte_tcp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
    );
    tcp_hdr->src_port = offload->src_port;
    tcp_hdr->dst_port = offload->dst_port;
}