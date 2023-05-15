#include <rte_malloc.h>

#include <event/ns_write.h>
#include <proto/ns_tcp.h>
#include <proto/ns_udp.h>
#include <base/ns_print.h>

static int handle_tcp_write_event(ns_tcp_packet_t *tcp_packet, struct rte_mbuf *tx_pkt)
{
    
}

static int handle_udp_write_event(struct rte_mbuf *tx_pkt, ns_offload_t *udp_packet)
{
    return udp_encode_packet(tx_pkt, udp_packet);
}

uint32_t handle_write_events(
    ns_processor_t *processor, struct rte_mbuf **tx_pkts, uint32_t max_pkt_cnt
)
{
    uint32_t alloc_cnt = 0;

    // tcp write events
    ns_tcp_server_entry_t *tcp_server_iter = processor->tcp_server_entries;
    for (; tcp_server_iter && alloc_cnt < max_pkt_cnt; tcp_server_iter = tcp_server_iter->next) {
        ns_tcp_packet_t *tcp_packet = NULL;
        while (rte_ring_dequeue(tcp_server_iter->server->snd_queue, &tcp_packet) == 0) {
            struct rte_mbuf *tx_pkt = rte_pktmbuf_alloc(processor->mem_pool);
            if (tx_pkt == NULL) {
                NS_PRINT("alloc tcp packet memory buffer failed.");
                return alloc_cnt;
            }

            int rc = handle_tcp_write_event(tcp_packet, tx_pkt);
            if (rc != NS_OK) {
                NS_PRINT("handling tcp write event failed. err:%s", rte_strerror(rc));
                return alloc_cnt;
            }
            // TODO: free tcp_packet memory
            tx_pkts[alloc_cnt] = tx_pkt;
            alloc_cnt++;
        }
    }

    // TODO: In extreme scenarios, UDP packets may never be sent in time
    // udp write events
    ns_udp_server_entry_t *udp_server_iter = processor->udp_server_entries;
    for (; udp_server_iter && alloc_cnt < max_pkt_cnt; udp_server_iter = udp_server_iter->next) {
        ns_offload_t *udp_packet = NULL;
        while (rte_ring_dequeue(udp_server_iter->server->snd_queue, &udp_packet) == 0) {
            struct rte_mbuf *tx_pkt = rte_pktmbuf_alloc(processor->mem_pool);
            if (tx_pkt == NULL) {
                NS_PRINT("alloc udp packet memory buffer failed.");
                return alloc_cnt;
            }

            int rc = handle_udp_write_event(udp_packet, tx_pkt);
            if (rc != NS_OK) {
                NS_PRINT("handling udp write event failed. err:%s", rte_strerror(rc));
                return alloc_cnt;
            }
            // TODO: free tcp_packet memory
            tx_pkts[alloc_cnt] = tx_pkt;
            alloc_cnt++;
        }
    }

    return alloc_cnt
}