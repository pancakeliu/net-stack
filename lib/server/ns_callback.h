#ifndef _NETSTACK_SERVER_CALLBACK_H_
#define _NETSTACK_SERVER_CALLBACK_H_

#include <rte_ring.h>

#include <proto/ns_tcp.h>
#include <proto/ns_offload.h>

// callbacks
typedef int (*ns_udp_on_read_callback)(struct rte_ring *send_buffer, ns_offload_t *offload);
typedef int (*ns_udp_on_write_callback)();

typedef int (*ns_tcp_on_read_callback)(ns_tcp_entry_t *tcp_entry, ns_offload_t *offload);
typedef int (*ns_tcp_on_write_callback)();

typedef int (*ns_other_on_read_callback)();
typedef int (*ns_other_on_write_callback)();

#endif // _NETSTACK_SERVER_CALLBACK_H_