#ifndef _NETSTACK_SERVER_CALLBACK_H_
#define _NETSTACK_SERVER_CALLBACK_H_

// callbacks
typedef int (*ns_udp_on_read_callback)();
typedef int (*ns_udp_on_write_callback)();

typedef int (*ns_tcp_on_read_callback)();
typedef int (*ns_tcp_on_write_callback)();

typedef int (*ns_other_on_read_callback)();
typedef int (*ns_other_on_write_callback)();

#endif // _NETSTACK_SERVER_CALLBACK_H_