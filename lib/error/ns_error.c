#include <error/ns_error.h>

const char *ns_strerror(const int error_code)
{
    switch (error_code) {
    case NS_ERROR_EAL_INIT_FAILED:
        return "ns_error_eal_init_failed";
    case NS_ERROR_MEMPOOL_CREATE_FAILED:
        return "ns_error_mempool_create_failed";
    case NS_ERROR_NO_AVALIABLE_ETH_DEV:
        return "ns_error_no_available_eth_dev";
    case NS_ERROR_PORT_INFO_GET_FAILED:
        return "ns_error_port_info_get_failed";
    case NS_ERROR_PORT_CONFIGURE_FAILED:
        return "ns_error_port_configure_failed";
    case NS_ERROR_PORT_RX_QUEUE_SETUP_FAILED:
        return "ns_error_port_rx_queue_setup_failed";
    case NS_ERROR_PORT_TX_QUEUE_SETUP_FAILED:
        return "ns_error_port_rx_queue_setup_failed";
    case NS_ERROR_PORT_START_FAILED:
        return "ns_error_port_start_failed";
    case NS_ERROR_GET_PORT_MAC_ADDRESS_FAILED:
        return "ns_error_get_port_mac_address_failed";
    case NS_ERROR_ARP_RECORD_ALREADY_EXISTS:
        return "ns_error_arp_record_already_exists";
    case NS_ERROR_RTE_MALLOC_FAILED:
        return "ns_error_rte_malloc_failed";
    case NS_ERROR_CREATE_PROCESSOR_FAILED:
        return "ns_error_create_processor_failed";
    case NS_ERROR_SET_SERVER_CALLBACKS_FAILED:
        return "ns_error_set_server_callbacks_failed";
    case NS_ERROR_CODE:
        return "ns_error_code";
    case NS_ERROR_UDP_PROCESS_FAILED:
        return "ns_error_udp_process_failed";
    case NS_ERROR_TCP_PROCESS_FAILED:
        return "ns_error_tcp_process_failed";
    case NS_ERROR_CHECKSUM_MISMATCH:
        return "ns_error_checksum_mismatch";
    case NS_ERROR_TCP_SEQ_NUMBER:
        return "ns_error_tcp_seq_number";
    case NS_ERROR_TCP_PROTOCOL_ILLEGAL:
        return "ns_error_tcp_protocol_illegal";
    case NS_ERROR_RING_ENQUEUE_FAILED:
        return "ns_error_ring_enqueue_failed";
    case NS_ERROR_RING_DEQUEUE_FAILED:
        return "ns_error_ring_dequeue_failed";

    default:
        break;
    }

    return "ns_ok";
}