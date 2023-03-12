#include "ns_error.h"

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
    case NS_ERROR_PROCESS_PACKETS_EMPTY:
        return "ns_error_process_packets_empty";

    default:
        break;
    }

    return "ns_ok";
}