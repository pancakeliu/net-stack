#ifndef _NETSTACK_ERROR_H_
#define _NETSTACK_ERROR_H_

static const int NS_OK                                = 0;
static const int NS_ERROR_EAL_INIT_FAILED             = -1;
static const int NS_ERROR_MEMPOOL_CREATE_FAILED       = -2;
static const int NS_ERROR_NO_AVALIABLE_ETH_DEV        = -3;
static const int NS_ERROR_PORT_INFO_GET_FAILED        = -4;
static const int NS_ERROR_PORT_CONFIGURE_FAILED       = -5;
static const int NS_ERROR_PORT_RX_QUEUE_SETUP_FAILED  = -6;
static const int NS_ERROR_PORT_TX_QUEUE_SETUP_FAILED  = -7;
static const int NS_ERROR_PORT_START_FAILED           = -8;
static const int NS_ERROR_GET_PORT_MAC_ADDRESS_FAILED = -9;
static const int NS_ERROR_PROCESS_PACKETS_EMPTY       = -10;

const char *ns_strerror(const int error_code);

#endif // _NETSTACK_ERROR_H_