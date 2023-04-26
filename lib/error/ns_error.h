#ifndef _NETSTACK_ERROR_ERROR_H_
#define _NETSTACK_ERROR_ERROR_H_

static const int NS_OK                                = 0;

static const int NS_KNI                               = 1;

static const int NS_ERROR_EAL_INIT_FAILED             = -1;
static const int NS_ERROR_MEMPOOL_CREATE_FAILED       = -2;
static const int NS_ERROR_NO_AVALIABLE_ETH_DEV        = -3;
static const int NS_ERROR_PORT_INFO_GET_FAILED        = -4;
static const int NS_ERROR_PORT_CONFIGURE_FAILED       = -5;
static const int NS_ERROR_PORT_RX_QUEUE_SETUP_FAILED  = -6;
static const int NS_ERROR_PORT_TX_QUEUE_SETUP_FAILED  = -7;
static const int NS_ERROR_PORT_START_FAILED           = -8;
static const int NS_ERROR_GET_PORT_MAC_ADDRESS_FAILED = -9;
static const int NS_ERROR_ARP_RECORD_ALREADY_EXISTS   = -10;
static const int NS_ERROR_RTE_MALLOC_FAILED           = -11;
static const int NS_ERROR_CREATE_PROCESSOR_FAILED     = -12;
static const int NS_ERROR_SET_SERVER_CALLBACKS_FAILED = -13;
static const int NS_ERROR_CODE                        = -14;
static const int NS_ERROR_UDP_PROCESS_FAILED          = -15;
static const int NS_ERROR_TCP_PROCESS_FAILED          = -16;
static const int NS_ERROR_CHECKSUM_MISMATCH           = -17;
static const int NS_ERROR_TCP_SEQ_NUMBER              = -18;
static const int NS_ERROR_TCP_PROTOCOL_ILLEGAL        = -19;
static const int NS_ERROR_RING_ENQUEUE_FAILED         = -20;

const char *ns_strerror(const int error_code);

#endif // _NETSTACK_ERROR_ERROR_H_