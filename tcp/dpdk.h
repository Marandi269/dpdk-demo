#ifndef __DPDK_H__
#define __DPDK_H__
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_mbuf_core.h>


class TcpConnection {
    enum staus {
        CLOSED = 0,
        LISTEN,
        SYN_SEND,
        SYN_REVD,
        ESTAB,

        FIN_WAIT_1,
        FIN_WAIT_2,
        CLOSING,
        TIME_WAIT,

        CLOSE_WAIT,
        LAST_ACK,
    };

    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint16_t dport;
};


#endif