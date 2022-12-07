
#ifndef __DPDK_H__
#define __DPDK_H__
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_mbuf_core.h>

#include <functional>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <array>
#include <map>
using std::cout;
using std::endl;
using std::map;
using std::function;
using std::string;
using std::pair;
using std::make_pair;
using std::initializer_list;
using std::array;

static inline uint32_t MAKE_IPV4_ADDR(uint8_t a, uint8_t b, uint8_t c, uint8_t d){
    return (a + (b<<8) + (c<<16) + (d<<24)); 
}

struct ArpRecord {
    uint8_t type;
    array<uint8_t,RTE_ETHER_ADDR_LEN> hwAddr;
    ArpRecord(uint8_t t, array<uint8_t,RTE_ETHER_ADDR_LEN>&& addr): type(t), hwAddr(addr){};
    ArpRecord(uint8_t t, uint8_t *addr): type(t){
        for(int i=0; i<RTE_ETHER_ADDR_LEN; i++){
            hwAddr[i] = addr[i];
        }
    };
    ArpRecord(const ArpRecord &r): type(r.type){
        for(int i=0; i<RTE_ETHER_ADDR_LEN; i++){
            hwAddr[i] = r.hwAddr[i];
        }
    }
    ArpRecord():type(0), hwAddr({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {}
};

class Dpdk {
public:
    static constexpr int NUM_MBUFS = (4096-1);
    static constexpr int BURST_SIZE = 32;

    static constexpr struct rte_eth_conf port_conf_default = {
        .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
    };
    static constexpr uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static map<uint16_t, function<void (rte_ether_hdr *ehdr, struct rte_mbuf *pBuf, Dpdk dpdk)>> etherProcessFuncs;
    static map<uint32_t, ArpRecord> arpTable;

    uint32_t portId = 0;
    uint32_t ip = MAKE_IPV4_ADDR(172, 16, 77, 130);
    uint32_t dstIp = 0;
    uint16_t port;
    uint16_t dstPort;
    struct rte_mempool *mbuf_pool = nullptr;
    uint8_t gSrcMac[RTE_ETHER_ADDR_LEN]; 
    uint8_t gDstMac[RTE_ETHER_ADDR_LEN]; 
    

    Dpdk(int argc, char* argv[]);
    void port_init();
    void run();

private: 
    void processSomePkts();    
};


#endif