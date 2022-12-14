#ifndef __DPDK_H__
#define __DPDK_H__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <sys/socket.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <thread>
using std::array;
using std::cout;
using std::endl;
using std::function;
using std::map;
using std::string;

static constexpr int NUM_MBUFS = (4096 - 1);
static constexpr int BURST_SIZE = 32;
static constexpr struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}};
static constexpr uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static inline uint32_t MAKE_IPV4_ADDR(uint8_t a, uint8_t b, uint8_t c,
                                      uint8_t d) {
  return (a + (b << 8) + (c << 16) + (d << 24));
}

static inline string ip2str(uint32_t ip) {
  struct in_addr addr;
  addr.s_addr = ip;
  return string(inet_ntoa(addr));
}

struct ArpRecord {
  uint8_t type;
  array<uint8_t, RTE_ETHER_ADDR_LEN> hwAddr;
  ArpRecord(uint8_t t, array<uint8_t, RTE_ETHER_ADDR_LEN> &&addr)
      : type(t), hwAddr(addr){};
  ArpRecord(uint8_t t, uint8_t *addr) : type(t) {
    for (int i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
      hwAddr[i] = addr[i];
    }
  };
  ArpRecord(const ArpRecord &r) : type(r.type) {
    for (int i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
      hwAddr[i] = r.hwAddr[i];
    }
  }
  ArpRecord() : type(0), hwAddr({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {}
};

class Dpdk {
public:
  Dpdk(int argc, char *argv[]);
  void init(int argc, char *argv[]);
  void run();
  void port_init();

private:
  void processSomePkts();
  using EtherHandlerType = void (Dpdk::*)(rte_ether_hdr *ehdr,
                                          struct rte_mbuf *pBuf);
  void send_arp(uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip);

  void ether_default_process(rte_ether_hdr *ehdr, struct rte_mbuf *pBuf);
  void arp_process(rte_ether_hdr *ehdr, struct rte_mbuf *pBuf);
  int encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac,
                     uint32_t sip, uint32_t dip);
  map<uint16_t, EtherHandlerType> etherPacketHandler = {
      {(uint16_t)rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP), &Dpdk::arp_process},
  };

  // data
  struct rte_mempool *mbuf_pool = nullptr;
  uint16_t devPortId = 0;
  uint8_t mac[RTE_ETHER_ADDR_LEN];
  uint32_t ip = MAKE_IPV4_ADDR(172, 16, 77, 130);
  map<uint32_t, ArpRecord> arpTable;

  // config
  const int num_rx_queues = 1;
  const int num_tx_queues = 1;
  struct rte_eth_conf port_conf = port_conf_default;
};
#endif