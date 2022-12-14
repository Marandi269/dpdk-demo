#include "dpdk.h"

Dpdk::Dpdk(int argc, char *argv[]) { init(argc, argv); };

void Dpdk::init(int argc, char *argv[]) {
  if (rte_eal_init(argc, argv) < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL init!");
  }
  this->mbuf_pool = rte_pktmbuf_pool_create(
      "mbuf_pool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (!this->mbuf_pool) {
    rte_exit(EXIT_FAILURE, "Could not create buf pool\n");
  }
  this->port_init();
  rte_eth_macaddr_get(this->devPortId, (struct rte_ether_addr *)&mac);
  for (uint8_t i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
    if (i) {
      printf(":");
    }
    printf("%02x", mac[i]);
  }
  printf("\n");
  if (rte_eth_promiscuous_enable(this->devPortId) < 0) {
    cout << "ether set rte_eth_promiscuous_enable failed!" << endl;
  };
  cout << "dpdk initialized!" << endl;
}

// void Dpdk::port_init() {
//   uint16_t nb_sys_ports = rte_eth_dev_count_avail();
//   if (nb_sys_ports <= 0) {
//     rte_exit(EXIT_FAILURE, "No Support eth found!\n");
//   }

//   struct rte_eth_dev_info dev_info;
//   rte_eth_dev_info_get(this->devPortId, &dev_info);

//   rte_eth_dev_configure(this->devPortId, this->num_rx_queues,
//                         this->num_tx_queues, &port_conf);

//   if (rte_eth_rx_queue_setup(this->devPortId, 0, 1024,
//                              rte_eth_dev_socket_id(this->devPortId), NULL,
//                              this->mbuf_pool) < 0) {
//     rte_exit(EXIT_FAILURE, "Could not setup RX queue!\n");
//   }
// }

void Dpdk::port_init() {
  uint16_t nb_sys_ports = rte_eth_dev_count_avail(); //
  if (nb_sys_ports == 0) {
    rte_exit(EXIT_FAILURE, "No Supported eth found\n");
  }

  struct rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(this->devPortId, &dev_info); //

  const int num_rx_queues = 1;
  const int num_tx_queues = 1;
  struct rte_eth_conf port_conf = port_conf_default;
  rte_eth_dev_configure(this->devPortId, num_rx_queues, num_tx_queues,
                        &port_conf);

  if (rte_eth_rx_queue_setup(this->devPortId, 0, 1024,
                             rte_eth_dev_socket_id(this->devPortId), NULL,
                             mbuf_pool) < 0) {

    rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
  }

  struct rte_eth_txconf txq_conf = dev_info.default_txconf;
  txq_conf.offloads = port_conf.rxmode.offloads;
  if (rte_eth_tx_queue_setup(this->devPortId, 0, 1024,
                             rte_eth_dev_socket_id(this->devPortId),
                             &txq_conf) < 0) {

    rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
  }

  if (rte_eth_dev_start(this->devPortId) < 0) {
    rte_exit(EXIT_FAILURE, "Could not start\n");
  }
};

void Dpdk::run() {
  cout << "dpdk running!" << endl;

  while (true) {
    this->processSomePkts();
  }
}

void Dpdk::processSomePkts() {
  struct rte_mbuf *mbufs[BURST_SIZE];
  uint8_t n = rte_eth_rx_burst(this->devPortId, 0, mbufs, BURST_SIZE);
  if (n > BURST_SIZE) {
    // ERROR
    rte_exit(EXIT_FAILURE, "Error receiving from eth!\n");
  }
  cout << "received " << int(n) << " packets" << endl;
  if (!n) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  }

  for (uint8_t i = 0; i < n; i++) {
    struct rte_mbuf *p = mbufs[i];
    struct rte_ether_hdr *hdr = rte_pktmbuf_mtod(p, struct rte_ether_hdr *);
    cout << "ether packet type: " << hdr->ether_type << endl;
    EtherHandlerType handler = this->etherPacketHandler[hdr->ether_type];
    this->etherPacketHandler.at(hdr->ether_type);
    handler = bool(handler) ? handler : &Dpdk::ether_default_process;
    (this->*handler)(hdr, p);
    rte_pktmbuf_free(p);
  }
}

void Dpdk::arp_process(rte_ether_hdr *ehdr, struct rte_mbuf *pBuf) {
  cout << "arp processing..." << endl;
  struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(
      pBuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

  cout << "arp look for: " << ip2str(ahdr->arp_data.arp_tip) << "\tmy ip is"
       << ip2str(this->ip) << endl;

  if (ahdr->arp_data.arp_tip != this->ip) {
    return;
  }
  this->arpTable[ahdr->arp_data.arp_sip] =
      ArpRecord(0, ahdr->arp_data.arp_sha.addr_bytes);
  if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
    printf("arp --> request\n");
    this->send_arp(RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes,
                   ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
  }
  if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
    printf("arp --> reply\n");
  }
}

void Dpdk::send_arp(uint16_t opcode, uint8_t *dst_mac, uint32_t sip,
                    uint32_t dip) {
  const unsigned total_length =
      sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (!mbuf) {
    rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
  }

  mbuf->pkt_len = total_length;
  mbuf->data_len = total_length;

  uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
  this->encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

  rte_eth_tx_burst(this->devPortId, 0, &mbuf, 1);
  rte_pktmbuf_free(mbuf);
}

int Dpdk::encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac,
                         uint32_t sip, uint32_t dip) {
  // 1 ethhdr
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->s_addr.addr_bytes, this->mac, RTE_ETHER_ADDR_LEN);
  if (!strncmp((const char *)dst_mac, (const char *)gDefaultArpMac,
               RTE_ETHER_ADDR_LEN)) {
    uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
    rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
  } else {
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
  }
  eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

  // 2 arp
  struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
  arp->arp_hardware = htons(1);
  arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
  arp->arp_hlen = RTE_ETHER_ADDR_LEN;
  arp->arp_plen = sizeof(uint32_t);
  arp->arp_opcode = htons(opcode);

  rte_memcpy(arp->arp_data.arp_sha.addr_bytes, this->mac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

  arp->arp_data.arp_sip = sip;
  arp->arp_data.arp_tip = dip;

  return 0;
}

void Dpdk::ether_default_process(rte_ether_hdr *ehdr, struct rte_mbuf *pBuf) {}