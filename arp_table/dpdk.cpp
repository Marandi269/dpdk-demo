#include "dpdk.h"

function<void (rte_ether_hdr *ehdr, struct rte_mbuf *pBuf, Dpdk dpdk)> ether_empty_process  = [](rte_ether_hdr *ehdr, struct rte_mbuf *pBuf, Dpdk dpdk) {
    cout<<"empty handler..."<<endl;
};

map<uint32_t, ArpRecord>  Dpdk::arpTable = {};

int encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip, Dpdk dpdk) {
    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, dpdk.gSrcMac, RTE_ETHER_ADDR_LEN);
    if (!strncmp((const char *)dst_mac, (const char *)dpdk.gDefaultArpMac, RTE_ETHER_ADDR_LEN)) {
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

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, dpdk.gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    return 0;
}


struct rte_mbuf * send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip, Dpdk dpdk){
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip, dpdk);

    return mbuf;
}

void arp_process(rte_ether_hdr *ehdr, struct rte_mbuf *pBuf, Dpdk dpdk) {
    cout<<"arp processing..."<<endl;
    struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(pBuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
    struct in_addr addr;
    addr.s_addr = ahdr->arp_data.arp_tip;
    string arpDst = string(inet_ntoa(addr));
    addr.s_addr = dpdk.ip;
    string myIp = string(inet_ntoa(addr));
    cout<< "arp look for: "<< arpDst << "\tmy ip is" << myIp <<endl;
    if(ahdr->arp_data.arp_tip != dpdk.ip) {
        return;
    }
    dpdk.arpTable[ahdr->arp_data.arp_sip] = ArpRecord(0, ahdr->arp_data.arp_sha.addr_bytes);
    if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
        printf("arp --> request\n");
        struct rte_mbuf *arpbuf = send_arp(dpdk.mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes,
                                                ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip, dpdk);
        rte_eth_tx_burst(dpdk.portId, 0, &arpbuf, 1);
        rte_pktmbuf_free(arpbuf);
    }  
    if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
        printf("arp --> reply\n");
    }
}

static uint16_t icmp_checksum(uint16_t *addr, int count) {
    register long sum = 0;
    while (count > 1) {
        sum += *(unsigned short*)addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}


static int encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
                              uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb, const unsigned char* padding, Dpdk dpdk) {

    // 1 ether
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, dpdk.gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2 ip
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) + 56);
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; // ttl = 64
    ip->next_proto_id = IPPROTO_ICMP;
    ip->src_addr = sip;
    ip->dst_addr = dip;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3 icmp
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmp->icmp_code = 0;
    icmp->icmp_ident = id;
    icmp->icmp_seq_nb = seqnb;

    memcpy((u_int8_t*)&icmp[1], padding, 56);
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = icmp_checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr) + 56);

    return 0;
}

static struct rte_mbuf *send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
                                     uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb, const unsigned char* padding, Dpdk dpdk) {

    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) + 56;
    printf("total_length: %d\n", total_length);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }


    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb, padding, dpdk);

    return mbuf;

}


static int encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len, Dpdk dpdk) {

    // encode

    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, dpdk.gDstMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dpdk.gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);


    // 2 iphdr
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; // ttl = 64
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = dpdk.ip;
    ip->dst_addr = dpdk.dstIp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3 udphdr

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = dpdk.port;
    udp->dst_port = dpdk.dstPort;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t*)(udp+1), data, udplen);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    struct in_addr addr;
    addr.s_addr = dpdk.ip;
    printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(dpdk.port));

    addr.s_addr = dpdk.dstIp;
    printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(dpdk.dstPort));

    return 0;
}


static struct rte_mbuf *send_udp(Dpdk dpdk, uint8_t *data, uint16_t length) {
    // mempool --> mbuf
    const unsigned total_len = length + 42;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(dpdk.mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_udp_pkt(pktdata, data, total_len, dpdk);
    return mbuf;
}

void ipv4_process(rte_ether_hdr *ehdr, struct rte_mbuf *pBuf, Dpdk dpdk){
    struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(pBuf, struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
    if(iphdr->next_proto_id == IPPROTO_ICMP){
        printf("icmp...\n");
        struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
        struct in_addr addr;
        addr.s_addr = iphdr->src_addr;
        cout<<"icmp ---> src: %s " << inet_ntoa(addr) <<endl;

        if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {

            addr.s_addr = iphdr->dst_addr;
            printf(" local: %s , type : %d\n", inet_ntoa(addr), icmphdr->icmp_type);
            unsigned char *p = (unsigned char *)(void *)&icmphdr[1];
            u_int8_t padding[56];
            memcpy(padding, p, 56);
            struct rte_mbuf *txbuf = send_icmp(dpdk.mbuf_pool, ehdr->s_addr.addr_bytes,
                                                    iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb, padding, dpdk);

            rte_eth_tx_burst(dpdk.portId, 0, &txbuf, 1);
            rte_pktmbuf_free(txbuf);
        }

        return;
    }
    
    if (iphdr->next_proto_id == IPPROTO_UDP) {

        struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
        rte_memcpy(dpdk.gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

        rte_memcpy(&dpdk.ip, &iphdr->dst_addr, sizeof(uint32_t));
        rte_memcpy(&dpdk.dstIp, &iphdr->src_addr, sizeof(uint32_t));

        rte_memcpy(&dpdk.port, &udphdr->dst_port, sizeof(uint16_t));
        rte_memcpy(&dpdk.dstPort, &udphdr->src_port, sizeof(uint16_t));

        uint16_t length = ntohs(udphdr->dgram_len);
        *((char*)udphdr + length) = '\0';

        struct in_addr addr;
        addr.s_addr = iphdr->src_addr;
        printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

        addr.s_addr = iphdr->dst_addr;
        printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port),
                (char *)(udphdr+1));


        struct rte_mbuf *txbuf = send_udp(dpdk, (uint8_t *)(udphdr+1), length);
        rte_eth_tx_burst(dpdk.portId, 0, &txbuf, 1);
        rte_pktmbuf_free(txbuf);

        return;
    }
    
    cout<<"unhandled ipv4..."<<endl;
}

map<uint16_t, function<void (rte_ether_hdr *ehdr, struct rte_mbuf *pBuf, Dpdk dpdk)>> Dpdk::etherProcessFuncs = {
    {
        (uint16_t) rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP),
        arp_process,
    },
    {
        rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4),
        ipv4_process,
    }
};

Dpdk::Dpdk(int argc, char *argv[]){
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    this->mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
                                                            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == nullptr) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    this->port_init();
    rte_eth_macaddr_get(this->portId, (struct rte_ether_addr *)gSrcMac);
}

void Dpdk::port_init() {
    uint16_t nb_sys_ports= rte_eth_dev_count_avail(); //
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(this->portId, &dev_info); //

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(this->portId, num_rx_queues, num_tx_queues, &port_conf);


    if (rte_eth_rx_queue_setup(this->portId, 0 , 1024,
                            rte_eth_dev_socket_id(this->portId),NULL, mbuf_pool) < 0) {

        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

    }

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(this->portId, 0 , 1024,
                            rte_eth_dev_socket_id(this->portId), &txq_conf) < 0) {

        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");

    }

    if (rte_eth_dev_start(this->portId) < 0 ) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }

};

void Dpdk::run(){
    while (true)
    {
        this->processSomePkts();
    }
    
}

void Dpdk::processSomePkts(){
    struct rte_mbuf *mbufs[BURST_SIZE];
    unsigned num_recvd = rte_eth_rx_burst(this->portId, 0, mbufs, BURST_SIZE);
    if (num_recvd > BURST_SIZE) {
        rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
    }
    cout<<"num_recvd: "<<num_recvd<<endl;
    if(!num_recvd){
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    for (int i = 0;i < num_recvd;i ++) {
        struct rte_mbuf *pBuf = mbufs[i];
        struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(pBuf, struct rte_ether_hdr*);
        
        function<void (rte_ether_hdr *ehdr, struct rte_mbuf *pBuf, Dpdk dpdk)> handler = etherProcessFuncs[(ehdr->ether_type)];
        
        handler = bool(handler)? handler : ether_empty_process;
        handler(ehdr, pBuf, *this);
        rte_pktmbuf_free(pBuf);
    }
}