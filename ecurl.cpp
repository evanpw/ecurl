#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

enum class EtherType : uint16_t {
    Ipv4 = 0x0008,
    Arp = 0x0608,
    Ipv6 = 0xDD86
};

struct EthernetHeader {
    uint8_t destination[6];
    uint8_t source[6];
    EtherType ether_type;
} __attribute__((packed));

static_assert(sizeof(EthernetHeader) == 14, "EthernetHeader has the wrong size");

struct Ipv4Header {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t source[4];
    uint8_t destination[4];

    void set_version(uint8_t value);
    void set_header_length(uint8_t value);
    void set_checksum(uint16_t value);
    void set_total_length(uint16_t value);

    uint8_t get_header_length() const;
    uint16_t get_total_length() const;

} __attribute__((packed));

static_assert(sizeof(Ipv4Header) == 20, "Ipv4Header has the wrong size");

void Ipv4Header::set_version(uint8_t value) {
    version_ihl = (version_ihl & 0xF) | (value << 4);
}

void Ipv4Header::set_header_length(uint8_t value) {
    version_ihl = (version_ihl & 0xF0) | (value & 0xF);
}

void Ipv4Header::set_checksum(uint16_t value) {
    checksum = htons(value);
}

void Ipv4Header::set_total_length(uint16_t value) {
    total_length = htons(value);
}

uint8_t Ipv4Header::get_header_length() const {
    return version_ihl & 0xF;
}

uint16_t Ipv4Header::get_total_length() const {
    return htons(total_length);
}

uint16_t compute_checksum(Ipv4Header* packet) {
    uint32_t sum = 0;

    // Sum up all words in the header
    size_t header_length = packet->get_header_length() * 4;
    uint8_t* bytes = (uint8_t*)packet;
    for (size_t i = 0; i < header_length; i += 2) {
        uint16_t word = (bytes[i] << 8) | bytes[i + 1];
        sum += word;
    }

    // Include the overflow
    while ((sum >> 16) != 0) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return ~sum;
}

struct TcpHeader {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset_res_ns;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;

    void set_source_port(uint16_t value);
    void set_dest_port(uint16_t value);
    void set_fin(bool value);
    void set_syn(bool value);
    void set_psh(bool value);
    void set_ack(bool value);

    uint16_t get_source_port() const;
    uint16_t get_dest_port() const;
    bool get_fin() const;
    bool get_syn() const;
    bool get_psh() const;
    bool get_ack() const;
} __attribute__((packed));

void TcpHeader::set_source_port(uint16_t value) {
    source_port = htons(value);
}

void TcpHeader::set_dest_port(uint16_t value) {
    dest_port = htons(value);
}

bool TcpHeader::get_fin() const {
    return flags & (1 << 0);
}

void TcpHeader::set_fin(bool value) {
    uint8_t bit = 1 << 0;

    if (value) {
        flags |= bit;
    } else {
        flags &= ~bit;
    }
}

void TcpHeader::set_syn(bool value) {
    uint8_t bit = 1 << 1;

    if (value) {
        flags |= bit;
    } else {
        flags &= ~bit;
    }
}

uint16_t TcpHeader::get_source_port() const {
    return ntohs(source_port);
}

uint16_t TcpHeader::get_dest_port() const {
    return ntohs(dest_port);
}

bool TcpHeader::get_syn() const {
    return flags & (1 << 1);
}

void TcpHeader::set_psh(bool value) {
    uint8_t bit = 1 << 3;

    if (value) {
        flags |= bit;
    } else {
        flags &= ~bit;
    }
}

bool TcpHeader::get_psh() const {
    return flags & (1 << 3);
}

void TcpHeader::set_ack(bool value) {
    uint8_t bit = 1 << 4;

    if (value) {
        flags |= bit;
    } else {
        flags &= ~bit;
    }
}

bool TcpHeader::get_ack() const {
    return flags & (1 << 4);
}

static_assert(sizeof(TcpHeader) == 20, "TcpHeader has the wrong size");

uint16_t compute_checksum(TcpHeader* packet, uint8_t* local_ip, uint8_t* remote_ip, size_t payload_size) {
    uint32_t sum = 0;

    size_t header_length = (packet->data_offset_res_ns >> 4) * 4;
    size_t total_length = header_length + payload_size;

    // Compute the checksum of the pseudo-header (see http://www.roman10.net/2011/11/27/how-to-calculate-iptcpudp-checksumpart-1-theory/)
    sum += (local_ip[0] << 8) | local_ip[1];
    sum += (local_ip[2] << 8) | local_ip[3];
    sum += (remote_ip[0] << 8) | remote_ip[1];
    sum += (remote_ip[2] << 8) | remote_ip[3];
    sum += 6; // TCP protocol
    sum += total_length;

    // Sum up all words in the header
    uint8_t* bytes = (uint8_t*)packet;
    for (size_t i = 0; i < total_length; i += 2) {
        uint16_t word = (bytes[i] << 8) | bytes[i + 1];
        sum += word;
    }

    // Include the overflow
    while ((sum >> 16) != 0) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return ~sum;
}

struct SplayedPacket {
    SplayedPacket(uint8_t* buffer = nullptr, size_t size = 0, EthernetHeader* ethernet = nullptr, Ipv4Header* ip = nullptr, TcpHeader* tcp = nullptr, uint8_t* payload = nullptr)
    : buffer(buffer), size(size), ethernet(ethernet), ip(ip), tcp(tcp), payload(payload)
    {}

    SplayedPacket(const SplayedPacket&) = delete;
    SplayedPacket& operator=(const SplayedPacket&) = delete;
    SplayedPacket& operator=(SplayedPacket&&) = delete;

    SplayedPacket(SplayedPacket&& rhs) {
        this->buffer = rhs.buffer;
        this->size = rhs.size;
        this->ethernet = rhs.ethernet;
        this->ip = rhs.ip;
        this->tcp = rhs.tcp;
        this->payload = rhs.payload;

        rhs.buffer = nullptr;
        rhs.size = 0;
        rhs.ethernet = nullptr;
        rhs.ip = nullptr;
        rhs.tcp = nullptr;
        rhs.payload = nullptr;
    }

    ~SplayedPacket() {
        delete[] buffer;
    }

    void fill_checksum();

    uint8_t* buffer;
    size_t size;
    EthernetHeader* ethernet;
    Ipv4Header* ip;
    TcpHeader* tcp;
    uint8_t* payload;
};

void SplayedPacket::fill_checksum() {
    if (ip) {
        ip->set_checksum(compute_checksum(ip));

        if (tcp) {
            size_t header_length = sizeof(Ipv4Header) + sizeof(TcpHeader); 
            size_t payload_size = ip->get_total_length() - header_length;
            tcp->checksum = htons(compute_checksum(tcp, ip->source, ip->destination, payload_size));
        }
    }
}

void print_packet(SplayedPacket& packet) {
    printf("source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            packet.ethernet->source[0],
            packet.ethernet->source[1],
            packet.ethernet->source[1],
            packet.ethernet->source[3],
            packet.ethernet->source[4],
            packet.ethernet->source[5]);

    printf("destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            packet.ethernet->destination[0],
            packet.ethernet->destination[1],
            packet.ethernet->destination[2],
            packet.ethernet->destination[3],
            packet.ethernet->destination[4],
            packet.ethernet->destination[5]);

    switch (packet.ethernet->ether_type) {
        case EtherType::Ipv4:
            printf("ether_type: ipv4\n");
            break;

        case EtherType::Arp:
            printf("ether_type: arp\n");
            break;

        case EtherType::Ipv6:
            printf("ether_type: ipv6\n");
            break;

        default:
            printf("ether_type: UNKNOWN\n");
            break;
    }

    if (!packet.ip) {
        return;
    }

    if (packet.ip->protocol == 0x06) {
        printf("protocol: tcp\n");
    } else if (packet.ip->protocol == 0x11) {
        printf("protocol: udp\n");
    } else {
        printf("protocol: UNKNOWN\n");
    }

    printf("total_length: %d\n", (int)packet.ip->get_total_length());
    printf("source: %d.%d.%d.%d\n",
           (int)packet.ip->source[0],
           (int)packet.ip->source[1],
           (int)packet.ip->source[2],
           (int)packet.ip->source[3]);
    printf("destination: %d.%d.%d.%d\n",
           (int)packet.ip->destination[0],
           (int)packet.ip->destination[1],
           (int)packet.ip->destination[2],
           (int)packet.ip->destination[3]);

    if (!packet.tcp) {
        return;
    }

    printf("source_port: %d\n", (int)packet.tcp->get_source_port());
    printf("dest_port: %d\n", (int)packet.tcp->get_dest_port());
    printf("seq_number: %u\n", ntohl(packet.tcp->seq_number));
    printf("ack_number: %u\n", ntohl(packet.tcp->ack_number));
    printf("data_offset: %d\n", packet.tcp->data_offset_res_ns >> 4);
    printf("window_size: %d\n", (int)ntohs(packet.tcp->checksum));

    printf("flags:");

    if (packet.tcp->get_fin()) {
        printf(" FIN");
    }

    if (packet.tcp->get_syn()) {
        printf(" SYN");
    }

    if (packet.tcp->flags & 4) {
        printf(" RST");
    }

    if (packet.tcp->get_psh()) {
        printf(" PSH");
    }

    if (packet.tcp->get_ack()) {
        printf(" ACK");
    }

    if (packet.tcp->flags & 32) {
        printf(" URG");
    }

    if (packet.tcp->flags & 64) {
        printf(" ECE");
    }

    if (packet.tcp->flags & 128) {
        printf( " CWR");
    }

    printf("\n");

    if (packet.payload) {
        size_t header_length = sizeof(Ipv4Header) + sizeof(TcpHeader); 
        size_t payload_size = packet.ip->get_total_length() - header_length;
    
        char* msg = new char[payload_size + 1];
        memcpy(msg, packet.payload, payload_size);
            
        printf("Payload:\n%s\n", msg);
    }
}

SplayedPacket parse_packet(uint8_t* buffer, size_t size) {
    SplayedPacket result;

    result.buffer = buffer;
    result.size = size;
    result.ethernet = (EthernetHeader*)buffer;

    if (result.ethernet->ether_type == EtherType::Ipv4) {
        result.ip = (Ipv4Header*)(buffer + sizeof(EthernetHeader));

        if (result.ip->protocol == 0x06) {
           result.tcp = (TcpHeader*)(buffer + sizeof(EthernetHeader) + sizeof(Ipv4Header));

            size_t header_length = sizeof(Ipv4Header) + sizeof(TcpHeader); 
            size_t payload_size = result.ip->get_total_length() - header_length;
            if (payload_size > 0) {
                result.payload = buffer + sizeof(EthernetHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader);
            }
        }
    }

    return result;
}

SplayedPacket build_packet(uint8_t* local_mac, uint8_t* remote_mac,
                           uint8_t* local_ip, uint8_t* remote_ip,
                           uint16_t local_port, uint16_t remote_port,
                           uint8_t* payload = nullptr, size_t payload_size = 0) {
    
    size_t size = sizeof(EthernetHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + payload_size;

    // We're assuming that uint8_t is a "character type" that's allowed to alias, like char
    uint8_t* buffer = new uint8_t[size];
    memset(buffer, 0, size);

    EthernetHeader* ethernet = (EthernetHeader*)buffer;
    memcpy(ethernet->source, local_mac, 6);
    memcpy(ethernet->destination, remote_mac, 6);
    ethernet->ether_type = EtherType::Ipv4;

    Ipv4Header* ip = (Ipv4Header*)(buffer + sizeof(EthernetHeader));
    ip->set_version(4);
    ip->set_header_length(5);           // 5 32-bit words = 20 byts
    ip->set_total_length(size - sizeof(EthernetHeader));
    ip->ttl = 30;
    ip->protocol = 0x06;                // TCP
    memcpy(ip->source, local_ip, 4);
    memcpy(ip->destination, remote_ip, 4);

    TcpHeader* tcp = (TcpHeader*)(buffer + sizeof(EthernetHeader) + sizeof(Ipv4Header));
    tcp->set_source_port(local_port);
    tcp->set_dest_port(remote_port);
    tcp->data_offset_res_ns = (5 << 4);     // 5 4-byte words
    tcp->window_size = 29000;

    if (payload_size > 0) {
        memcpy(buffer + sizeof(EthernetHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader), payload, payload_size);
    }

    return {buffer, size, ethernet, ip, tcp, payload};
}

SplayedPacket wait_for_packet(int sockfd, uint8_t* local_ip) {
    while (true) {
        uint8_t* buffer = new uint8_t[4096];

        ssize_t bytes_recvd = recvfrom(sockfd, buffer, 4096, 0, NULL, NULL);
        if (bytes_recvd == -1) {
            perror("recvfrom");
            return {};
        } else if (bytes_recvd == 0) {
            return {};
        }

        SplayedPacket packet = parse_packet(buffer, bytes_recvd);

        // Wait for a packet sent to my IP address
        if (packet.ip) {
            if (memcmp(packet.ip->destination, local_ip, 4) == 0) {
                return packet;
            }
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s interface_name\n", argv[0]);
        return 1;
    }

    const char* if_name = argv[1];

    // Open raw socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket");
    }

    // Get index of network interface
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        return 1;
    }

    // Get MAC address of network interface
    struct ifreq if_mac;
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
        perror("SIOCGIFHWADDR");
        return 1;
    }

    assert(if_mac.ifr_hwaddr.sa_family == ARPHRD_ETHER);

    uint8_t* local_mac = (uint8_t*)if_mac.ifr_hwaddr.sa_data;

    // Link-level address
    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_idx.ifr_ifindex;
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, local_mac, 6);
    device.sll_halen = 6;

    // My router (TODO: get this from ARP)
    uint8_t remote_mac[6] = {0xa4, 0x2b, 0x8c, 0xb8, 0x15, 0x6a};
    uint8_t local_ip[4] = {192, 168, 0, 18};
    uint8_t remote_ip[4] = {198, 199, 120, 200};
    uint16_t local_port = 52000 + rand() % 1000;
    uint16_t remote_port = 80;

    // Send SYN
    SplayedPacket syn_packet = build_packet(local_mac, remote_mac, local_ip, remote_ip, local_port, remote_port);
    syn_packet.tcp->set_syn(true);
    syn_packet.fill_checksum();

    int bytes_sent = sendto(sockfd, syn_packet.buffer, syn_packet.size, 0, (struct sockaddr*)&device, sizeof(device));
    if (bytes_sent <= 0) {
        perror("sendto() failed");
        return 1;
    }

    // Receive SYN-ACK
    SplayedPacket syn_ack_response = wait_for_packet(sockfd, local_ip);
    if (syn_ack_response.buffer) {
        print_packet(syn_ack_response);
        printf("\n");
    }
    assert(syn_ack_response.tcp->get_syn() && syn_ack_response.tcp->get_ack());

    // Send ACK
    SplayedPacket ack_packet = build_packet(local_mac, remote_mac, local_ip, remote_ip, local_port, remote_port);
    ack_packet.tcp->set_ack(true);
    ack_packet.tcp->seq_number = htonl(1);   // My last seq number + 1
    ack_packet.tcp->ack_number = htonl(ntohl(syn_ack_response.tcp->seq_number) + 1);
    ack_packet.fill_checksum();

    bytes_sent = sendto(sockfd, ack_packet.buffer, ack_packet.size, 0, (struct sockaddr*)&device, sizeof(device));
    if (bytes_sent <= 0) {
        perror("sendto() failed");
        return 1;
    }

    // Send HTTP request
    const char* request = "GET /login HTTP/1.0\r\n\r\n\0";
    SplayedPacket request_packet = build_packet(local_mac, remote_mac, local_ip, remote_ip, local_port, remote_port, (uint8_t*)request, strlen(request));
    request_packet.tcp->set_ack(true);
    request_packet.tcp->seq_number = htonl(1);
    request_packet.tcp->ack_number = htonl(ntohl(syn_ack_response.tcp->seq_number) + 1);
    request_packet.fill_checksum();

    bytes_sent = sendto(sockfd, request_packet.buffer, request_packet.size, 0, (struct sockaddr*)&device, sizeof(device));
    if (bytes_sent <= 0) {
        perror("sendto() failed");
        return 1;
    }

    uint32_t local_seq_number = 1 + strlen(request);
    uint32_t remote_seq_number = ntohl(syn_ack_response.tcp->seq_number) + 1;

    // Read response until we get a FIN packet
    bool finished = false;
    while (!finished) {
        SplayedPacket response = wait_for_packet(sockfd, local_ip);
        assert(response.buffer && response.tcp);

        if (ntohl(response.tcp->seq_number) == remote_seq_number) {
            print_packet(response);
            printf("\n");

            size_t header_length = sizeof(Ipv4Header) + sizeof(TcpHeader); 
            size_t payload_size = response.ip->get_total_length() - header_length;

            if (response.tcp->get_fin()) {
                assert(payload_size == 0);
                payload_size += 1;
                finished = true;
            }

            // Don't ack the same byte twice
            if (payload_size > 0)
            {
                remote_seq_number += payload_size;
               
                SplayedPacket ack_packet = build_packet(local_mac, remote_mac, local_ip, remote_ip, local_port, remote_port);
                ack_packet.tcp->set_ack(true);
                ack_packet.tcp->seq_number = htonl(local_seq_number);
                ack_packet.tcp->ack_number = htonl(remote_seq_number);
                ack_packet.fill_checksum();

                bytes_sent = sendto(sockfd, ack_packet.buffer, ack_packet.size, 0, (struct sockaddr*)&device, sizeof(device));
                if (bytes_sent <= 0) {
                    perror("sendto() failed");
                    return 1;
                }
            }
        }
    }

    // Send FIN packet
    SplayedPacket fin_packet = build_packet(local_mac, remote_mac, local_ip, remote_ip, local_port, remote_port);
    fin_packet.tcp->set_ack(true);
    fin_packet.tcp->set_fin(true);
    fin_packet.tcp->seq_number = htonl(local_seq_number);
    fin_packet.tcp->ack_number = htonl(remote_seq_number);
    fin_packet.fill_checksum();

    bytes_sent = sendto(sockfd, fin_packet.buffer, fin_packet.size, 0, (struct sockaddr*)&device, sizeof(device));
    if (bytes_sent <= 0) {
        perror("sendto() failed");
        return 1;
    }

    // Wait for the final ACK
    SplayedPacket response = wait_for_packet(sockfd, local_ip);
    assert(response.buffer && response.tcp);
    assert(ntohl(response.tcp->seq_number) == remote_seq_number);

    print_packet(response);
    printf("\n");

    close(sockfd);
    return 0;
}
