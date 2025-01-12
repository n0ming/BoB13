#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}
struct data {
    u_int8_t data[200];
};
typedef struct {
    char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void Ethernet_Mac(struct libnet_ethernet_hdr* ethernet) {
    printf("\n[Packet Result]\n");

    printf("dhost :");
    int count = sizeof(ethernet->ether_dhost) / sizeof(ethernet->ether_dhost[0]);

    for (int i = 0; i < count; i++) {
        printf("%02x", ethernet->ether_dhost[i]);
        if (i < count - 1) printf(":");
    }
    printf("\nshost :");
    for (int i = 0; i < count; i++) {
        printf("%02x", ethernet->ether_shost[i]);
        if (i < count - 1) printf(":");
    }
    printf("\n");
}

void IP_Addr(struct libnet_ipv4_hdr* ip) {
    struct in_addr src_ip_addr, dst_ip_addr;
    src_ip_addr.s_addr = ip->ip_src.s_addr;
    dst_ip_addr.s_addr = ip->ip_dst.s_addr;

    printf("src ip :%s\n", inet_ntoa(src_ip_addr));
    printf("dst ip :%s\n", inet_ntoa(dst_ip_addr));
}

void TCP_Port(struct libnet_tcp_hdr* tcp) {
    printf("src tcp :%u\n", ntohs(tcp->th_sport));
    printf("dst tcp :%u\n", ntohs(tcp->th_dport));
}

void DATA(const u_char* packet, int length) {
    printf("data :");
    if (length > 0) {
        int print_length = length > 20 ? 20 : length;
        for (int i = 0; i < print_length; i++) {
            printf("%02x", packet[i]);
        }
    }
    else {
        printf("No data");
    }
    printf("\n");
}
int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;

        struct libnet_ethernet_hdr* ethernet = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) continue;
        if (ip->ip_p != IPPROTO_TCP) continue;

        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet + sizeof(const struct libnet_ipv4_hdr) + sizeof(const struct libnet_ethernet_hdr));
        const u_char* data = (packet + sizeof(const struct libnet_tcp_hdr) + sizeof(const struct libnet_ipv4_hdr) + sizeof(const struct libnet_ethernet_hdr));
        int data_length = header->caplen - (sizeof(struct libnet_ethernet_hdr) + ip->ip_hl * 4 + tcp->th_off * 4);

        Ethernet_Mac(ethernet);
        IP_Addr(ip);
        TCP_Port(tcp);
        DATA(data, data_length);
    }
    pcap_close(pcap);
}


