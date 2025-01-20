#include <pcap.h>
#include <stdbool.h>
#include <cstdint>
#include <map>
#include <iostream>
#include <string>
#include <iomanip>
#include <cstring> // For memcpy
#include <cstdlib>

#define Beacon 128 //define: int (0x80=128)

using namespace std;
int channel;

void usage() {
    printf("syntax: beacon <interface>\n");
    printf("sample: beacon mon0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {.dev_ = NULL};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

struct Mac {
    uint8_t mac[6];

    // operator< 정의 (std::map에서 사용 가능하도록)
    bool operator<(const Mac& other) const {
        return memcmp(mac, other.mac, 6) < 0;
    }
};

struct airodump {
    uint8_t bssid[6];
    string ssid;
    int beacon;
    int power;
    int channel;
};

map<Mac, airodump> bssid_map;

struct rtap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
};

struct beacon {
    uint16_t subtype; // 2 bytes
    uint16_t zero;    // 2 bytes
    struct Mac macs[3];
    uint16_t Sequence_Num; // 2 bytes
};

void print_packet(const u_char* packet, int length) {
    cout << "Packet length: " << length << " bytes" << endl;
    for (int i = 0; i < length; i++) {
        if (i % 16 == 0) cout << endl; 
        cout << hex << setw(2) << setfill('0') << (int)packet[i] << " ";
    }
    cout << dec << endl << endl;
}

// BSSID를 문자열로 변환
string mac_to_string(const Mac& mac) {
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < 6; i++) {
        ss << setw(2) << (int)mac.mac[i];
        if (i < 5) ss << ":";
    }
    return ss.str();
}

// 태그 파싱 함수
const u_char* tag(const u_char* location, const Mac& bssid, int power) {
    int len = (int)(location[1]);
    string ssid;
    if (location[0] == 0x00 && len > 0) {
        ssid = string(reinterpret_cast<const char*>(location + 2), len);
    } else {
        ssid = "<Hidden SSID>"; 
    }

    if (len > 0 && bssid_map.find(bssid) != bssid_map.end()) {
            bssid_map[bssid].beacon++;
	    bssid_map[bssid].power = power;
    } else {
            airodump new_entry = {};
            memcpy(new_entry.bssid, bssid.mac, 6);
            new_entry.beacon = 1;
            new_entry.ssid = ssid;
	    new_entry.power = power;
	    new_entry.channel = channel;
            bssid_map[bssid] = new_entry;
    }
    return location + 2 + len;
}

// 맵 데이터 출력
void UpdateBeaconMsg() {
    system("clear");
    cout << "BSSID              PWR  Beacons  ESSID" << endl;
    for (const auto& entry : bssid_map) {
        const Mac& mac = entry.first;
        const airodump& data = entry.second;

        cout << mac_to_string(mac) << "  ";
        cout << setw(4) << data.power << "  ";
        cout << setw(7) << data.beacon << "  ";
        cout << data.ssid<< endl ;
	//cout << setw(2) << channel <<"  " << "\n";
    }
}

int GetAntennaSignal(uint32_t present, const u_char* fields) { 
    int count = 0;
    //print_packet(fields, 20);
    if (present & (1 << 0)) count += 8; // MAC TSFT
    if (present & (1 << 1)) count += 1; // Flags
    if (present & (1 << 2)) count += 1; // Rate
    if (present & (1 << 3)) {
	//count += 2; // Channel
	int16_t frequency = *(uint16_t*)(fields+count);
	if(frequency >= 2412 && frequency <=2472) channel = (frequency-2407)/5;
	else channel = -1;
	count += 4;
    }
    if (present & (1 << 4)) count += 2; // FHSS
    if (present & (1 << 5)) count += 0; // Antenna signal

    return static_cast<int8_t>(*(fields + count));
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

        struct rtap_header* rtap_h = (struct rtap_header*)packet;
	uint32_t it_present = rtap_h->present;
	int rtap_len = sizeof(struct rtap_header);

	while (it_present & (1 << 31)) { //present 3개 더한 위치 값 구하기
            it_present = *(uint32_t*)(packet + rtap_len);
            rtap_len += sizeof(uint32_t);
        }
	const u_char* fields = packet + rtap_len;
        
	struct beacon* beacon_frame = (struct beacon*)(packet + (rtap_h->len));
        if (beacon_frame->subtype == Beacon) {
            const Mac& bssid = beacon_frame->macs[1];
            int power = GetAntennaSignal(rtap_h->present, fields);

        const u_char* wm_start = packet + (rtap_h->len) + sizeof(struct beacon) + 12;
        int remaining_length = header->caplen - (wm_start - packet);
        while (remaining_length > 4) {
                wm_start = tag(wm_start, bssid, power);
                remaining_length = header->caplen - (wm_start - packet);
            }
        }

        UpdateBeaconMsg();
    }

    pcap_close(pcap);
    return 0;
}
