#include <pcap.h>
#include <stdbool.h>
#include <cstdint>
#include <map>
#include <iostream>
#include <string>
#include <iomanip>
#include <bitset>

#define Beacon 128 //define: int (0x80=128)

using namespace std;

struct Mac {
    uint8_t mac[6];
    bool operator<(const Mac& other) const {
        return memcmp(mac, other.mac, 6) < 0;
    }
};

struct airodump {
    uint8_t bssid[6];
    string ssid;
    int beacon;
    int power;
};

map<Mac,airodump> bssid_map;

void usage(){
    printf("syntax: beacon <interface>\n");
    printf("sample: beacon mon0\n");
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
struct rtap_header {
	uint8_t version;
	uint8_t pad;
	uint16_t len;
	uint32_t present;
};

struct rtapdata {
    uint8_t  antsignal;
    uint16_t tx_attenuation;
    uint8_t  flags;
    uint16_t rx_flags;
};

struct beacon {
	uint16_t subtype; //2byte
	uint16_t zero; //2byte
	struct Mac macs[3]; //18byte
	uint16_t Sequence_Num; //2byte
};

const u_char* tag(const u_char* location, const Mac* bssid){
	int len = (int)(location[1]);
	if(location[0] == 0x00 && len > 0){
        	uint8_t ssid[len];
        	for (int i = 0; i < len; i++) ssid[i] = location[2 + i];
		
		if(bssid_map.find(bssid) !=beacon_map.end()) {
			bssid_map[bssid].beacon++;
		} esle { 
			airodump new_entry = {};
			memcpy(new_entry.bssid, bssid.mac, 6);
			new_entry.beacon = 1;
			new_entry.ssid = ssid;
			bssid_map[bssid] = new_entry;
		}
	}
	return (location + 2 + len);
}
/*
void UpdateBeaconMsg(airodump* result){
	cout <<" BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID"<<"\n";
	cout <<" ";
	for(int i=0; i<6; i++) {
		cout << hex << setw(2) <<setfill('0') <<(int)result->bssid[i];
		if (i<5) cout << ":";
	}
	cout << "  ";
	cout << hex << result->power << "  ";
	cout << dec <<result->beacon;
	cout << result->ssid << "\n";
	
}*/
void UpdateBeaconMsg(const airodump* result) {
    cout << "BSSID              PWR  Beacons  ESSID" << endl;
    for (const auto& entry : bssid_map) {
        const Mac& mac = entry.first;
        const airodump& data = entry.second;

        cout << mac_to_string(mac) << "  ";
        cout << setw(4) << data.power << "  ";
        cout << setw(7) << data.beacon << "  ";
        cout << data.ssid << endl;
    }
}

int antenna (uint32_t present, const u_char* fields){
	int count = 0;
	
	if (present & (1 << 0)) count += 8; // MAC TSFT
	if (present & (1 << 1)) count += 1; // Flags
	if (present & (1 << 2)) count += 1; // Rate
	if (present & (1 << 3)) count += 4; // Channel
	if (present & (1 << 4)) count += 2; // FHSS
	if (present & (1 << 5)) count += 1; // Antenna signal
	cout << "offset" << count << endl;
	int8_t signal = *(fields + count);	
	return (static_cast<int>(signal));
}
int main(int argc, char* argv[]){
	if(!parse(&param, argc, argv))
		return -1;
	
	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    	if (pcap == NULL) {
        	fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        	return -1;
    	}

	uint8_t bssid[6];
	while(true){
		struct airodump result;
		struct pcap_pkthdr* header;
        	const u_char* packet;
        	int res = pcap_next_ex(pcap, &header, &packet);
        	if (res == 0) continue;

		struct rtap_header* rtap_h = (struct rtap_header*)packet;
		const u_char* fields = packet + rtap_h->len;

		struct beacon* beacon = (struct beacon*)(packet+(rtap_h->len));
		if(beacon->subtype == Beacon) {
			result.power = antenna(rtap_h->present, fields);
			//print_packet(packet, header->len);
			for(int i=0; i<6; i++){
				result.bssid[i] = beacon->macs[1].mac[i];
			}
		}

		int count =0;
		const u_char* wm_start = packet + (rtap_h->len)+sizeof(struct beacon) + 12;
		int remaining_length = header->caplen - (wm_start - packet);
		while(remaining_length > 4){
			wm_start = tag(wm_start,&result);
			remaining_length = header->caplen - (wm_start - packet);
		}

		UpdateBeaconMsg(&result);
	}
	return 0;
}
