#include <pcap.h>
#include <stdbool.h>
#include <cstdint>
#include <map>
#include <iostream>
#include <string>
#include <mutex>

#define Beacon 128 //define: int (0x80=128)

using namespace std;
map<string, int> beacon_num;
map<string, int> id_to_row;
string ssid_key;
mutex cout_mutex;
int current_row =1;

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

struct rtapdata {
    uint8_t  antsignal;
    uint16_t tx_attenuation;
    uint8_t  flags;
    uint16_t rx_flags;
};
struct Mac{
	uint8_t mac[6];
};

struct beacon {
	uint16_t subtype; //2byte
	uint16_t zero; //2byte
	struct Mac macs[3]; //18byte
	uint16_t Sequence_Num; //2byte
};

const u_char* tag(const u_char* location){
	int len = (int)(location[1]);
	if(location[0] == 0x00 && len > 0){
        	uint8_t ssid[len];
        	for (int i = 0; i < len; i++) ssid[i] = location[2 + i];
		
		ssid_key = string(reinterpret_cast<char*>(ssid), len);
		
		if(beacon_num.find(ssid_key) != beacon_num.end()){
			beacon_num[ssid_key] += 1;
		} else {
			beacon_num[ssid_key] = 1;
		}
		cout << "SSID: " << ssid_key << "Beacon: " << beacon_num[ssid_key] << "\n";
	}
	return (location + 2 + len);
}

void UpdateBeaconMsg(uint8_t* bssid, string& ssid, int beacon_num){
	lock_guard<mutex> lock(cout_mutex);

	if(id_to_row.find(ssid) == id_to_row.end()){
		id_to_row[ssid] = current_row++;
	}

	int row = id_to_row[ssid];

	cout << "\033[" << row << ";1H";
	cout << "\033[2K";
	cout << "[BSIID] ";
	for(int i=0; i<6;i++) cout <<  hex << (int)bssid[i];
	cout << dec;
	cout << " [Beacon] " << beacon_num << " [#Data] 0 " << " [SSID] " << ssid << flush; 
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
		struct pcap_pkthdr* header;
        	const u_char* packet;
        	int res = pcap_next_ex(pcap, &header, &packet);
        	if (res == 0) continue;

		struct rtapdata* rtap = (struct rtapdata*)packet;
		struct beacon* beacon = (struct beacon*)(packet+(rtap->tx_attenuation));
		if(beacon->subtype == Beacon) {
			//printf("length: %02x ", rtap->tx_attenuation);
			//printf("subtype: %02x ", beacon->subtype);
			//printf("zero : %02x ", beacon->zero);
			printf("BSSID: ");
			for(int i=0; i<6; i++){
				bssid[i] = beacon->macs[1].mac[i];
				printf("%02x", beacon->macs[1].mac[i]);
			}/*
			printf(" ");
			printf("Sequence Number: %02x", beacon->Sequence_Num);
		
    			printf("\n");*/
		}

		int count =0;
		const u_char* wm_start = packet + (rtap->tx_attenuation)+sizeof(struct beacon) + 12;
		int remaining_length = header->caplen - (wm_start - packet);
		while(remaining_length > 4){
			wm_start = tag(wm_start);
			remaining_length = header->caplen - (wm_start - packet);
			//printf("remaining length : %d\n", remaining_length);
		}

		//UpdateBeaconMsg(bssid, ssid_key, beacon_num[ssid_key]);
	}
	return 0;
}
