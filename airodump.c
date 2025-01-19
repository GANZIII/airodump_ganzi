#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_NETWORKS 256
#define ESSID_MAX_LEN 100

struct ieee80211_radiotap_header {
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
} __attribute__((__packed__));

struct BEACON_FRAME {
    u_int8_t frame_type[2];
    u_int16_t duration_id;
    u_int8_t destination_mac[6];
    u_int8_t source_mac[6];
    u_int8_t bssid[6];
    u_int16_t sequence_ctr;
} __attribute__((__packed__));


typedef struct {
    u_int8_t bssid[6];
    int beacons;
    char essid[ESSID_MAX_LEN];
} Network;

Network networks[MAX_NETWORKS];
int network_count = 0;

char* dev;

// 사용법 출력
void usage(void)
{
	printf("syntax : airodump <interface>\n");
}

// 입력 인자 파싱
bool parse(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return 0;
    }
    dev = argv[1];
    return 1;
}

// 네트워크 리스트 출력
void print_networks() {
    system("clear");
    printf("BSSID                  Beacons  ESSID\n");
    for (int i = 0; i < network_count; i++) {
        printf("%02X:%02X:%02X:%02X:%02X:%02X  %8d  %s\n",
               networks[i].bssid[0], networks[i].bssid[1], networks[i].bssid[2],
               networks[i].bssid[3], networks[i].bssid[4], networks[i].bssid[5],
               networks[i].beacons, networks[i].essid);
    }
}

// BSSID 비교 함수
bool compare_bssid(u_int8_t* bssid1, u_int8_t* bssid2) {
    return memcmp(bssid1, bssid2, 6) == 0;
}

// 네트워크 추가 또는 업데이트
void add_or_update_network(u_int8_t* bssid, const char* essid) {
    for (int i = 0; i < network_count; i++) {
        if (compare_bssid(networks[i].bssid, bssid)) {
            networks[i].beacons++;
            return;
        }
    }

    // 새 네트워크 추가
    if (network_count < MAX_NETWORKS) {
        memcpy(networks[network_count].bssid, bssid, 6);
        strncpy(networks[network_count].essid, essid, ESSID_MAX_LEN - 1);
        networks[network_count].essid[ESSID_MAX_LEN - 1] = '\0';
        networks[network_count].beacons = 1;
        network_count++;
    }
}

// 패킷 분석
void parse_packet(const u_char* packet, int caplen) {
    struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*)packet;
    struct BEACON_FRAME* beacon = (struct BEACON_FRAME*)(packet + radiotap->it_len);

    // Beacon Frame이 아닌 경우 무시
    if (beacon->frame_type[0] != 0x80)
        return;

    u_int8_t* bssid = beacon->bssid;

    // ESSID 추출
    int idx = radiotap->it_len + sizeof(struct BEACON_FRAME) + 12;
    char essid[ESSID_MAX_LEN] = "Hidden";

    while (idx < caplen) {
        int tag_num = packet[idx];
        int tag_len = packet[idx + 1];
        if (tag_num == 0) { // ESSID 태그
            if (tag_len > 0 && tag_len < ESSID_MAX_LEN) {
                memcpy(essid, &packet[idx + 2], tag_len);
                essid[tag_len] = '\0';
            }
            break;
        }
        idx += tag_len + 2;
    }

    add_or_update_network(bssid, essid);
    print_networks();
}

int main(int argc, char* argv[]) {
    if (parse(argc, argv) == 0)
        return (1);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) fails: %s\n", dev, errbuf);
        return (1);
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex fails: %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        parse_packet(packet, header->caplen);
    }

    pcap_close(pcap);
    return 0;
}


