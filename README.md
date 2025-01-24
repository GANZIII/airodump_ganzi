# **report airodump**

Last edited by [**gilgil**](mailto:gilgil@gilgil.net) September 7, 2020 10:25 PM

### **과제**

airodump-ng와 비슷한 출력을 할 수 있는 프로그램을 작성하라.

### **실행**

`syntax : airodump <interface>
sample : airodump mon0`

### **상세**

- Beacon Frame에서 BSSID, Beacons, (#Data), (ENC), ESSID는 필수적으로 출력한다(괄호 항목은 선택).
- Beacon Frame에서 PWR 정보는 Radiotap Header에 있으며, Radiotap Header 분석은 [Radiotap](https://www.radiotap.org/) 사이트를 참고한다.
- Station은 기본적으로 AP와 연결되어 통신을 하지만 그렇지 않은 Frame(Probe Request)도 존재한다.
- 가능하다면 Channel Hopping 기능을 추가한다.
- [가상의 무선 네트워크 어댑터를 생성](https://gilgil.gitlab.io/2020/09/07/1.html) 기법을 이용하여 디버깅을 편하게 할 수도 있다.
- 필요한 경우 GitHub에 있는 [airodump-ng](https://github.com/aircrack-ng/aircrack-ng/tree/master/src/airodump-ng) 소스 코드를 참조한다.

---

# 헤더, 구조체

```c
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

```

- `ieee80211_radiotap_header`는 아래 사이트의 구조체와 동일하다.
- `radiotap` 헤더는 무선 패킷의 첫 번째 부분으로, 패킷의 메타 데이터를 제공한다.

https://www.radiotap.org/

- BEACON 구조체
    - 비콘 프레임은 802.11 무선 네트워크 관리 프레임으로, AP 정보 전송한다.
    - `frame_type`: 맥 헤더의 첫 2 바이트
        - 프레임 타입(관리 프레임, 데이터프레임 등)과 서브 타입(비콘, Probe Request 등)을 지정한다.
        - 비코 프레임은 `Type: 0(관리 프레임)` 과 `Subtype: 8(비콘 프레임)` 으로 식별된다.
    - `duration_id` : Duration/ID 필드
        - 네트워크 내에서 프레임 전송 예약 시간 표시
    - `destination_mac` : 도착지 맥주소
        - 비콘 프레임의 목적지 주소는 브로드캐스트 주소(FF:FF:FF:FF:FF:FF)로 설정된다.
    - `source_mac`: 출발지 맥주소
        - 비콘 프레임 전송하는 AP의 맥주소
    - `bssid`: BSSID
        - AP의 고유 식별자로, 일반적으로 AP의 맥주소와 동일
    - `sequence_ctr` : Sequence Control 필드
        - 프레임 순서 추적에 사용된다.
        - Fragmentation Number와 Sequence Number를 포함한다.

# 네트워크 구조체

```c
typedef struct {
    u_int8_t bssid[6];
    int beacons;
    char essid[ESSID_MAX_LEN];
} Network;

Network networks[MAX_NETWORKS];
int network_count = 0;
```

- `bssid`: 네트워크 고유 식별 MAC 주소
- `beacons`: AP에서 전송된 비콘 프레임의 수
- `essid`: 네트워크 이름
- 최대 256개의 네트워크를 저장하는 networks 배열을 사용해 네트워크 정보 관리

# main 함수

```c
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
```

- `parse`: 인터페이스 이름이 인자로 들어왔는지 확인
- `pcap_open_live`: 지정한 인터페이스에서 실시간 패킷 캡처
- `pcap_next_ex`: 캡처된 패킷 읽고, `parse_packet` 함수로 전달

# parse_packet

```c
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
```

- `radiotap`: 래디오탭 헤더 (무선 프레임 맨 앞에 위치)
- `beacon`: 래딩오탭 해더 바로 뒤에 비콘 프레임이 있다. (packet + radiotap→it_len)
- 비콘 프레임 여부 확인
    - `frame_ctr` 이 0x80으로 시작하면 비콘 프레임
    - 비콘 프레임이 아닐 시 반환
- BSSID 추출
    - beacon→bssid
- ESSID 파싱
    - ESSID는 비콘 프레임의 Tagged Parameters 섹션에 있다.
    - 12 바이트를 더하는 이유는, 12 바이트 만큼의 고정 필드(Timestamp, Beacon Interval, Capability Information)를 스킵하기 위해서이다.
    - `idx`는 래디오탭 헤더, 비콘 프레임, 고정 필드를 건너뛴 위치를 계산해 `Tagged Parameters` 섹션의 시작을 가리킨다.
    - 기본값: `HIDDEN`
- Tagged Parameters 루프
    - `Tagged Parameters`는 `tag_num`, `tag_len`, 데이터를 포함한다.
        
        ```c
        [Tag Number (1 byte)] [Tag Length (1 byte)] [Tag Data (N bytes)]
        ```
        
    - `tag_num` 이 0이면 ESSID 태그이다.
    - `tag_len`: ESSID 데이터 길이
    - ESSID 데이터를 `packet[idx+2]`에서 읽는다.
        - 2를 더하는 이유는, 2바이트(Tag Nunber, Tag Length)를 건너뛰기 위해서이다.
    - 따ꀀ서 `idx`도 teg_len + 2 로 갱신한다.
- 네트워크 리스트 업데이트 및 출력
    - `add_or_update_network`: 네트워크 리스트에 BSSID와 ESSID를 추가하거나, 이미 존재하면 비콘 값 증가시킨다.
    - `print_networks`: 네트워크 리스트 출력

# add_or_update_network

```c
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

```

- 기존 네트워크 업데이트
    - 배열에 이미 있는 네트워크라면 비콘 값 증가
- 새 네트워크 추가
    - 배열에 없으면 새 네트워크 정보 추가
    - `bssid`, `essid`, 초기 비콘 값 저장 (1)

# print_networks

```c
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
```

- `clear`로 화면 지우고 새로운 네트워크 정보 갱신
- BSSID(네트워크 맥주소), 비콘(비콘 프레임 수), ESSID(네트워크 이름) 출력

# 전체 코드

```c
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

```

# 의존성

```bash
sudo apt update
sudo apt install libpcap-dev
```
# 실행 예시

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/c3677699-221e-4815-8d4e-4b443d63f94c/21c176aa-a712-4dde-8c27-a59b31eeb171/image.png)

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/c3677699-221e-4815-8d4e-4b443d63f94c/f81f2b4b-8c0f-45fc-a759-2f8363efd141/image.png)

# 피드백

- `attribute` 는 C 표준 X. 리눅스 전용이므로 `pragma pack(push, 1)` 사용
- 배열 로 돌면 n(O) 이므로 map 활용
- + 12, +2 이런 부분은 코드 보기 편하게 sizeof(fixed)나 매크로 활용
- 네트워크 카운트 overflow 체크
