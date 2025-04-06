#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include "myheader.h"

#define MAX_PAYLOAD 64  // 최대 출력할 페이로드 길이

// MAC 주소를 보기 좋게 출력하는 함수
void print_mac_address(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 페이로드 데이터를 출력하는 함수
void print_payload(const u_char *payload, int len) {
    int display_len = len < MAX_PAYLOAD ? len : MAX_PAYLOAD;
    if (display_len <= 0) {
        printf("  [No Payload Data]\n");
        return;
    }
    printf("  Payload (%d bytes):\n  ", display_len);
    for (int i = 0; i < display_len; i++) {
        printf("%c", isprint(payload[i]) ? payload[i] : '.');
    }
    if (len > MAX_PAYLOAD)
        printf("... (%d more bytes)\n", len - MAX_PAYLOAD);
    printf("\n");
}

// 캡처된 패킷을 처리하는 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 이더넷 헤더 파싱
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != 0x0800) return;  // IP 패킷이 아니면 리턴

    // IP 헤더 파싱
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip->iph_protocol != IPPROTO_TCP) return;  // TCP가 아니면 리턴

    // IP, TCP 헤더 길이 계산
    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    // 페이로드 위치 및 길이 계산
    int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - payload_offset;
    const u_char *payload = packet + payload_offset;

    // 출력 시작
    printf("\n===== Captured TCP Packet =====\n");

    // 이더넷 정보 출력
    printf("[Ethernet Header]\n");
    printf("  Src MAC: "); print_mac_address(eth->ether_shost); printf("\n");
    printf("  Dst MAC: "); print_mac_address(eth->ether_dhost); printf("\n");

    // IP 정보 출력
    printf("[IP Header]\n");
    printf("  Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    // TCP 정보 출력
    printf("[TCP Header]\n");
    printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

    // 페이로드 출력
    if (payload_len > 0) {
        print_payload(payload, payload_len);
    } else {
        printf("  [No Payload Data]\n");
    }
}

int main() {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 사용 가능한 네트워크 장치 목록 가져오기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // 첫 번째 장치를 기본 장치로 사용
    device = alldevs;
    if (device == NULL) {
        fprintf(stderr, "No available network device found.\n");
        return 1;
    }

    char *dev = device->name;
    printf("Using device: %s\n", dev);

    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP 패킷만 필터링
    bpf_u_int32 net = 0;

    // 장치에서 라이브 캡처 세션 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // 필터 적용 (tcp만 수집)
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't apply filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    // 패킷 캡처 시작
    pcap_loop(handle, -1, got_packet, NULL);

    // 자원 정리
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}