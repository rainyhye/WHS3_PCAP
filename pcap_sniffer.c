#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"  // Ethernet, IP, TCP 구조체 포함

#define MAX_PAYLOAD 64 // 출력할 최대 payload 길이

// MAC 주소를 보기 좋게
void print_mac(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 패킷 하나 처리하는 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) return; // IPv4 패킷만 처리

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip->iph_protocol != IPPROTO_TCP) return; // TCP 아니면 무시

    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    int total_header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - total_header_size;
    const u_char *payload = packet + total_header_size;

    printf("\n===== Captured TCP Packet =====\n");

    printf("[Ethernet Header]\n");
    printf("  Source MAC: "); print_mac(eth->ether_shost); printf("\n");
    printf("  Dest   MAC: "); print_mac(eth->ether_dhost); printf("\n");

    printf("[IP Header]\n");
    printf("  Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dest   IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("[TCP Header]\n");
    printf("  Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("  Dest   Port: %d\n", ntohs(tcp->tcp_dport));

    if (payload_len > 0) {
        printf("[Payload] (%d bytes)\n  ", payload_len);
        int max = (payload_len > MAX_PAYLOAD) ? MAX_PAYLOAD : payload_len;
        for (int i = 0; i < max; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
        if (payload_len > MAX_PAYLOAD)
            printf("... (%d more bytes not shown)\n", payload_len - MAX_PAYLOAD);
    }
}

// main 함수: 네트워크 캡처 시작
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";  // TCP 패킷만 
    bpf_u_int32 net = 0;

    // 사용할 네트워크 디바이스 자동 탐색
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    printf("Listening on device: %s\n", dev);

    // 캡처 세션 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // 필터 설정
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s\n", filter_exp);
        return 2;
    }

    // 패킷 캡처 루프 시작
    pcap_loop(handle, -1, got_packet, NULL);

    // 캡처 세션 닫기
    pcap_close(handle);
    return 0;
}

