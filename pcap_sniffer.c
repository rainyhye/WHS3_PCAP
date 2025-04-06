#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include "myheader.h"

#define MAX_PAYLOAD 64  // 최대 출력할 페이로드 길이

// MAC 주소 출력
void print_mac_address(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 페이로드 출력
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
        printf("... (%d more bytes)", len - MAX_PAYLOAD);
    printf("\n");
}

// 패킷 캡처 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != 0x0800) return; // IP 패킷만 처리

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip->iph_protocol != IPPROTO_TCP) return; // TCP만 처리

    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - payload_offset;
    const u_char *payload = packet + payload_offset;

    printf("\n===== Captured TCP Packet =====\n");

    printf("[Ethernet Header]\n");
    printf("  Src MAC: "); print_mac_address(eth->ether_shost); printf("\n");
    printf("  Dst MAC: "); print_mac_address(eth->ether_dhost); printf("\n");

    printf("[IP Header]\n");
    printf("  Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("[TCP Header]\n");
    printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

    if (payload_len > 0) {
        print_payload(payload, payload_len);
    } else {
        printf("  [No Payload Data]\n");
    }
}

int main() {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, dev_index = 0;

    // 사용 가능한 네트워크 장치 목록 가져오기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // 장치 리스트 출력
    printf("Available Devices:\n");
    for (device = alldevs; device != NULL; device = device->next) {
        printf("[%d] %s\n", i++, device->name);
    }

    // 사용자 입력으로 장치 선택
    printf("Select device index: ");
    scanf("%d", &dev_index);

    device = alldevs;
    for (int j = 0; j < dev_index && device != NULL; j++) {
        device = device->next;
    }

    if (device == NULL) {
        fprintf(stderr, "Invalid device index.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    char *device_name = device->name;
    printf("Using device: %s\n", device_name);
    pcap_freealldevs(alldevs);  // 리스트 해제

    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    handle = pcap_open_live(device_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device_name, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't apply filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }

    printf("Listening for TCP packets... Press Ctrl+C to stop.\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}