# PCAP TCP Packet Sniffer

이 프로그램은 C언어 기반의 libpcap API를 사용하여 TCP 패킷을 분석하고 출력합니다.

## 기능

- Ethernet Header 출력 (Source/Destination MAC)
- IP Header 출력 (Source/Destination IP)
- TCP Header 출력 (Source/Destination Port)
- TCP Payload 메시지 최대 64바이트까지 출력

## 파일 구조

```
WHS3_PCAP/
├── pcap_sniffer.c     # MAIN 코드
├── myheader.h       # 구조체 정의 헤더 파일
```

## 실행 방법

```bash
gcc pcap_sniffer.c -o pcap_sniffer -lpcap
sudo ./pcap_sniffer
```
