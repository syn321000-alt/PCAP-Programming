# PCAP-Programming

# TCP Packet Sniffer

PCAP API를 이용해 TCP 패킷의 Ethernet/IP/TCP 헤더와 HTTP 메시지(페이로드)를 출력하는 프로그램입니다.

## 환경
- Ubuntu, gcc, libpcap

## 빌드
gcc -o tcp_sniff tcp_sniff.c -lpcap

## 실행
sudo ./tcp_sniff

## 주요 구현
- BPF 필터: "tcp" 로 TCP 패킷만 캡처 (UDP 제외)
- IP 헤더 길이: ip->iph_ihl * 4 로 계산 (가변 길이 옵션 대응)
- TCP 헤더 길이: TH_OFF(tcp) * 4 로 계산 (가변 길이 옵션 대응)
- 위 두 길이를 이용해 HTTP 메시지(Application 계층 페이로드)의 시작 위치와 길이를 정확히 계산하여 출력
