#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) != 0x0800) return; // IP가 아니면 무시

  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

  if (ip->iph_protocol != IPPROTO_TCP) return; // TCP만 처리

  int ip_header_len = ip->iph_ihl * 4; // IP 헤더 실제 길이 (가변)

  struct tcpheader *tcp = (struct tcpheader *)
                          ((u_char *)ip + ip_header_len);

  int tcp_header_len = TH_OFF(tcp) * 4; // TCP 헤더 실제 길이 (가변)

  // HTTP 메시지(페이로드) 시작 위치
  u_char *payload = (u_char *)tcp + tcp_header_len;

  // 전체 IP 패킷 길이 - IP헤더 - TCP헤더 = 페이로드 길이
  int ip_total_len = ntohs(ip->iph_len);
  int payload_len = ip_total_len - ip_header_len - tcp_header_len;

  printf("=====================================================\n");

  // Ethernet 헤더 출력
  printf("Ethernet Header\n");
  printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
         eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
         eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

  // IP 헤더 출력
  printf("IP Header\n");
  printf("   Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
  printf("   Dst IP: %s\n", inet_ntoa(ip->iph_destip));
  printf("   Header Len: %d bytes\n", ip_header_len);

  // TCP 헤더 출력
  printf("TCP Header\n");
  printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
  printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));
  printf("   Header Len: %d bytes\n", tcp_header_len);

  // HTTP 메시지(애플리케이션 데이터) 출력
  if (payload_len > 0) {
    printf("HTTP Message (%d bytes)\n", payload_len);
    for (int i = 0; i < payload_len; i++) {
      if (isprint(payload[i]) || payload[i] == '\n' || payload[i] == '\r')
        putchar(payload[i]);
      else
        putchar('.');
    }
    printf("\n");
  } else {
    printf("HTTP Message: (no payload)\n");
  }

  printf("=====================================================\n\n");
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net = 0;

  // Step 1: NIC에서 라이브 캡처 시작 (인터페이스 이름은 환경에 맞게 수정)
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  // Step 2: 필터 컴파일 및 적용 (TCP만)
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    pcap_perror(handle, "Compile error:");
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &fp) != 0) {
    pcap_perror(handle, "Setfilter error:");
    exit(EXIT_FAILURE);
  }

  // Step 3: 패킷 캡처 루프
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);
  return 0;
}