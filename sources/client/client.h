#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <string.h>
#include "common.h"
#include "header_comp.h"

#define SOCKET_CLIENT_INTERFACE    "eth1"

typedef struct Sc_packetSpec
{
    int protocol;
    int version;
    int port;
    int seq;
    int ack_seq;
    int rsf_flag;
    int ack_flag;
    int blocked;
    const char *payload;
}Sc_packetSpec;


void initClient();
void sendPacket(Sc_packetSpec *packet_spec);
void closeClient();
struct udphdr* constructUdpHeader(char *buffer, Sc_packetSpec *packet_spec);
struct tcphdr* constructTcpHeader(char *buffer, Sc_packetSpec *packet_spec);
struct iphdr* constructIpHeader(char *buffer, Sc_packetSpec *packet_spec);
struct ether_header* constructEthHeader(char *buffer);
void openSocket();
int calculateTcpCksum(struct tcphdr *tcp_header, int payload_size);
int inCksum(unsigned short *addr, int len);
uint16_t ip_fast_csum(const uint8_t *iph, const size_t ihl);
void generatePacket(Sc_packetSpec *packet_spec);
void printPacket(Sc_packetSpec *packet_spec, int i);
void setVerbose(int verbose_level);

#endif //__CLIENT_H__
