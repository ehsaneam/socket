#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <string.h>
#include "common.h"
#include "header_comp.h"

#define DEST_MAC_ADDR       {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}  // Destination MAC address
#define SRC_MAC_ADDR        {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}  // Source MAC address
#define DEST_IP_ADDR        "127.0.0.1"                           // Destination IP address
#define SRC_IP_ADDR         "127.0.0.1"                           // Source IP address
#define IP_HDR_LEN              sizeof(struct iphdr)
#define TCP_HDR_LEN             sizeof(struct tcphdr)
#define UDP_HDR_LEN             sizeof(struct udphdr)

typedef struct Sc_packetSpec
{
    int protocol;
    int version;
    int port;
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