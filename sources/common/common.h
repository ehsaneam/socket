#ifndef __COMMON_H__
#define __COMMON_H__

#include <time.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "tcp.h"
#include "udp.h"

#define DBG_INFO        3
#define DBG_WARNING     2
#define DBG_ERROR       1

#define BUFFER_SIZE     2048

#define SOCKET_PORT         12345

#define DEST_MAC_ADDR       "\x70\x4D\x7B\x63\x2F\x8D"  // Destination MAC address
#define SRC_MAC_ADDR        "\x00\x0A\x35\x00\x00\x00"  // Source MAC address
#define DEST_IP_ADDR        "192.168.75.204"                           // Destination IP address
#define SRC_IP_ADDR         "192.168.75.194"                           // Source IP address
#define IP_HDR_LEN              sizeof(struct iphdr)
#define TCP_HDR_LEN             sizeof(struct tcphdr)
#define UDP_HDR_LEN             sizeof(struct udphdr)

#define RANDOM_PACKETS  0
#define DUMP_PACKETS    1

#define PACK_FILE_FIELDS 8

#define ETH_HDR_LEN     sizeof(struct ether_header)

void dumpPacket(unsigned char *buffer, int len, const char *prompt);

unsigned int if_nametoindex(const char *ifname);

int isValidProtocol(int protocol);
int isValidPort(int port);

int getRandPort();
int getRandVersion();
int getRandProtocol();
int getRandBlock();
int getRandSeq();

const char* versionToString(int version);
int toVersion(char *str);
const char* protocolToString(int protocol);
int toProtocol(char *str);
const char* stateToString(int blocked);
int toState(char *str);
const char* rsfFlagToString(int rsf);
int toRsfFlag(char *str);

int openPackFile(const char *path);
int readLinePack(char *line, char (*fields)[256]);
void closePackFile();

#endif //__COMMON_H__
