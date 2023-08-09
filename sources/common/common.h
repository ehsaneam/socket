#ifndef __COMMON_H__
#define __COMMON_H__

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define SOCKET_INTERFACE    "lo"
#define SOCKET_PORT         12345
#define DBG_INFO        3
#define DBG_WARNING     2
#define DBG_ERROR       1

#define RANDOM_PACKETS  0
#define DUMP_PACKETS    1

#define ETH_HDR_LEN     sizeof(struct ether_header)

void dumpPacket(unsigned char *buffer, int len, const char *prompt);

unsigned int if_nametoindex(const char *ifname);

int isValidProtocol(int protocol);
int isValidPort(int port);

int getRandPort();
int getRandVersion();
int getRandProtocol();
int getRandBlock();

const char* versionToString(int version);
int toVersion(char *str);
const char* protocolToString(int protocol);
int toProtocol(char *str);
const char* stateToString(int blocked);
int toState(char *str);

int openPackFile(const char *path);
int readLinePack(char *line, char (*fields)[256]);
void closePackFile();

#endif //__COMMON_H__