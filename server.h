#ifndef __SERVER_H__
#define __SERVER_H__

#include "common.h"
#include "header_comp.h"

#define READ_SOCKET_FAILED  -1

void receivePackets();
void initServer();
void closeServer();
int receiveRaw(char *buffer, int len);
void extractTcp(char *buffer, int bytes_read, struct iphdr *ip_header);
void extractUdp(char *buffer, int bytes_read, struct iphdr *ip_header);
void openSocket();
void setVerbose(int verbose_level);

#endif //__SERVER_H__