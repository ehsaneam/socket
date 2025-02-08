#include "client.h"

int sockfd;
struct sockaddr_ll sa = {0};
int verbose = DBG_ERROR;
int packet_generation_model = DUMP_PACKETS;

#define PRINT_ERR_SOCK(fmt, ...) \
    if( verbose>=DBG_ERROR ) \
        perror("[SOCKET] [ERROR] " fmt, ##__VA_ARGS__)

#define PRINT_WARN_SOCK(fmt, ...) \
    if( verbose>=DBG_WARNING ) \
        printf("[SOCKET] [WARNING] " fmt, ##__VA_ARGS__)

#define PRINT_INFO_SOCK(fmt, ...) \
    if( verbose>=DBG_INFO ) \
        printf("[SOCKET] [INFO] " fmt, ##__VA_ARGS__)

int main(int argc, char *argv[])
{
    if( argc>2 )
    {
        if( !strcmp(argv[1], "-v") )
        {
            int verbose_level = atoi(argv[2]);
            setVerbose(verbose_level);
        }
    }

    srand(time(NULL));
    Sc_packetSpec *packet_spec = (Sc_packetSpec *)malloc(sizeof(Sc_packetSpec));

    initClient();
    for( int i=0 ; i<40 ; i++ )
    {
        generatePacket(packet_spec);
        // printPacket(packet_spec, i);
        sendPacket(packet_spec);
        usleep(20);
    }
    free(packet_spec);
    closeClient();

    return 0;
}

void sendPacket(Sc_packetSpec *packet_spec)
{
    int payload_size = strlen(packet_spec->payload);
    if( payload_size==0 || !isValidProtocol(packet_spec->protocol) )
    {
        PRINT_ERR_SOCK("protocol is not supported\n");
        closeClient();
        exit(EXIT_FAILURE);
    }
    char buffer[ETH_FRAME_LEN];
    char compressed_buffer[ETH_FRAME_LEN];

    // Construct Ethernet frame
    constructEthHeader(buffer);
    constructEthHeader(compressed_buffer);
    int total_packet_len = ETH_HDR_LEN;

    // Construct IP packet
    constructIpHeader(buffer + ETH_HDR_LEN, packet_spec);
    total_packet_len += IP_HDR_LEN;

    // Construct transport layer packet (TCP or UDP)
    if( packet_spec->protocol==IPPROTO_TCP )
    {
        constructTcpHeader(buffer + total_packet_len, packet_spec);
        total_packet_len += TCP_HDR_LEN;
    }
    else if( packet_spec->protocol==IPPROTO_UDP )
    {
        constructUdpHeader(buffer + total_packet_len, packet_spec);
        total_packet_len += UDP_HDR_LEN;
    }
    total_packet_len += payload_size;
    PRINT_INFO_SOCK("\n--------------------\n");
    PRINT_INFO_SOCK("INFO: packet created\n");
    // compDecompTest2((unsigned char*)buffer + ETH_HDR_LEN,
    //                 total_packet_len - ETH_HDR_LEN);

    int comp_ret = compressPacket((unsigned char*)buffer + ETH_HDR_LEN,
                                total_packet_len - ETH_HDR_LEN,
                                (unsigned char*)compressed_buffer + ETH_HDR_LEN);
    
    // dumpPacket((unsigned char*)buffer+ETH_HDR_LEN, total_packet_len-ETH_HDR_LEN, "buffer");
    // dumpPacket((unsigned char*)compressed_buffer+ETH_HDR_LEN, comp_ret, "compressed buffer");
    // printf("packet compressed, %d -> %ld\n", 
    //         total_packet_len, comp_ret+ETH_HDR_LEN);

    // printf("%d,%ld\n", total_packet_len, comp_ret+ETH_HDR_LEN);

    total_packet_len = comp_ret+ETH_HDR_LEN;
    if( !packet_spec->blocked )
    {
        if( sendto(sockfd, compressed_buffer, total_packet_len, 0,
            (struct sockaddr*)&sa, sizeof(struct sockaddr_ll))==-1 )
        {
            PRINT_ERR_SOCK("compressed packet send failed");
            closeClient();
            exit(EXIT_FAILURE);
        }
        PRINT_INFO_SOCK("compressed packet sent\n");
    }
}

void initClient()
{
    openSocket();
    PRINT_INFO_SOCK("socket opened\n");

    if( initCompressor(ROHC_SMALL_CID)<0 )
    {
        closeClient();
        exit(EXIT_FAILURE);
    }
    PRINT_INFO_SOCK("compressor initiated\n");

    if( packet_generation_model==DUMP_PACKETS )
    {
        int ret_open = openPackFile("../resources/dump_packet.csv");
        if( ret_open<0 )
        {
            PRINT_ERR_SOCK("Failed to open dump packet file.\n");
            closeClient();
            exit(EXIT_FAILURE);
        }
        PRINT_INFO_SOCK("dump packet file opened\n");
    }
}

void closeClient()
{
    close(sockfd);
    PRINT_INFO_SOCK("socket closed\n");
    releaseCompressor();
    PRINT_INFO_SOCK("compressor released\n");
    closePackFile();
    PRINT_INFO_SOCK("dump packet file closed\n");
}

struct udphdr* constructUdpHeader(char *buffer, Sc_packetSpec *packet_spec)
{
    struct udphdr *udp_header = (struct udphdr*)(buffer);
    int payload_size = strlen(packet_spec->payload);
    udp_header->source = htons(packet_spec->port);      // Source port
    udp_header->dest = htons(packet_spec->port);   // Destination port
    udp_header->len = htons(UDP_HDR_LEN + payload_size);
    udp_header->check = 0;

    // Copy payload to UDP packet
    memcpy(buffer + UDP_HDR_LEN, packet_spec->payload, payload_size);
    return udp_header;
}

struct tcphdr* constructTcpHeader(char *buffer, Sc_packetSpec *packet_spec)
{
    int payload_size = strlen(packet_spec->payload);

    struct tcphdr *tcp_header = (struct tcphdr*)(buffer);
    tcp_header->src_port = htons(packet_spec->port);      // Source port
    tcp_header->dst_port = htons(packet_spec->port);   // Destination port
    tcp_header->seq_num = htonl(packet_spec->seq);
    tcp_header->ack_num = htonl(packet_spec->ack_seq);
    tcp_header->data_offset = 5;
    tcp_header->res_flags = 0;
    tcp_header->rsf_flags = htons(packet_spec->rsf_flag);
    // tcp_header->fin = 0;
    // tcp_header->syn = 1;
    // tcp_header->rst = 0;
    tcp_header->psh_flag = 0;
    tcp_header->ack_flag = htons(packet_spec->ack_flag);
    tcp_header->urg_flag = 0;
    tcp_header->ecn_flags = 0;
    tcp_header->window = htons(65535);
    tcp_header->checksum = 0;
    tcp_header->urg_ptr = 0;

    memcpy(buffer + TCP_HDR_LEN, packet_spec->payload, payload_size);

    tcp_header->checksum = calculateTcpCksum(tcp_header, payload_size);

    // dumpPacket((unsigned char*)buffer, TCP_HDR_LEN, "SAGTUT");

    return tcp_header;
}

struct iphdr* constructIpHeader(char *buffer, Sc_packetSpec *packet_spec)
{
    struct iphdr *ip_header = (struct iphdr*)(buffer);
    int payload_size = strlen(packet_spec->payload);
    ip_header->ihl = 5;
    ip_header->version = packet_spec->version;
    ip_header->tos = 0;
    ip_header->protocol = packet_spec->protocol;
    if( packet_spec->protocol==IPPROTO_TCP )
    {
        ip_header->tot_len = htons(IP_HDR_LEN + TCP_HDR_LEN + payload_size);
    }
    else if( packet_spec->protocol==IPPROTO_UDP )
    {
        ip_header->tot_len = htons(IP_HDR_LEN + UDP_HDR_LEN + payload_size);
    }
    ip_header->id = htons(packet_spec->port);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(SRC_IP_ADDR);
    ip_header->daddr = inet_addr(DEST_IP_ADDR);

    // Calculate IP checksum
    ip_header->check = ip_fast_csum((uint8_t*)ip_header, 
                            IP_HDR_LEN/sizeof(uint32_t));
    return ip_header;
}

struct ether_header* constructEthHeader(char *buffer)
{
    struct ether_header *eth_header = (struct ether_header*)buffer;
    memcpy(eth_header->ether_dhost, DEST_MAC_ADDR, 6);
    memcpy(eth_header->ether_shost, SRC_MAC_ADDR, 6);
    eth_header->ether_type = htons(ETH_P_IP);
    return eth_header;
}

void openSocket()
{
    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if( sockfd==-1 )
    {
        PRINT_ERR_SOCK("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up sockaddr_ll
    sa.sll_ifindex = if_nametoindex(SOCKET_CLIENT_INTERFACE);

    // Set destination MAC address
    memcpy(sa.sll_addr, DEST_MAC_ADDR, 6);
    sa.sll_halen = htons(6);
}

int calculateTcpCksum(struct tcphdr *tcp_header, int payload_size)
{
    // Calculate TCP checksum
    struct pseudo_header
    {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
        struct tcphdr tcp;
    }pseudo_header;

    pseudo_header.source_address = inet_addr(SRC_IP_ADDR);
    pseudo_header.dest_address = inet_addr(DEST_IP_ADDR);
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(TCP_HDR_LEN + payload_size);

    int pseudo_packet_size = sizeof(struct pseudo_header) + 
                        TCP_HDR_LEN + payload_size;
    char *pseudo_packet = malloc(pseudo_packet_size);
    memcpy(pseudo_packet, (char *)&pseudo_header, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp_header, 
                TCP_HDR_LEN + payload_size);

    int check_sum = htons(inCksum((unsigned short*)pseudo_packet, pseudo_packet_size));
    free(pseudo_packet);
    return check_sum;
}

int inCksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while( nleft>1 )
    {
        sum += *w++;
        nleft -= 2;
    }

    if( nleft==1 )
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

uint16_t ip_fast_csum(const uint8_t *const iph, const size_t ihl)
{
	const uint8_t *buff = iph;
	size_t len = ihl * 4;
	bool odd;
	size_t count;
	uint32_t result = 0;

	if(len == 0)
	{
		return ~result;
	}
	odd = 1 & (uintptr_t) buff;
	if(odd)
	{
#ifdef __LITTLE_ENDIAN
		result = *buff;
#else
		result += (*buff << 8);
#endif
		len--;
		buff++;
	}
	count = len >> 1; /* nr of 16-bit words.. */
	if(count)
	{
		if(2 & (uintptr_t) buff)
		{
			result += *(uint16_t *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1; /* nr of 32-bit words.. */
		if(count)
		{
			uint32_t carry = 0;
			do
			{
				uint32_t word = *(uint32_t *) buff;
				count--;
				buff += sizeof(uint32_t);
				result += carry;
				result += word;
				carry = (word > result);
			}
			while(count);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if(len & 2)
		{
			result += *(uint16_t *) buff;
			buff += 2;
		}
	}
	if(len & 1)
	{
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	}
	result = from32to16(result);
	if(odd)
	{
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
	return ~result;
}

	return (uint16_t) (sum & 0xffff);
}

void generatePacket(Sc_packetSpec *packet_spec)
{
    packet_spec->payload = "Hello, Server!";
    if( packet_generation_model==RANDOM_PACKETS )
    {
        packet_spec->protocol = getRandProtocol();
        packet_spec->version = getRandVersion();
        packet_spec->port = getRandPort();
        packet_spec->blocked = getRandBlock();
        packet_spec->seq = getRandSeq();
        packet_spec->ack_seq = getRandSeq();
        packet_spec->rsf_flag = 0;
        packet_spec->ack_flag = 0;
    }
    else if( packet_generation_model==DUMP_PACKETS )
    {
        char buffer[PACK_FILE_FIELDS][256];
        char line[1024];
        int ret = readLinePack(line, buffer);
        if( ret<0 )
        {
            PRINT_ERR_SOCK("Unexpected end of file.");
            closeClient();
            exit(EXIT_FAILURE);
        }
        else if( ret<PACK_FILE_FIELDS )
        {
            PRINT_ERR_SOCK("Not enough fields in row.");
            closeClient();
            exit(EXIT_FAILURE);
        }
        packet_spec->protocol = toProtocol(buffer[0]);
        packet_spec->version  = toVersion(buffer[1]);
        packet_spec->port     = atoi(buffer[2]);
        packet_spec->seq = atoi(buffer[3]);
        packet_spec->ack_seq = atoi(buffer[4]);
        packet_spec->rsf_flag = toRsfFlag(buffer[5]);
        packet_spec->ack_flag = atoi(buffer[6]);
        packet_spec->blocked  = toState(buffer[7]);
    }
}

void printPacket(Sc_packetSpec *packet_spec, int i)
{
    printf("%d,%s,%s,%d,%d,%d,%s,%d,\"%s\",%s,", 
            i, protocolToString(packet_spec->protocol), 
            versionToString(packet_spec->version), packet_spec->port, 
            packet_spec->seq, packet_spec->ack_seq,
            rsfFlagToString(packet_spec->rsf_flag), packet_spec->ack_flag,
            packet_spec->payload, stateToString(packet_spec->blocked));
    assert(packet_spec!=NULL);
    assert(i>=0);
}

void setVerbose(int verbose_level)
{
    verbose = verbose_level;
    setRohcVerbose(verbose_level);
}
