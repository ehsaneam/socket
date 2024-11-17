#include "server.h"

int sockfd = 0;
int verbose = DBG_ERROR;
int packet_cntr = 0;

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

    initServer();
    receivePackets();
    closeServer();

    return 0;
}

void receivePackets()
{
    // char all_content[40*ETH_FRAME_LEN];
    char buffer[ETH_FRAME_LEN];
    char compressed_buffer[ETH_FRAME_LEN];

    // FILE *fptr;
    // fptr = fopen("/home/esi/Projects/RoHC_hardware/rohc_compress/resources/outputs", "r");
    // fseek(fptr, 0, SEEK_END); // seek to end of file
    // int all_content_size = ftell(fptr); // get current file pointer
    // int seeker = 0;
    // fseek(fptr, 0, SEEK_SET);
    // fread(all_content, 1, all_content_size, fptr);
    
    // if( fptr==NULL )
	// {
	// 	PRINT_ERR_SOCK("***********************--->file nis\n");
	// 	return;
	// }

    while( true )
    {
        // printf("%d\n", seeker);
        int bytes_compressed = receiveRaw(compressed_buffer, sizeof(compressed_buffer));
        // char *end_of_packet = find_str(all_content + seeker, "Hello, Server!", all_content_size-seeker);
        // if( end_of_packet== NULL || all_content_size<=seeker )
        // {
            // printf("tamum shod\n");
            // break;
        // }
        // int bytes_compressed = (end_of_packet + 1) - (all_content + seeker);
        // memcpy(compressed_buffer, all_content + seeker, bytes_compressed);
        // dumpPacket((unsigned char*)compressed_buffer+ETH_HDR_LEN, 
        //             bytes_compressed-ETH_HDR_LEN, "compressed buffer");
        // dumpPacket((unsigned char*)compressed_buffer, 
        //             bytes_compressed, "compressed buffer");

        PRINT_INFO_SOCK("--------------------\n");
        // Extract the Ethernet frame header
        // struct ether_header *eth_header = (struct ether_header *)buffer;
        // PRINT_INFO_SOCK("decompression started, bypass %ld bytes of eth-hdr\n", ETH_HDR_LEN);
        int bytes_read = decompressPacket((unsigned char*)compressed_buffer + ETH_HDR_LEN, 
                                        bytes_compressed - ETH_HDR_LEN,
                                        (unsigned char*)buffer);
        // int bytes_read = decompressPacket((unsigned char*)compressed_buffer, 
        //                                 bytes_compressed, (unsigned char*)buffer);
        // printf("%d\n", bytes_read);


        packet_cntr++;
        if( bytes_read==DECOMP_FAILED )
        {
            exit(EXIT_FAILURE);
        }
        else if( bytes_read<=0 )
        {
            continue;
        }
        // dumpPacket((unsigned char*)buffer, bytes_read, "buffer");

        // Extract the IP packet from the received Ethernet frame
        struct iphdr *ip_header = (struct iphdr*)buffer;
        unsigned short protocol = ip_header->protocol;
        int ip_header_length = ip_header->ihl * 4;

        if( !isValidProtocol(protocol) )
        {
            PRINT_WARN_SOCK("protocol not detected\n");
            continue;
        }

        if( protocol==IPPROTO_TCP )
        {
            extractTcp(buffer + ip_header_length,
                bytes_read - ip_header_length, ip_header);
        }
        else if( protocol==IPPROTO_UDP )
        {
            extractUdp(buffer + ip_header_length,
                bytes_read - ip_header_length, ip_header);
        }
        //seeker += bytes_compressed + 1;
    }
    //fclose(fptr);
}

void initServer()
{
    openSocket();
    PRINT_INFO_SOCK("socket opened\n");

    if( initDecompressor(ROHC_SMALL_CID)<0 )
    {
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    PRINT_INFO_SOCK("decompressor initiated\n");
}

void closeServer()
{
    close(sockfd);
    PRINT_INFO_SOCK("socket closed\n");
    
    releaseDecompressor();
    PRINT_INFO_SOCK("decompressor released\n");
}

void extractTcp(char *buffer, int len, struct iphdr *ip_header)
{
    // Extract the TCP header
    struct tcphdr *tcp_header = (struct tcphdr*)buffer;

    // Extract the source and destination ports
    unsigned short src_port = ntohs(tcp_header->src_port);
    unsigned short dst_port = ntohs(tcp_header->dst_port);

    if( isValidPort(src_port) || isValidPort(dst_port) )
    {
        // Calculate the TCP header length
        int tcp_header_length = tcp_header->data_offset * 4;

        // Extract the TCP payload
        char* tcp_payload = buffer + tcp_header_length;

        // Calculate the TCP payload length
        int tcp_payload_length = len - tcp_header_length;

        printf("%d) TCP Payload: %.*s | Src: %s:%d, Dest: %s:%d\n", 
            packet_cntr, tcp_payload_length, tcp_payload, 
            inet_ntoa(*(struct in_addr*)&(ip_header->saddr)), src_port,
            inet_ntoa(*(struct in_addr*)&(ip_header->daddr)), dst_port);
    }
}

void extractUdp(char *buffer, int bytes_read, struct iphdr *ip_header)
{
    // Extract the UDP header
    struct udphdr* udp_header = (struct udphdr*)buffer;

    // Extract the source and destination ports
    unsigned short src_port = ntohs(udp_header->source);
    unsigned short dst_port = ntohs(udp_header->dest);

    if( isValidPort(src_port) || isValidPort(dst_port) )
    {
        // Calculate the UDP header length
        int udp_header_length = sizeof(struct udphdr);

        // Extract the UDP payload
        char* udp_payload = buffer + udp_header_length;

        // Calculate the UDP payload length
        int udp_payload_length = bytes_read - udp_header_length;

        printf("%d) UDP Payload: %.*s | Src: %s:%d, Dest: %s:%d\n", 
            packet_cntr, udp_payload_length, udp_payload,
            inet_ntoa(*(struct in_addr*)&(ip_header->saddr)), src_port,
            inet_ntoa(*(struct in_addr*)&(ip_header->daddr)), dst_port);
    }
}

void openSocket()
{
    struct sockaddr_ll sa = {0};

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if( sockfd==-1 )
    {
        PRINT_ERR_SOCK("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up sockaddr_ll
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex(SOCKET_INTERFACE);

    // Bind socket to the interface
    if( bind(sockfd, (struct sockaddr*)&sa, sizeof(sa))==-1 )
    {
        PRINT_ERR_SOCK("Socket bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

int receiveRaw(char *buffer, int len)
{
    int bytes_read = recv(sockfd, buffer, len, 0);
    if( bytes_read==READ_SOCKET_FAILED )
    {
        PRINT_ERR_SOCK("Packet receive failed");
        closeServer();
        exit(EXIT_FAILURE);
    }
    return bytes_read;
}

void setVerbose(int verbose_level)
{
    setRohcVerbose(verbose_level);
    verbose = verbose_level;
}

char* find_str(char *phrase, char *word, int total_size)
{
    int word_size = strlen(word);
    int match_num = 0;
    for( int i=0 ; i<total_size ; i++ )
    {
        if( phrase[i]==word[match_num] )
        {
            match_num++;
            if( match_num==word_size )
            {
                return (phrase + i);
            }
        }
        else
        {
            match_num = 0;
        }
    }
    return NULL;
}
