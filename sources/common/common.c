#include "common.h"

int sc_protocols[] = {IPPROTO_TCP, IPPROTO_UDP};
int sc_ports[] = {12345, 54321, 11111, 33333};
int sc_rsf_flags[] = {0, 1, 2, 4};
int sc_versions[] = {4};
FILE *pack_file;

void dumpPacket(unsigned char *buffer, int len, const char *prompt)
{
    printf("-------------%s:%d------------\n", prompt, len);
    int i;
    for( i=0; i<len; i++ )
    {
        printf("0x%02x ", buffer[i]);
        if( i!=0 && ((i+1)%8)==0 )
        {
            printf("\n");
        }
    }
    if( i!=0 && (i%8)!=0 ) /* be sure to go to the line */
    {
        printf("\n");
    }
    printf("-------------%s:%d------------\n", prompt, len);
}

int getRandPort()
{
    int r = rand() % 4;
    return sc_ports[r];
}

int getRandVersion()
{
    int r = rand() % 1;
    return sc_versions[r];
}

int getRandProtocol()
{
    int r = rand() % 2;
    return sc_protocols[r];
}

int getRandBlock()
{
    int r = rand() % 100;
    return (r<1);
}

int getRandSeq()
{
    int r = rand() % (1<<16);
    return r;
}

const char* protocolToString(int protocol)
{
    switch( protocol ) 
    {
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_TCP:
            return "TCP";
        default:
            return "Unknown";
    }
}

const char* versionToString(int version)
{
    switch( version )
    {
        case 4:
            return "IPv4";
        default:
            return "Unknown";
    }
}

const char* stateToString(int blocked)
{
    switch( blocked )
    {
        case 0:
            return "SUCCEED";
        case 1:
            return "BLOCKED";
        default:
            return "Unknown";
    }
}

const char* rsfFlagToString(int rsf)
{
    switch(rsf)
    {
        case 1:
            return "FIN";
        case 2:
            return "SYN";
        case 4:
            return "RST";
        default:
            return "";
    }
}

int toProtocol(char *str)
{
    if( !strcmp(str, "UDP") )
    {
        return IPPROTO_UDP;
    }
    else if( !strcmp(str, "TCP") )
    {
        return IPPROTO_TCP;
    }
    else return -1;
}

int toVersion(char *str)
{
    if( !strcmp(str, "IPv4") )
    {
        return 4;
    }
    else
    {
        return -1;
    }
}

int toState(char *str)
{
    if( !strcmp(str, "SUCCEED") )
    {
        return 0;
    }
    else if( !strcmp(str, "BLOCKED") )
    {
        return 1;
    }
    else
    {
        return -1;
    }
}

int toRsfFlag(char *str)
{
    if( !strcmp(str, "FIN") )
    {
        return 1;
    }
    else if( !strcmp(str, "SYN") )
    {
        return 2;
    }
    else if( !strcmp(str, "RST") )
    {
        return 4;
    }
    else
    {
        return 0;
    }
}

int isValidPort(int port)
{
    int size = sizeof(sc_ports) / sizeof(int);
    for( int i=0 ; i<size ; i++)
    {
        if( port==sc_ports[i] )
        {
            return 1;
        }
    }
    return 0;
}

int isValidProtocol(int protocol)
{
    if( protocol==IPPROTO_TCP ||
        protocol==IPPROTO_UDP )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int openPackFile(const char *path)
{
    pack_file = fopen(path, "r");
    if( pack_file==NULL )
    {
        return -1;
    }
    return 0;
}

void closePackFile()
{
    if( pack_file!=NULL )
    {
        fclose(pack_file);
    }
}

int readLinePack(char *line, char (*fields)[256])
{
    char *field;
    char *pos;
    int fc = 0; // field counter

    if( fgets(line, 1024, pack_file)!=NULL )
    {
        field = strtok(line, ",");
        while( field!=NULL )
        {
            if( (pos=strchr(field, '\n'))!=NULL )
            {
                *pos = '\0';
            }
            strcpy(fields[fc], field);
            fc++;
            field = strtok(NULL, ",");
        }
        return fc;
    }
    return -1;
}