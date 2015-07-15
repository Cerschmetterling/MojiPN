// Win Defines

#ifndef BASETYPES
#define BASETYPES
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
#endif  /* !BASETYPES */

typedef unsigned long       DWORD;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;


/*
	Paket size
*/
#define MAXBUF 65535

/*
	Regex to check if valid
*/
#define IPv4_REGEX  \b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b
#define IPv6_REGEX (([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))
#define MAC_REGEX /^([0-9a-f]{1,2}[\.:-]){5}([0-9a-f]{1,2})$/i

/*
	Header Type
*/
#define TYPE_UNKNOWN -1
#define TYPE_IP 0
#define TYPE_IPV6 1
#define TYPE_ARP 2
/*
	Protocol Number
*/
#define ICMP 1
#define IGMP 2
#define IPv4 4
#define TCP 6
#define UDP 17

/*
	Arp Modes
*/
#define ARP_REQUEST 1
#define ARP_REPLY 2



/*
	Packet Structs
	-ARP
	-IPv4
	-IPv6
	-ICMP
	-TCP
	-UDP
*/
typedef struct arp_hdr {
    uint16_t hardware_type;    /* Hardware Type           */
    uint16_t protocol_type;    /* Protocol Type           */
    unsigned char hardware_len;        /* Hardware Address Length */
    unsigned char protocol_len;        /* Protocol Address Length */
    uint16_t operation_code;     /* Operation Code          */
    unsigned char sender_hwaddress[6];      /* Sender hardware address */
    unsigned char sender_ipaddress[4];      /* Sender IP address       */
    unsigned char target_hwaddress[6];      /* Target hardware address */
    unsigned char target_ipaddress[4];      /* Target IP address       */
} ARP_HDR;


typedef struct ip_hdr
{
	unsigned char ip_header_len:4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version :4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset :5; // Fragment offset field

	unsigned char ip_more_fragment :1;
	unsigned char ip_dont_fragment :1;
	unsigned char ip_reserved_zero :1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;


typedef struct ipv6_hdr
{
    unsigned char version: 4;
    unsigned int traffic_class: 8;
    unsigned int flow_label: 20;
    unsigned int payload_length: 16;
    unsigned int next_header: 8;
    unsigned int hop_limit: 8;
    unsigned char source_addr[16];
    unsigned char dest_addr[16];
} IPV6_HDR;


typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1:3; //according to rfc
	unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin :1; //Finish Flag
	unsigned char syn :1; //Synchronise Flag
	unsigned char rst :1; //Reset Flag
	unsigned char psh :1; //Push Flag
	unsigned char ack :1; //Acknowledgement Flag
	unsigned char urg :1; //Urgent Flag

	unsigned char ecn :1; //ECN-Echo Flag
	unsigned char cwr :1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

typedef struct icmp_hdr
{
    unsigned char  type; // ICMP Error type
	unsigned char  code; // Type sub code
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
} ICMP_HDR;

/*
Functions
*/

void dump_arp(ARP_HDR* arp_hdr)
{
	uint16_t htype = ntohs(arp_hdr->hardware_type);
	uint16_t ptype = ntohs(arp_hdr->protocol_type);
	uint16_t oper = ntohs(arp_hdr->operation_code);
	switch (htype)
	{
	case 0x0001:
		printf("ARP HTYPE: Ethernet(0x%04X)\n", htype);
		break;
	default:
		printf("ARP HYPE: 0x%04X\n", htype);
		break;
	}
	switch (ptype)
	{
	case 0x0800:
		printf("ARP PTYPE: IPv4(0x%04X)\n", ptype);
		break;
	default:
		printf("ARP PTYPE: 0x%04X\n", ptype);
		break;
	}
	printf("ARP HLEN: %d\n", arp_hdr->hardware_len);
	printf("ARP PLEN: %d\n", arp_hdr->protocol_len);
	switch (oper)
	{
	case 0x0001:
		printf("ARP OPER: Request(0x%04X)\n", oper);
		break;
	case 0x0002:
		printf("ARP OPER: Response(0x%04X)\n", oper);
		break;
	default:
		printf("ARP OPER: 0x%04X\n", oper);
		break;
	}
	printf("ARP Sender HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
		arp_hdr->sender_hwaddress[0], arp_hdr->sender_hwaddress[1], arp_hdr->sender_hwaddress[2],
		arp_hdr->sender_hwaddress[3], arp_hdr->sender_hwaddress[4], arp_hdr->sender_hwaddress[5]);
	printf("ARP Sender PA: %d.%d.%d.%d\n", arp_hdr->sender_ipaddress[0],
		arp_hdr->sender_ipaddress[1], arp_hdr->sender_ipaddress[2], arp_hdr->sender_ipaddress[3]);
	printf("ARP Target HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
		arp_hdr->target_hwaddress[0], arp_hdr->target_hwaddress[1], arp_hdr->target_hwaddress[2],
		arp_hdr->target_hwaddress[3], arp_hdr->target_hwaddress[4], arp_hdr->target_hwaddress[5]);
	printf("ARP Target PA: %d.%d.%d.%d\n", arp_hdr->target_ipaddress[0],
		arp_hdr->target_ipaddress[1], arp_hdr->target_ipaddress[2], arp_hdr->target_ipaddress[3]);
	printf("ARP DONE =====================\n");
}
char* getMacFomated(unsigned char* mac)
{
	char* dest = new char[20];
		sprintf_s(dest, 20, "%02X-%02X-%02X-%02X-%02X-%02X",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		return dest;
}
void PrintData (char* data ,int start, int Size)
{
    char a , line[17] , c;
    int j;

    //loop over each character and print
    for(int i=start ; i < Size ; i++)
    {
        c = data[i];

        //Print the hex value for every character , with a space. Important to make unsigned
        printf(" %.2x", (unsigned char) c);

        //Add the character to data line. Important to make unsigned
        a = ( c >=32 && c <=128) ? (unsigned char) c : '.';

        line[i%16] = a;

        //if last character of a line , then print the line - 16 characters in 1 line
        if( (i!=0 && (i+1)%16==0) || i == Size - 1)
        {
            line[i%16 + 1] = '\0';

            //print a big gap of 10 characters between hex and characters
            printf("          ");

            //Print additional spaces for last lines which might be less than 16 characters in length
            for( j = strlen(line) ; j < 16; j++)
            {
                printf( "   ");
            }

            printf( "%s \n" , line);
        }
    }

    printf( "\n");
}

void printIpHeader(IPV4_HDR * iphdr)
{
	unsigned short iphdrlen;
	struct sockaddr_in source, dest;
	iphdrlen = iphdr->ip_header_len * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	printf("\n");
	printf("IP Header\n");
	printf(" |-IP Version : %d\n", (unsigned int)iphdr->ip_version);
	printf(" |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)iphdr->ip_header_len, ((unsigned int)(iphdrlen)));
	printf(" |-Type Of Service : %d\n", (unsigned int)iphdr->ip_tos);
	printf(" |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(iphdr->ip_total_length));
	printf(" |-Identification : %d\n", ntohs(iphdr->ip_id));
	printf(" |-Reserved ZERO Field : %d\n", (unsigned int)iphdr->ip_reserved_zero);
	printf(" |-Dont Fragment Field : %d\n", (unsigned int)iphdr->ip_dont_fragment);
	printf(" |-More Fragment Field : %d\n", (unsigned int)iphdr->ip_more_fragment);
	printf(" |-TTL : %d\n", (unsigned int)iphdr->ip_ttl);
	printf(" |-Protocol : %d\n", (unsigned int)iphdr->ip_protocol);
	printf(" |-Checksum : %d\n", ntohs(iphdr->ip_checksum));
	printf(" |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	printf(" |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}

void printIpv6Header(IPV6_HDR hdr){
	
}
