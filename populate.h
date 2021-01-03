#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>


/* Ethernet addresses are 6 bytes */
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN_STR 18
#define IP_ADDR_LEN_STR 16

#define ARP 2054
#define IPV4 2048
#define IPV6 34525

#define ICMPV4_PROTOCOL 1
#define TCP_PROTOCOL 6
#define EGP_PROTOCOL 8
#define IGP_PROTOCOL 9
#define UDP_PROTOCOL 17
#define FTP_DATA_PROTOCOL 20
#define FTP_CONTROL_PROTOCOL 21
#define SSH_PROTOCOL 22
#define TELNET_PROTOCOL 23
#define SMTP_PROTOCOL 25
#define RSVP_PROTOCOL 46
#define GRE_PROTOCOL 47
#define ESP_PROTOCOL 50
#define DNS_PROTOCOL 53
#define ICMPV6_PROTOCOL 58
#define BOOTP_SERVER_PROTOCOL 67
#define BOOTP_CLIENT_PROTOCOL 68
#define TFTP_PROTOCOL 69
#define HTTP_PROTOCOL 80
#define KERBEROS_PROTOCOL 88
#define POP2_PROTOCOL 109
#define POP3_PROTOCOL 110
#define NNTP_PROTOCOL 119
#define NTP_PROTOCOL 123
#define IMAP4_PROTOCOL 143
#define HTTPS_PROTOCOL 443
#define SNMP_PROTOCOL 161

#define ERROR -1

/* Ethernet header */
struct sniff_ethernet 
{
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
        u_char ip_vhl;          /* version << 4 | header length >> 2 */
        u_char ip_tos;          /* type of service */
        u_short ip_len;         /* total length */
        u_short ip_id;          /* identification */
        u_short ip_off;         /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char ip_ttl;          /* time to live */
        u_char ip_p;            /* protocol */
        u_short ip_sum;         /* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;       /* source port */
        u_short th_dport;       /* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
        u_char th_offx2;        /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;         /* window */
        u_short th_sum;         /* checksum */
        u_short th_urp;         /* urgent pointer */
};

struct sniff_udp {
	u_short uh_sport;  	/* source port */
	u_short uh_dport;	/* destination port */
	u_short uh_length;	/* size of udp header */
	u_short uh_checksum;  	/* checksum */
};

struct custom_udp
{
	int source_port;
	int destination_port;
	unsigned char* data;
	int data_length;

} typedef UDP_Packet;

struct custom_tcp
{
        int source_port;
        int destination_port;
        unsigned char* data;
        int sequence_number;
        int ack_number;
        int th_flag;
        int data_length;

} typedef TCP_Segment;

struct custom_ip
{
        char source_ip[IP_ADDR_LEN_STR];
        char destination_ip[IP_ADDR_LEN_STR];
        int transport_protocol;
        TCP_Segment data;

} typedef IP_Packet;


struct custom_ethernet
{
        char source_mac[ETHER_ADDR_LEN_STR];
        char destination_mac[ETHER_ADDR_LEN_STR];
        int ethernet_type;
        int frame_size;
        IP_Packet data;

} typedef ETHER_Frame;

int populate_packet_ds(const struct pcap_pkthdr* header, const u_char* packet,ETHER_Frame* frame);
void print_payload(int payload_length, unsigned char* payload);
