#include <stdio.h>
#include "populate.h"


void generate_ip(unsigned int ip, char ip_addr[])
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    snprintf(ip_addr,IP_ADDR_LEN_STR,
        "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]); 
}

void print_payload(int payload_length, unsigned char* payload)
{
        if (payload_length > 0) 
        {
				puts("----START OF PAYLOAD----");                
				const u_char* temp_pointer = payload;
                int byte_count = 0;
                while (byte_count++ < payload_length) 
                {
                        printf("%c", (char)*temp_pointer);
                        temp_pointer++;
                }
                printf("\n");
				puts("----END OF PAYLOAD----");
        }
}


int populate_packet_ds(const struct pcap_pkthdr* header, const u_char* packet, ETHER_Frame* custom_frame)
{
	const struct sniff_ethernet* ethernet; /* The ethernet header */
	const struct sniff_ip* ip; /* The IP header */
	const struct sniff_tcp* tcp; /* The TCP header */
	const struct sniff_udp* udp;/* The UDP header */
	unsigned char* payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;
	u_int size_udp;

	ethernet = (struct sniff_ethernet*)(packet);
	//ETHER_Frame custom_frame;
	char src_mac_address[ETHER_ADDR_LEN_STR];
	char dst_mac_address[ETHER_ADDR_LEN_STR];
	custom_frame->frame_size = header->caplen;
	// Convert unsigned char MAC to string MAC
	for(int x=0;x<6;x++){
		snprintf(src_mac_address+(x*2),ETHER_ADDR_LEN_STR,
                "%02x",ethernet->ether_shost[x]);
		snprintf(dst_mac_address+(x*2),ETHER_ADDR_LEN_STR,
                "%02x",ethernet->ether_dhost[x]);
    }

	strcpy(custom_frame->source_mac,src_mac_address);
	strcpy(custom_frame->destination_mac, dst_mac_address);

    if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP){
		custom_frame->ethernet_type = ARP;
		printf("\nARP packet: %d\n",custom_frame->ethernet_type);
    }

	if(ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
		custom_frame->ethernet_type = IPV4;
		printf("\nIPV4 packet: %d\n",custom_frame->ethernet_type);

		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		IP_Packet custom_packet;
		char src_ip[IP_ADDR_LEN_STR];
		char dst_ip[IP_ADDR_LEN_STR];
		generate_ip(ip->ip_src.s_addr,src_ip);
		generate_ip(ip->ip_dst.s_addr,dst_ip);

		strcpy(custom_packet.source_ip,src_ip);
		strcpy(custom_packet.destination_ip, dst_ip);
		//printf("Test IP: Source:%s Dest:%s",src_ip,custom_packet.source_ip);
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return ERROR;
		}
		custom_packet.data = custom_frame->data.data;
		custom_frame->data = custom_packet;

		if((int)ip->ip_p==ICMPV4_PROTOCOL){
			printf("\nICMP Protocol\n");
			custom_frame->data.transport_protocol = ICMPV4_PROTOCOL;
		}
		if((int)ip->ip_p==UDP_PROTOCOL){
			printf("\nUDP Handling\n");
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			//UDP_Packet custom_segment;
			TCP_Segment custom_segment;
			
			size_udp = ntohs(udp->uh_length);

			if (size_udp < 8) {
				printf("   * Invalid UDP header length: %u bytes\n", size_udp);
				return ERROR;
			}
			
			payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_udp);
			int payload_length = (header->caplen)-SIZE_ETHERNET-size_ip-size_udp;
						
			custom_segment.source_port = ntohs(udp->uh_sport);
			custom_segment.destination_port = ntohs(udp->uh_dport);
			custom_segment.data = payload;
			custom_segment.data_length = payload_length;

			custom_packet.data = (TCP_Segment)custom_segment;
			custom_frame->data = custom_packet;
			custom_frame->data.transport_protocol = UDP_PROTOCOL;
		}
		if((int)ip->ip_p==RSVP_PROTOCOL){
			printf("\nRSVP_PROTOCOL\n");
			custom_frame->data.transport_protocol = RSVP_PROTOCOL;
		}
		if((int)ip->ip_p==GRE_PROTOCOL){
			printf("\nGRE_PROTOCOL\n");
			custom_frame->data.transport_protocol = GRE_PROTOCOL;
		}
		if((int)ip->ip_p==EGP_PROTOCOL){
			printf("\nEGP_PROTOCOL\n");
			custom_frame->data.transport_protocol = EGP_PROTOCOL;
		}
		if((int)ip->ip_p==IGP_PROTOCOL){
			printf("\nIGP_PROTOCOL\n");
			custom_frame->data.transport_protocol = IGP_PROTOCOL;
		}
		if((int)ip->ip_p==ICMPV6_PROTOCOL){
			printf("\nICMPV6 PROTOCOL\n");
			custom_frame->data.transport_protocol = ICMPV6_PROTOCOL;
		}
		if((int)ip->ip_p==TCP_PROTOCOL){
			printf("\nTCP Handling\n");
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			TCP_Segment custom_segment;

			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return ERROR;
			}
			payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			int payload_length = (header->caplen)-SIZE_ETHERNET-size_ip-size_tcp;
			
			custom_segment.source_port = ntohs(tcp->th_sport);
			custom_segment.destination_port = ntohs(tcp->th_dport);
			custom_segment.th_flag = (int)tcp->th_flags;
			custom_segment.sequence_number = tcp->th_seq;
			custom_segment.data = payload;
			custom_segment.data_length = payload_length;
			
			custom_packet.data = custom_segment;
			custom_frame->data = custom_packet;
			custom_frame->data.transport_protocol = TCP_PROTOCOL;

		}
	}
	return 0;
}

