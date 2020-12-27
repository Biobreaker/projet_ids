#include "populate.h"
#include <stdlib.h>
#include <syslog.h>
#include <stdbool.h>
//define for rule files
#define MAX_OPTION 5
#define MAX_VALUE_LEN 25
#define MAX_WORD_LEN 15
#define MAX_LINE 2*MAX_WORD_LEN + 4*IP_ADDR_LEN_STR  + MAX_OPTION*MAX_VALUE_LEN

struct rule_option{

	#define MSG_OPTION 1
	#define CONTENT_OPTION 2

	int key;
	char value[MAX_VALUE_LEN];

} typedef Option;

struct ids_rule{

	#define ACTION_ALERT 1
	#define ANY 0
	#define DIRECTION_LEN 3

	int action;
	char protocol[MAX_WORD_LEN];
	char source_ip[IP_ADDR_LEN_STR];
	int source_port;
	char direction[DIRECTION_LEN];
	char destination_ip[IP_ADDR_LEN_STR];
	int destination_port;
	Option option_array[MAX_OPTION];
	int option_size;

} typedef Rule;

/* 
ICMPV4_PROTOCOL 1
TCP_PROTOCOL 6
UDP_PROTOCOL 17
FTP_DATA_PROTOCOL 20
FTP_CONTROL_PROTOCOL 21
SFTP_PROTOCOL 22
TELNET_PROTOCOL 23
SMTP_PROTOCOL 25
RSVP_PROTOCOL 46
GRE_PROTOCOL 47
ESP_PROTOCOL 50
DNS_PROTOCOL 53
ICMPV6_PROTOCOL 58
DHCP_PROTOCOL 67
TFTP_PROTOCOL 69
HTTP_PROTOCOL 80
POP3_PROTOCOL 110
NTP_PROTOCOL 123
IMAP4_PROTOCOL 143
HTTPS_PROTOCOL 443
SNMP_PROTOCOL 161
*/

bool protocolCheck(Rule* rules_ds, ETHER_Frame* frame){
	bool r_value = false;
	if(strcmp(rules_ds->protocol,"any")==0){
		//check with frame protocol
			r_value = true;
	}
	if(strcmp(rules_ds->protocol,"http")==0){
		//check with frame protocol
		r_value = true;
	}
	if(strcmp(rules_ds->protocol,"tcp")==0){
		//check with frame protocol
		r_value = true;
	}
	if(strcmp(rules_ds->protocol,"udp")==0){
		//check with frame protocol
		r_value = true;
	}
	if(strcmp(rules_ds->protocol,"ftp")==0){
		//check with frame protocol
		r_value = true;
	}
	if(strcmp(rules_ds->protocol,"icmp")==0){
		//check with frame protocol
		r_value = true;
	}
	return r_value;
}

void rule_matcher(Rule* rules_ds, ETHER_Frame* frame){
	//Source IP check
	if(strcmp(rules_ds->source_ip,"any")==0||strcmp(rules_ds->source_ip,frame->data.source_ip)==0){
		//Source Port check
		if(rules_ds->source_port == ANY||rules_ds->source_port == frame->data.data.source_port){
			//Direction check
			if(strcmp(rules_ds->direction,"->")==0){
				//Destination IP check
				if(strcmp(rules_ds->destination_ip,"any")==0||strcmp(rules_ds->destination_ip,frame->data.destination_ip)==0){
					//Destination Port check
					if(rules_ds->destination_port == ANY||rules_ds->destination_port == frame->data.data.destination_port){
						//Protocol check
						//Make a fct for protocol check
						if(rules_ds->protocol==ANY){
							printf("Rule matched\n");
							//Option check
							//also make fct
								//react according to action and option
								//if(rules_ds->action == ACTION_ALERT){
						}
					}
				}
			}
		}
	}
}

//count == nbr of line in file
void read_rules(FILE* file, Rule* rules_ds, int count){
	char str_line[MAX_LINE];
	char checkWord[MAX_WORD_LEN];
	for(int i = 0 ; i < count ; i++){
		fgets(str_line,MAX_LINE,file);
		//copy firt param (Action)
		strcpy(checkWord,(strtok(str_line," ")));
		if(strcmp(checkWord,"alert")==0){
			rules_ds[i].action = ACTION_ALERT;
		}
		//copy second param (Protocol)
		strcpy(rules_ds[i].protocol,(strtok(NULL," ")));
		//copy third param (IP source)
		strcpy(rules_ds[i].source_ip,strtok(NULL," "));
		//copy fourth (Port source)
		rules_ds[i].source_port = atoi(strtok(NULL," "));
		//copy fifth param (Direction)
		strcpy(rules_ds[i].direction,strtok(NULL," "));
		//copy sixth param (IP Destination)
		strcpy(rules_ds[i].destination_ip,strtok(NULL," "));
		//copy seventh param (Port Destination)
		strcpy(checkWord,(strtok(NULL," ")));
		rules_ds[i].destination_port = atoi(checkWord);
		//copy options
		char option[MAX_VALUE_LEN];
		//copy key into option
		strcpy(option,strtok(NULL,"(:"));
		int option_nbr = 0;
		while(option[0]!=')'){
			//checking KEY -> maybe just past it and do it in rule_matcher
			if(strcmp(option,"msg")==0){
				rules_ds[i].option_array[option_nbr].key = MSG_OPTION;
			}
			if(strcmp(option,"content")==0){
				rules_ds[i].option_array[option_nbr].key = CONTENT_OPTION;
			}
			//isolating value of option
			strcpy(option,strtok(NULL,"\""));
			strcpy(rules_ds[i].option_array[option_nbr].value,option);
			//checking for another option
			strcpy(option,strtok(NULL,";:\""));
			option_nbr++;
		}
		rules_ds[i].option_size = option_nbr;
	}
}

void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){

	//create Struct Frame
	ETHER_Frame* frame = (ETHER_Frame*)calloc(1,sizeof(ETHER_Frame));

		//puts("\nSTART OF PACKET");	
	//Filling frame with data
	populate_packet_ds(header, packet, frame);
	/* // print Ether_Frame
	printf(	"-----------\nMAC Source: %s\nMAC Destination: %s\nEthernet Type: %d\nFrame Size: %d\n----\n"
			"IP Source: %s\nIP Destination: %s\n----\n"
			"Port Source: %d\nPort Destination: %d\nData: %s\nData Length: %d\n"
			"\nEND OF PACKET\n\n",
			frame->source_mac,frame->destination_mac,frame->ethernet_type,frame->frame_size,
			frame->data.source_ip,frame->data.destination_ip,
			frame->data.data.source_port,frame->data.data.destination_port,frame->data.data.data,frame->data.data.data_length
			);
	*/	
	free(frame);
}


int main(int argc, char** argv){

	FILE* f_rules = fopen(argv[1],"r");
	char str_line[MAX_LINE];
	//Checking nbr of line in file
	int nbr_line = 0;
	while(fgets(str_line,MAX_LINE,f_rules)!=NULL){
		nbr_line++;
	}
	//reset cursor in file   
	rewind(f_rules);

	Rule tab_rules[nbr_line];
	//Rule* tab_rules = (Rule*)calloc(nbr_line,sizeof(Rule));
	read_rules(f_rules,tab_rules,nbr_line);
	/* //Print tab_rule content
	for(int i = 0;i<nbr_line;i++){
		printf("Regle n°%d\n-----\nAction: %d, Protocol: %d, From: %s:%d Direction:[%s], To: %s:%d\n",i+1,tab_rules[i].action,tab_rules[i].protocol,
			tab_rules[i].source_ip,tab_rules[i].source_port,tab_rules[i].direction,tab_rules[i].destination_ip,tab_rules[i].destination_port);
		for(int j = 0;j<tab_rules[i].option_size;j++){
			printf("Option %d: [%d:%s]",j+1,tab_rules[i].option_array[j].key,tab_rules[i].option_array[j].value);
			printf("//");
		}
		puts("\n");
	}
	*/
	char* device = "eth1";
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t* handle;

	handle = pcap_create(device,error_buffer);
	pcap_set_timeout(handle,10);
	pcap_activate(handle);
	//if total_packet_count == 0 -> endless loop
	int total_packet_count = 5;

	puts("\n-------Starting-------\n");
	pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

	fclose(f_rules);
	return 0;
}
