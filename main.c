#include "populate.h"
#include <stdlib.h>
#include <syslog.h>
#include <stdbool.h>

//define for rule files
#define MAX_OPTION 5
#define MAX_VALUE_LEN 50
#define MAX_WORD_LEN 15
#define MAX_LINE 2*MAX_WORD_LEN + 4*IP_ADDR_LEN_STR  + MAX_OPTION*MAX_VALUE_LEN

//used to store options in rules
struct rule_option{

	#define MSG_OPTION 1
	#define CONTENT_OPTION 2

	int key;
	char value[MAX_VALUE_LEN];

} typedef Option;

//used to store converted ids.rules value
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

//used to transfer int and struct ids_rule to my_packet_handler
struct argument_passer{

	#define MAX_RULE_LINES 32

	int total_line;
	Rule rules_array[MAX_RULE_LINES];
	
} typedef Arg_passer;

//function proto
void printRule(Rule*,int);
void printFrame(ETHER_Frame*);
bool protocolCheck(Rule*,ETHER_Frame*);
bool contentCheck(Rule*,ETHER_Frame*);
void rule_matcher(Rule*,ETHER_Frame*);
void read_rules(FILE*,Rule*,int);

//Great check for Protocols
bool protocolCheck(Rule* rules_ds, ETHER_Frame* frame){
	bool r_value = false;
	if(strcmp(rules_ds->protocol,"any")==0){
			r_value = true;
	}
	//Transport Layer Protocols
	if(strcmp(rules_ds->protocol,"icmp")==0){
		if(frame->data.transport_protocol == ICMPV4_PROTOCOL ||frame->data.transport_protocol == ICMPV6_PROTOCOL){
			r_value = true;
		}
	}
	if(strcmp(rules_ds->protocol,"tcp")==0){
		if(frame->data.transport_protocol == TCP_PROTOCOL){
			r_value = true;
		}

	}
	if(strcmp(rules_ds->protocol,"egp")==0){
		if(frame->data.transport_protocol == EGP_PROTOCOL){
			r_value = true;
		}
	}
	if(strcmp(rules_ds->protocol,"igp")==0){
		if(frame->data.transport_protocol == IGP_PROTOCOL){
			r_value = true;
		}
	}
	if(strcmp(rules_ds->protocol,"udp")==0){
		if(frame->data.transport_protocol == UDP_PROTOCOL){
			r_value = true;
		}
	}
	if(strcmp(rules_ds->protocol,"rsvp")==0){
		if(frame->data.transport_protocol == RSVP_PROTOCOL){
			r_value = true;
		}
	}
	if(strcmp(rules_ds->protocol,"gre")==0){
		if(frame->data.transport_protocol == GRE_PROTOCOL){
			r_value = true;
		}
	}
	//Application Layer Protocols
		//via TCP
	if(frame->data.transport_protocol == TCP_PROTOCOL){
		if(strcmp(rules_ds->protocol,"ftp")==0){
			if(frame->data.data.source_port == FTP_DATA_PROTOCOL || frame->data.data.destination_port == FTP_DATA_PROTOCOL
			  || frame->data.data.source_port == FTP_CONTROL_PROTOCOL || frame->data.data.destination_port == FTP_DATA_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"sftp")==0){
			if(frame->data.data.source_port == SSH_PROTOCOL || frame->data.data.destination_port == SSH_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"scp")==0){
			if(frame->data.data.source_port == SSH_PROTOCOL || frame->data.data.destination_port == SSH_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"telnet")==0){
			if(frame->data.data.source_port == TELNET_PROTOCOL || frame->data.data.destination_port == TELNET_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"smtp")==0){
			if(frame->data.data.source_port == SMTP_PROTOCOL || frame->data.data.destination_port == SMTP_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"dns")==0){
			if(frame->data.data.source_port == DNS_PROTOCOL || frame->data.data.destination_port == DNS_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"http")==0){
			if(frame->data.data.source_port == HTTP_PROTOCOL || frame->data.data.destination_port == HTTP_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"kerberos")==0){
			if(frame->data.data.source_port == KERBEROS_PROTOCOL || frame->data.data.destination_port == KERBEROS_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"pop2")==0){
			if(frame->data.data.source_port == POP2_PROTOCOL || frame->data.data.destination_port == POP2_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"pop3")==0){
			if(frame->data.data.source_port == POP3_PROTOCOL || frame->data.data.destination_port == POP3_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"nntp")==0){
			if(frame->data.data.source_port == NNTP_PROTOCOL || frame->data.data.destination_port == NNTP_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"imap4")==0){
			if(frame->data.data.source_port == IMAP4_PROTOCOL || frame->data.data.destination_port == IMAP4_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"https")==0){
			if(frame->data.data.source_port == HTTPS_PROTOCOL || frame->data.data.destination_port == HTTPS_PROTOCOL){
				r_value = true;
			}
		}
	}
		//via UDP
	if(frame->data.transport_protocol == UDP_PROTOCOL){
		if(strcmp(rules_ds->protocol,"dns")==0){
			if(frame->data.data.source_port == DNS_PROTOCOL || frame->data.data.destination_port == DNS_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"dhcp")==0){
			if(frame->data.data.source_port == BOOTP_SERVER_PROTOCOL || frame->data.data.destination_port == BOOTP_SERVER_PROTOCOL
			  ||frame->data.data.source_port == BOOTP_CLIENT_PROTOCOL || frame->data.data.destination_port == BOOTP_CLIENT_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"tftp")==0){
			if(frame->data.data.source_port == TFTP_PROTOCOL || frame->data.data.destination_port == TFTP_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"kerberos")==0){
			if(frame->data.data.source_port == KERBEROS_PROTOCOL || frame->data.data.destination_port == KERBEROS_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"ntp")==0){
			if(frame->data.data.source_port == NTP_PROTOCOL || frame->data.data.destination_port == NTP_PROTOCOL){
				r_value = true;
			}
		}
		if(strcmp(rules_ds->protocol,"snmp")==0){
			if(frame->data.data.source_port == SNMP_PROTOCOL || frame->data.data.destination_port == SNMP_PROTOCOL){
				r_value = true;
			}
		}
	}
	return r_value;
}

//Option check
bool contentCheck(Rule* rules_ds, ETHER_Frame* frame){
	bool contentCheck = false;
	bool isContentOption = false;
	bool isContentInPayload = false;
	for(int i = 0 ; i < rules_ds->option_size ; i++){
		if(rules_ds->option_array[i].key == CONTENT_OPTION){
			isContentOption = true;
			if(strstr((char*)frame->data.data.data,rules_ds->option_array[i].value)!=NULL){
				isContentInPayload = true;
			}
		}
	}
	if(!isContentOption){
		contentCheck = true;
	}
	if(isContentInPayload){
		contentCheck = true;
	}
	return contentCheck;
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
						if(protocolCheck(rules_ds, frame)){
							//Option content Check
							if(contentCheck(rules_ds,frame)){
								//react according to action and option
								printf("Rule matched\n");
								char rule_message[MAX_VALUE_LEN];
								strcpy(rule_message,"No message provided in .rules file");
								for(int i = 0 ; i < rules_ds->option_size ; i++){
									if(rules_ds->option_array[i].key == MSG_OPTION){
										strcpy(rule_message,rules_ds->option_array[i].value);
									}
								}
								if(rules_ds->action == ACTION_ALERT){
									openlog("IDS",LOG_PID|LOG_CONS,LOG_USER);
									syslog(LOG_ALERT,rule_message);
									closelog();
								}
							}
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

// print rules
void printRule(Rule* p_rule, int index){
	printf("Regle n°%d\n-----\nAction: %d, Protocol: %s, From: %s:%d Direction:[%s], To: %s:%d\n",index+1,p_rule->action,p_rule->protocol,
			p_rule->source_ip,p_rule->source_port,p_rule->direction,p_rule->destination_ip,p_rule->destination_port);
		for(int j = 0;j<p_rule->option_size;j++){
			printf("Option %d: [%d:%s]",j+1,p_rule->option_array[j].key,p_rule->option_array[j].value);
			printf("//");
		}
		puts("\n");
}

// print Ether_Frame
void printFrame(ETHER_Frame* frame){
	printf(	"-----------\nMAC Source: %s\nMAC Destination: %s\nEthernet Type: %d\nFrame Size: %d\n----\n"
			"IP Source: %s\nIP Destination: %s\n----\n"
			"Port Source: %d\nPort Destination: %d\nData: %s\nData Length: %d\n",
			frame->source_mac,frame->destination_mac,frame->ethernet_type,frame->frame_size,
			frame->data.source_ip,frame->data.destination_ip,
			frame->data.data.source_port,frame->data.data.destination_port,frame->data.data.data,frame->data.data.data_length
			);
}

void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){

	//create Struct Frame
	ETHER_Frame* frame = (ETHER_Frame*)calloc(1,sizeof(ETHER_Frame));
		//puts("\nSTART OF PACKET");	
	//Filling frame with data
	populate_packet_ds(header, packet, frame);
	//recasting args into Arg_passes
	Arg_passer* arg_pass = (Arg_passer*)args;
	//Matching frame with rules
	for(int i = 0;i<arg_pass->total_line;i++){
		rule_matcher(&arg_pass->rules_array[i],frame);
	}
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
	
	Arg_passer arg_pass = {nbr_line};
	
	//Filling rule struct
	read_rules(f_rules,arg_pass.rules_array,nbr_line);
	fclose(f_rules);
	
	char* device = "eth1";
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t* handle;

	handle = pcap_create(device,error_buffer);
	pcap_set_timeout(handle,10);
	pcap_activate(handle);
	//if total_packet_count == 0 -> endless loop
	int total_packet_count = 0;

	puts("\n-------Analyzing Packets-------\n");
		//using args to pass adress of arg_pass containing Rules and nbr_line
	pcap_loop(handle, total_packet_count, my_packet_handler, (unsigned char*)&arg_pass);

	return 0;
}
