#include "populate.h"
#include <stdlib.h>
//value for rule files
#define MAX_OPTION_LEN 5
#define MAX_DIRECTION_LEN 3
#define MAX_VALUE_LEN 25
#define MAX_RULE_PARAM 8
#define MAX_WORD_LEN 16
#define MAX_LINE MAX_WORD_LEN * MAX_RULE_PARAM + MAX_OPTION_LEN * MAX_VALUE_LEN

struct rule_option{

	#define MSG 0
	#define CONTENT 1

	int key;
	char value[MAX_VALUE_LEN];
} typedef Option;

struct ids_rule{
	//
	#define ACTION_ALERT 1
	#define ANY 0

	int action; 
	int protocol;
	char source_ip[IP_ADDR_LEN_STR];
	int source_port;
	char direction [MAX_DIRECTION_LEN];
	char destination_ip[IP_ADDR_LEN_STR];
	int destination_port;
	//maybe an array of struct rule_option ??
	Option option_array[MAX_OPTION_LEN];
	int option_size;

	
} typedef Rule;

void rule_matcher(Rule* rules_ds, ETHER_Frame* frame){
	if(rules_ds->action == ACTION_ALERT){
		//if(rules_ds->protocol==ANY || rules_ds->protocol==frame->protocol){
			if(strcmp(rules_ds->source_ip,"any")==0||strcmp(rules_ds->source_ip,frame->data.source_ip)==0){
				if(rules_ds->source_port == ANY||rules_ds->source_port == frame->data.data.source_port){
					if(strcmp(rules_ds->direction,"->")==0){
						if(strcmp(rules_ds->destination_ip,"any")==0||strcmp(rules_ds->destination_ip,frame->data.destination_ip)==0){
							if(rules_ds->destination_port == ANY||rules_ds->destination_port == frame->data.data.destination_port){
								//do things
								printf("Rule matched\n");
							}
						}
					}
				}
			}
		//}
	}
	
}

//count == nbr of line in file
void read_rules(FILE* file, Rule* rules_ds, int count){
	

}

void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){

	

	ETHER_Frame* frame = (ETHER_Frame*)calloc(1,sizeof(ETHER_Frame));

	puts("\nSTART OF PACKET");	

	populate_packet_ds(header, packet, frame);

	printf(	"-----------\nMAC Source: %s\nMAC Destination: %s\nEthernet Type: %d\nFrame Size: %d\n----\n"
			"IP Source: %s\nIP Destination: %s\n----\n"
			"Port Source: %d\nPort Destination: %d\nData: %s\nData Length: %d\n"
			"\nEND OF PACKET\n\n",
			frame->source_mac,frame->destination_mac,frame->ethernet_type,frame->frame_size,
			frame->data.source_ip,frame->data.destination_ip,
			frame->data.data.source_port,frame->data.data.destination_port,frame->data.data.data,frame->data.data.data_length
			);
	
	free(frame);
}

int main(int argc, char** argv){

		FILE* f_rules = fopen(argv[1],"r");

		char str_line[MAX_LINE];
		int nbr_line = 0;
		while(fgets(str_line,MAX_LINE,f_rules)!=NULL){
			//printf("str_line: %s\n",str_line);
			nbr_line++;
		}
		//printf("Nb of line: %d",nbr_line);

		//reset cursor in file   
		rewind(f_rules);
		Rule tab_rules[nbr_line];
		
		read_rules(f_rules,tab_rules,nbr_line);

        char* device = "eth1";
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t* handle;

        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,10);
        pcap_activate(handle);
		//if total_packet_count == 0 -> endless loop
        int total_packet_count = 0;

		puts("\n-------Starting-------\n");
        pcap_loop(handle, total_packet_count, my_packet_handler, NULL);
		//fclose(rule);
        
		return 0;
}
