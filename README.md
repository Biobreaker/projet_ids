# projet_ids
Code source du projet pour développement réalisé par Maxime Demoulin et Anthony Lesceux

# main.c
## rule_matcher
Prototype:
```c
void rule_matcher(Rule*,ETHER_Frame*);
```
Cette fonction vérifie, pour une règle et une frame données, l'égalité entre les champs de la règle et les champs de la frame.
Pour se faire, on utilise la fonction `strcmp(string1,string2)`.
### strcmp
Prototype:
```c
int strcmp( const char * first, const char * second );
```
Libaraire: `string.h`
Si toutes les verfications sont passées avec succès, alors un crée une entrée dans syslog selon les valeurs `action` et `msg`
### protocolCheck
Prototype:
```c
bool protocolCheck(Rule*,ETHER_Frame*);
```
Si la valeur du champ protocol est 'any', alors on égalise `r_value` à `true`.
```c
if(strcmp(rules_ds->protocol,"any")==0){
    r_value = true;
}
```
Sinon, on vérifie le protocol de cette façon générique:
```c
if(strcmp(rules_ds->protocol,"SomeProtocolValue")==0){
    if(frame->data.transport_protocol == SOME_PROTOCOL_DEFINE){
        r_value = true;
    }
}
```
### contentCheck
Prototype:
```c
bool contentCheck(Rule*,ETHER_Frame*);
```
#### Recherche de clé 'content'
On parcourt l'ensemble l'ensemble des clés pour vérifier si l'une d'elle est `content`.
```c
for(int i = 0 ; i < rules_ds->option_size ; i++){
    if(rules_ds->option_array[i].key == CONTENT_OPTION){
        isContentOption = true;
```
Si c'est le cas, on vérifie si le dit contenu est présent dans le payload.
```c
        if(strstr((char*)frame->data.data.data,rules_ds->option_array[i].value)!=NULL){
            isContentInPayload = true;
        }
    }
}
```
Si il n'y a pas de clé `content` alors la fonction renvoi `true`.
Si il y a une clé `content` et que le contenu est présent dans le payload alors la fonction renvoi `true`.
Sinon, la fonction renvoi `false`.
```c
return contentCheck;
}
```
### Recherche de clé 'msg'
De la même façon que pour la clé 'content', on parcourt l'ensemble des clés à la recherche de 'msg'
```c
for(int i = 0 ; i < rules_ds->option_size ; i++){
    if(rules_ds->option_array[i].key == MSG_OPTION){
        strcpy(rule_message,rules_ds->option_array[i].value);
    }
}
```
Lorsque celle-ci est trouvée, on copie sa valeur dans `rule_message`
### Generation de syslog
On vérifie que le type d'action est bien 'alert'. 
Si c'est le cas on crée un log de type `LOG_ALERT` avec pour message `rule_message`.
```c
if(rules_ds->action == ACTION_ALERT){
    openlog("IDS",LOG_PID|LOG_CONS,LOG_USER);
    syslog(LOG_ALERT,rule_message);
    closelog();
}
```
Si aucun message n'est fourni dans le fichier de règles, un message générique est envoyé.
## read_rules
Prototype:
```c
void read_rules(FILE*,Rule*,int);
```
Pour chacune des lignes du fichier de règles, on garnit une structure `Rule` selon les valeurs de la ligne en question.
Pour se faire on utilise la fonction `strtok(token,separators)`
### strtok
Prototype:
```c
char * strtok( char * restrict string, const char * restrict delimiters );
```
Libaraire: `string.h`
## main
```c
```
### Arg_passer
```c
struct argument_passer{

	#define MAX_RULE_LINES 256

	int total_line;
	Rule rules_array[MAX_RULE_LINES];
	
} typedef Arg_passer;
```
# populate.c
## Vérification des protocols couche Transport
Format générique:
```c
if((int)ip->ip_p==SOME_PROTOCOL){
    printf("\nSome Protocol\n");
    custom_frame->data.transport_protocol = SOME_PROTOCOL;
}
```
## Formatage UDP
```c
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
			
			//print_payload(payload_length, payload);
						
			custom_segment.source_port = ntohs(udp->uh_sport);
			custom_segment.destination_port = ntohs(udp->uh_dport);
			custom_segment.data = payload;
			custom_segment.data_length = payload_length;

			custom_packet.data = (TCP_Segment)custom_segment;
			custom_frame->data = custom_packet;
			custom_frame->data.transport_protocol = UDP_PROTOCOL;
		}
```
## Formatage TCP
```c
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
```
# populate.h
## define
Basé sur les informations de [cette page](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers), on obtient ces tableau
| Protocols couche Transport | Ports |
| :------------------------- |:-----:|
| ICMPv4                     | 1     |
| TCP                        | 6     |
| EGP                        | 8     |
| IGP                        | 9     |
| UDP                        | 17    |
| RSVP                       | 46    |
| GRE                        | 47    |
| ICMPv6                     | 58    |

| Protocols couche Applicative | TCP/UDP | Ports |
| :----------------------------|:-------:|:-----:|
| FTP                          | TCP     | 20/21 |
| SSH (sftp,scp,...)           | TCP     | 22    |
| Telnet                       | TCP     | 23    |
| SMTP                         | TCP     | 25    |
| DNS                          | UDP     | 53    |
| BOOTP (aka DHCP)             | UDP     | 67/68 |
| TFTP                         | UDP     | 69    |
| HTTP                         | TCP     | 80    |
| Kerberos                     | Les 2   | 88    |
| POPv2                        | TCP     | 109   |
| POPv3                        | TCP     | 110   |
| NNTP                         | TCP     | 119   |
| NTP                          | UDP     | 123   |
| IMAPv4                       | TCP     | 143   |
| SNMP                         | UDP     | 161   |
| HTTPS                        | TCP     | 443   |

Pour un soucis de lisibilité du code et d'utilisation, on crée un define pour chacun d'eux.

## sniff_udp
```c
struct sniff_udp {
    u_short uh_sport;     /* source port */
    u_short uh_dport;     /* destination port */
    u_short uh_length;		/* size of udp header */
    u_short uh_checksum;	/* checksum */
};
```
Cette structure est utilisé pour caster la frame et ainsi récupérer le contenu du header UDP [(cfr 
