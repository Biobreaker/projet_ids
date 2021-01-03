# projet_ids
Code source du projet pour développement réalisé par Maxime Demoulin et Anthony Lesceux

### Qu’est-ce qu’un IDS :

L’Intrusion Détection System (IDS) est un outil qui utilise un mécanisme de détection, destiné à surveiller le trafic entrant et sortant du réseau dans le but de détecter des activités anormales ou suspectes sur une cible. Dans le but de nous informer d’une potentielle attaque/intrusion en temps réel.

# [main.c](./main.c)
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

Si toutes les verfications sont passées avec succès, alors un crée une entrée dans syslog selon les valeurs `action` et `msg` du fichier `ids.rules`
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
### struct ids_rule (Alias Rule)
```c
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
```
Pour se faire on utilise la fonction `strtok(string,delimiters)`
### strtok
Prototype:
```c
char * strtok( char * restrict string, const char * restrict delimiters );
```
Libaraire: `string.h`

Cette fonction sert à décomposer une chaine de caractères selon certains délimiteurs.

Ici elle est utilisée:
+ Une première fois pour récupérer chaque paramètres d'une ligne du fichier `ids.rules` [(cfr ids.rules)](#idsrules)
+ Une deuxième fois pour récupérer les différentes options et leurs valeurs.

Pour les options on utilise la structure:
### struct rule_option (Alias Option)
```c
struct rule_option{
	#define MSG_OPTION 1
	#define CONTENT_OPTION 2
	int key;
	char value[MAX_VALUE_LEN];
} typedef Option;
```
## my_packet_handler
Prototype:
```c
typedef void (*pcap_handler)(u_char *arg, const struct pcap_pkthdr *, const u_char *);
```
`my_packet_handler` est une fonction de rappel utilisée par `pcap_loop()`.

Pour chaque paquet qui transite via le réseau, on reçoit peut les traiter via cette fonction.
```c
    ETHER_Frame* frame = (ETHER_Frame*)calloc(1,sizeof(ETHER_Frame));
    populate_packet_ds(header, packet, frame);
    Arg_passer* arg_pass = (Arg_passer*)args;
    for(int i = 0;i<arg_pass->total_line;i++){
        rule_matcher(&arg_pass->rules_array[i],frame);
    }
    free(frame);
```
Tout d'abord, un pointeur vers une structure `ETHER_Frame` est crée via la fonction `calloc()`
Ensuite on fait appel à la fonction `populate_packet_ds`[(cfr populate.c)](#populatec)
On crée une structure `Arg_passer`[(voir plus bas)](#structargumentpasseraliasargpasser)que l'on remplit avec les valeurs pointées par `args`
Après ça, on boucle sur le nombre total de ligne de notre fichier `ids.rules`.
Finalement, on libère l'espace en mémoire occupé par `frame`
## main
```c
    FILE* f_rules = fopen(argv[1],"r");
    char str_line[MAX_LINE];
    int nbr_line = 0;
    while(fgets(str_line,MAX_LINE,f_rules)!=NULL){
        nbr_line++;
    }
    if(nbr_line>MAX_RULE_LINES){
        printf("%s too big. Max lines value is %d\n",argv[1],MAX_RULE_LINES);
        return EXIT_FAILURE;
    }  
    rewind(f_rules);
    Arg_passer arg_pass = {nbr_line};
    read_rules(f_rules,arg_pass.rules_array,nbr_line);
    fclose(f_rules);
```
Dans la première partie du main, on ouvre un fichier que l'on va parcourir entièrement pour récupérer le nombre de ligne.

Ensuite, si ce nombre de ligne dépasse la valeur définie, on affiche le message d'erreur et on arrète le programme.

Finalement, on place lu curseur du fichier au début, puis on appel la fonction `read_rules()`
```c
    char* device = "eth1";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    handle = pcap_create(device,error_buffer);
    pcap_set_timeout(handle,10);
    pcap_activate(handle);
    int total_packet_count = 0;
    printf("\n-------Analyzing Packets on [%s]-------\n",device);
    pcap_loop(handle, total_packet_count, my_packet_handler, (unsigned char*)&arg_pass);
    return 0;
}
```
Dans la deuxième partie du main, on récupère la chaine de caractère en argument correspondant à l'interface d'écoute.

Ensuite on paramètre les varaibles pour pouvoir capturer via `pcap_loop()`.

Finalement, on affiche un message signifiant le début de la capture et on appelle `pcap_loop()` pour lancer la capture.

N.B.: Si la variable `total_packet_count` vaut 0 alors `pcap_loop()` boucle sans fin. Sinon elle capture le nombre de paquet équivalent.
### struct argument_passer (Alias Arg_passer)
Cette structure est utilisée pour passer l'ensemble des règles lues ainsi que leurs nombres à la fonction my_packet_handler
```c
struct argument_passer{
	#define MAX_RULE_LINES 256
	int total_line;
	Rule rules_array[MAX_RULE_LINES];
} typedef Arg_passer;
```
## print rules
Cette fonction est utilisée à des fins de debug. Elle affiche le contenu d'une rule
```c
void printRule(Rule* p_rule, int index){
    printf("Regle n°%d\n-----\nAction: %d, Protocol: %s, From: %s:%d Direction:[%s], To: %s:%d\n",index+1,p_rule->action,p_rule->protocol,
     p_rule->source_ip,p_rule->source_port,p_rule->direction,p_rule->destination_ip,p_rule->destination_port);
    for(int j = 0;j<p_rule->option_size;j++){
        printf("Option %d: [%d:%s]",j+1,p_rule->option_array[j].key,p_rule->option_array[j].value);
	printf("//");
    }
    puts("\n");
}
```
## printFrame
Cette fonction est également utilisée à des fins de debug. Elle affiche le contenu d'une frame
```c
void printFrame(ETHER_Frame* frame){
	printf(	"-----------\nMAC Source: %s\nMAC Destination: %s\nEthernet Type: %d\nFrame Size: %d\n----\n"
			"IP Source: %s\nIP Destination: %s\n----\n"
			"Port Source: %d\nPort Destination: %d\nData: %s\nData Length: %d\n",
			frame->source_mac,frame->destination_mac,frame->ethernet_type,frame->frame_size,
			frame->data.source_ip,frame->data.destination_ip,
			frame->data.data.source_port,frame->data.data.destination_port,frame->data.data.data,frame->data.data.data_length
			);
}
```
# [populate.c](./populate.c)
## populate_packet_ds
Prototype:
```c
int populate_packet_ds(const struct pcap_pkthdr* header, const u_char* packet, ETHER_Frame* custom_frame);
```
C'est dans cette fonction que l'on castera les données brutes des paquets dans des structures plus facilement compréhensibles et manipulables.

Chaque paquet est soumis à une vérification grâce aux structures sniff_xxx qui formatent les données via le casting.[(cfr Formatage UDP)](#formatage-udp)
## Vérification des protocols couche Transport
Format générique:
```c
if((int)ip->ip_p==SOME_PROTOCOL){
    printf("\nSome Protocol\n");
    custom_frame->data.transport_protocol = SOME_PROTOCOL;
}
```
Chaque protocol est vérifié selon sa valeur dans le header IP puis intégré dans dans la stucture `ETHER_Frame`
## Formatage UDP
```c
if((int)ip->ip_p==UDP_PROTOCOL){
    printf("\nUDP Handling\n");
    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
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
```
On caste les données à l'adresse du packet shiftée de la taille du header Ethernet et du header IP.

Ensuite on récupère la taille dans le champ correspondant via la fonction de formatage `ntohs()`

Si la taille est valable (supérieur à 8 dans le cas d'UDP), on continue. Sinon on renvoit une erreur.

On remplit chacun des champs de la structure et des sous-structures, en oubliant pas les convertir via `ntohs()` si nécessaire. 

Dans un soucis de simplicité, on réutilise TCP_Segment qui peut contenir les mêmes valeurs qu'UDP.

Finalement, on indique le type du protocol (UDP dans ce cas). 
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
Le déroulement est similaire au formatage UDP. Seulement, la taille du header TCP est multiplié par 4 pour être sur 16 bits.
# [populate.h](./populate.h)
## define
Basé sur les informations de [cette page](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers), on obtient ces tableaux
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
Cette structure est utilisé pour caster la frame et ainsi récupérer le contenu du header UDP.
# [ids.rules](./ids.rules)
Le fichier de configuration doit respecter le format suivant:
`action protocol ip_address_source port_source direction ip_address_dest port_dest (key1:"value1";key2,"value2";)`
Pour la simplicité du programme, seul l'action `alert` est implémentée.

La liste des protocols utilisable est:

`icmp`,`tcp`,`egp`,`igp`,`udp`,`rsvp`,`gre`,`ftp`,`sftp`,`scp`,`telnet`,`smtp`,`dns`,`dhcp`,`tftp`,`http`,`kerberos`,`pop2`,`pop3`,`nntp`,`ntp`,`imap4`,`snmp`,`https`
