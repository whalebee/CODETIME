#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
//#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <netdb.h>

// new
#include <pthread.h> // thread()
#include <unistd.h> // sleep()


// for mariadb .
//#include <mariadb/my_global.h>
#include <mariadb/mysql.h>

#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
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
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/*------------------global variables------------------*/
// socket
#define TO_MS 1000
#define IP_SIZE 16
#define IP_HDR_SIZE 20
#define TCP_HDR_SIZE 20

// sendraw
char bind_device_name[] = "lo" ;
int bind_device_name_len = 2 ;
int sendraw_mode = 1;

// DB
MYSQL *connection = NULL;
MYSQL conn;
MYSQL_RES *res;
MYSQL_ROW row;
MYSQL_RES *res_block;
MYSQL_ROW row_block;
MYSQL_RES *res_check;
MYSQL_ROW row_check;
int cmp_ret = 1; // base: allow
#define DOMAIN_BUF 260
#define REC_DOM_MAX 100
#define REC_DOM_LEN 260
// DB - new
int log_cnt = 0;
MYSQL_RES *res_check;
MYSQL_ROW row_check;
MYSQL_RES *res_cnt;
MYSQL_ROW row_cnt;
char block_domain_arr[REC_DOM_MAX][REC_DOM_LEN] = { 0x00 }; // block_domain_arr array for print block_list
int block_domain_count = 1;

// TCP Header checksum
struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};

// Protocol Info
char IPbuffer_str[IP_SIZE]; 		// IP_SIZE 16
char IPbuffer2_str[IP_SIZE]; 		// IP_SIZE 16
unsigned short tcp_src_port = 0;
unsigned short tcp_dst_port = 0;

// int gbl_debug = 1; 	// later .
// int g_ret = 0; 		// later .



/*------------------function------------------*/
// got_packet
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_info(const struct sniff_ethernet *ethernet, 
				const struct sniff_ip *ip, 
				const struct sniff_tcp *tcp,
				u_char* domain_str);

// DB
MYSQL_RES* mysql_perform_query(MYSQL *connection, char *sql_query);
void mysql_insert(u_char* domain_str);
void mysql_select_log();
void mysql_block_list(u_char* domain_str, const u_char *packet);
// DB - new
int get_mysql_log_cnt();
void select_block_list();
void *update_block_5m_run();


// sendraw
int sendraw( u_char* pre_packet , int mode ) ;
int print_chars(char print_char, int nums);
void print_payload_right(const u_char *payload, int len);
void print_hex_ascii_line_right(const u_char *payload, int len, int offset);
unsigned short in_cksum ( u_short *addr , int len );



///////////////////////////////////////
//                                   //
// begin MAIN FUNCTION !!!    		 //
//                                   //
///////////////////////////////////////
int main(int argc, char *argv[])
{
	pcap_t *handle;					/* Session handle */
	char *dev;						/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;			/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net;				/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char *packet;			/* The actual packet */
	struct pcap_if *devs;
	int result = 0 ;
	
	/* Define the device */
	pcap_findalldevs(&devs, errbuf);
	printf("INFO: dev name = %s .\n" , (*devs).name );
	dev = (*devs).name ;
	// strcpy(dev, "lo");
	
	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s  (LINE=%d)\n", dev, errbuf, __LINE__);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, TO_MS, errbuf); 	// TO_MS 1000
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s  (LINE=%d)\n", dev, errbuf, __LINE__);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s  (LINE=%d)\n", filter_exp, pcap_geterr(handle), __LINE__);
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s  (LINE=%d)\n", filter_exp, pcap_geterr(handle), __LINE__);
		return(2);
	}
	
	
	
	
	mysql_init(&conn);
	connection = mysql_real_connect(
			&conn,				// mariadb/mysql handler
			"192.168.35.4",		// host address
			"dbuser",				// db id
			"dbuserpass",				// db pass
			"project_db",		// db_name
			3306,				// port
			(char*)NULL,		// unix_socket -> usually NULL
			0					// client_flag -> usually 0
	);
	
	
	if ( connection == NULL ) {
		fprintf ( stderr , "ERROR: mariadb connection error: %s  (LINE=%d)\n", mysql_error(&conn) , __LINE__);
		return 1;
	} else { 
		fprintf ( stdout , "INFO: mariadb connection OK\n" );
	}

	/*-----------------Thread new-----------------*/
	pthread_t update_block_5m;
	int threadErr;
	// thread run 1
	if(threadErr = pthread_create(&update_block_5m,NULL,update_block_5m_run,NULL))
		fprintf(stderr, "ERROR: pthread_create()_5m error !! (LINE=%d) \n",__LINE__);
	
	result = pcap_loop(handle, 0, got_packet, NULL) ;
	if ( result != 0 ) {
		fprintf(stderr, "ERROR: pcap_loop end with error !!!!  (LINE=%d)\n", __LINE__);
	} else {
		fprintf(stdout, "INFO: pcap_loop end without error .\n");
	}
	
	/* And close the session */
	pcap_close(handle);
	return(0);
} // end of main function.

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
	/*------------------ethernet------------------*/
	#define SIZE_ETHERNET 14 /* ethernet headers are always exactly 14 bytes */
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	ethernet = (struct sniff_ethernet*)(packet); // ethernet header
	
	/*---------------------IP---------------------*/
	u_int size_ip;
	const struct sniff_ip *ip;
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < IP_HDR_SIZE)	// IP_HDR_SIZE 20
	{											
		// printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
		
	/*--------------------PORT--------------------*/
	u_int size_tcp;
	const struct sniff_tcp *tcp;
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < TCP_HDR_SIZE) // TCP_HDR_SIZE 20
	{
		// printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
		
	/*-------------------payload------------------*/
	const char *payload; /* Packet payload */
	unsigned short payload_len = 0; // payload
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	payload_len = ntohs(ip->ip_len) - size_ip - size_tcp;
	// printf("payload_len (pre_packet) %u \n", payload_len);
	
	/*-------------------domain-------------------*/
	u_char* domain = NULL;
	u_char* domain_end = NULL;
	u_char domain_str[DOMAIN_BUF] = {0x00};		// DOMAIN_BUF 260
	int domain_len = 0;
	domain = strstr(payload, "Host: ");
	if(domain != NULL){
		domain_end = strstr(domain, "\x0d\x0a");
		if(domain_end != NULL){
			domain_len = domain_end - domain - 6;
			strncpy(domain_str, domain + 6, domain_len);
		}
	}

	/*-----------------print data-----------------*/
	if(domain_len){
		
		// print ehternet, ip, tcp, domain
		print_info(ethernet, ip, tcp, domain_str);
		
		// block_list : compare(domain_str <-> block_list), block or allow
		mysql_block_list(domain_str, packet);
		
		// INSERT to tb_packet_log
		mysql_insert(domain_str);
		
		// SELECT tb_packet_log
		// mysql_select_log();
		
		// fputc('\n',stdout);	
	}	
	
} // end of got_packet function .

unsigned short in_cksum(u_short *addr, int len)
{
        int         sum = 0;
        int         nleft = len;
        u_short     *w = addr;
        u_short     answer = 1;		// return for checksum .
		u_short 	result = 0;		// check for integrity .
		
        while (nleft > 1){
            sum += *w++;
            nleft -= 2;
        }

        if (nleft == 1){
            *( (u_char *)(&answer) ) = *(u_char *)w ;
            sum += answer;
        }
		
        sum = (sum >> 16) + (sum & 0xffff); // hight bit(8 8=16) + low bit(ff ff) .
        sum += (sum >> 16); 				// wrap around -> carry value is too add in sum .
		
        answer = ~sum;

		result = answer + sum  + 1;
		if( result == 0 ) {
			//	fprintf(stdout, "INFO: tcphdr in_cksum() success ! \n");
			return answer;
		} else {
			fprintf(stderr, "ERROR :  tcphdr in_cksum() result is not integrity status !! (LINE=%d) \n",__LINE__);
			return -1;
		}
}
// end in_cksum function .


int sendraw( u_char* pre_packet, int mode)
{
		const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

		u_char packet[1600];
        int IP_HDRINCL_ON=1, len ; // len Later .
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
		struct sockaddr_in address, target_addr; // target_addr later
        int port;
        int pre_payload_size = 0 ;
		u_char *payload = NULL ;
		int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;
		int setsockopt_result = 0 ;
		int prt_sendto_payload = 0 ;
		int warning_page = 1 ;
		int ret = 1 ;							
		int raw_socket, recv_socket;			// recv_socket later .
		
		
		// --------vlan--------
		// int size_vlan = 0 ; 					// excepted because of i think that i don't need this yet .
		// int size_vlan_apply = 0 ; 			// excepted because of i think that i don't need this yet .
		// int vlan_tag_disabled = 0 ;			// excepted because of i think that i don't need this yet .
		
		// --------later--------
		// char recv_packet[100], compare[100]; // later .
        // struct hostent *target; 				// later .
		// int loop1=0; 						// later .
        // int loop2=0; 						// later .
		// int rc = 0 ; 						// later .
		// struct ifreq ifr ; 					// relative ioctl() -> ioctl function is control hardware and analyze hardware status
		// char * if_bind ; 					// later .
		// int if_bind_len = 0 ; 				// later .
		// char* ipaddr_str_ptr ; 				// later .
		
		

		#ifdef SUPPORT_OUTPUT
			printf("\n");
			print_chars('\t',6);
			printf( "[raw socket sendto]\t[start]\n\n" );

			print_chars('\t',6);
			printf("   PRE_PACKET WHOLE(L2_PACKET_DATA) (%d bytes only):\n", 54);
			print_payload_right(pre_packet, 54);
			printf("\n");
		#endif

        for( port=80; port<81; port++ ) {
			// create raw socket
			raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
			if ( raw_socket < 0 ) {
				print_chars('\t',6);
				fprintf(stderr,"Error in socket() creation - %s  (LINE=%d)\n", strerror(errno) , __LINE__);
				fprintf(stderr,"Error in socket() creation - %s  (LINE=%d)\n", strerror(errno) , __LINE__);
				return -2;
			}
		
			// IP_HDRINCL option: include IP_Header .
			setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&IP_HDRINCL_ON, sizeof(IP_HDRINCL_ON)); 

			if ( bind_device_name != NULL ) {
				// i think that ifreq will be use later ( SO_BINDTODEVICE ) .
				setsockopt_result = setsockopt( raw_socket, SOL_SOCKET, SO_BINDTODEVICE, bind_device_name, bind_device_name_len );

				if( setsockopt_result == -1 ) {
					print_chars('\t',6);
					fprintf(stderr,"ERROR: setsockopt() - %s  (LINE=%d)\n", strerror(errno) , __LINE__);
					return -2;
				}
				#ifdef SUPPORT_OUTPUT
				else {
					print_chars('\t',6);
					fprintf(stdout,"OK: setsockopt(%s)(%d) - %s  (LINE=%d)\n", bind_device_name, setsockopt_result, strerror(errno) , __LINE__);
				}
				#endif
			}
			
			// ethernet setting in pre_packet without vlan
			ethernet = (struct sniff_ethernet*)(pre_packet);
			if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) {
				#ifdef SUPPORT_OUTPUT
				print_chars('\t',6);
				printf("NORMAL PACKET");
				#endif
			} else {
				fprintf(stderr,"NOTICE: ether_type is not IPv4, so you prepare other ether_types .......... \n");
			}

			// TCP, IP reset header without vlan
			iphdr = (struct iphdr *)(packet) ;
			memset( iphdr, 0, 20 );
			tcphdr = (struct tcphdr *)(packet + 20);
			memset( tcphdr, 0, 20 );

			// twist s and d address
			source_address.s_addr = ((struct iphdr *)(pre_packet + 14))->daddr ;
			dest_address.s_addr = ((struct iphdr *)(pre_packet + 14))->saddr ;		// for return response
          
			iphdr->id = ((struct iphdr *)(pre_packet + 14))->id ;// identification field in ip_header
			
			int pre_tcp_header_size = 0;
			// char pre_tcp_header_size_char = 0x0; 	// Later
			pre_tcp_header_size = ((struct tcphdr *)(pre_packet + 14 + 20))->doff ;
			pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + 14))->tot_len ) - ( 20 + pre_tcp_header_size * 4 ) ;

			// TCP header setting
			tcphdr->source = ((struct tcphdr *)(pre_packet + 14 + 20))->dest ;// src_port field in tcp_header
			tcphdr->dest = ((struct tcphdr *)(pre_packet + 14 + 20))->source ;// dst_port field in tcp_header
			tcphdr->seq = ((struct tcphdr *)(pre_packet + 14 + 20))->ack_seq ;// SEQ num field in tcp_header
			tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + 14 + 20))->seq  + htonl(pre_payload_size - 20)  ;// ACK num field in tcp_header
			tcphdr->window = ((struct tcphdr *)(pre_packet + 14 + 20))->window ;// window field in tcp_header
			tcphdr->doff = 5;// offset field in tcp_header
			tcphdr->ack = 1;// tcp_flag field in tcp_header
			tcphdr->psh = 1;// tcp_flag field in tcp_header
			tcphdr->fin = 1;// tcp_flag field in tcp_header
			
			// created pseudo_header for calculate TCP checksum ( total = 12bytes )
			pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
			pseudo_header->saddr = source_address.s_addr;// TTL,Protocol,Checksum field in ip_header(strange value)
			pseudo_header->daddr = dest_address.s_addr;// src_ip field in ip_header(not change value)
			pseudo_header->useless = (u_int8_t) 0;// reserved field in tcp_header
			pseudo_header->protocol = IPPROTO_TCP;// dst_ip field in ip_header(strange value)
			pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);// dst_ip field in ip_header(strange value)


			char *fake_packet = 
						"HTTP/1.1 200 OK\x0d\x0a"
						"Content-Length: 530\x0d\x0a"
						"Content-Type: text/html"
						"\x0d\x0a\x0d\x0a"
						"<html>\r\n"
						"<head>\r\n"
						"<meta charset=\"UTF-8\">\r\n"
						"<title>\r\n"
						"CroCheck - WARNING - PAGE\r\n"
						"SITE BLOCKED - WARNING - \r\n"
						"</title>\r\n"
						"</head>\r\n"
						"<body>\r\n"
						"<center>\r\n"
						"<img   src=\"http://127.0.0.1/warning.jpg\" alter=\"*WARNING*\">\r\n"
						"<h1>SITE BLOCKED</h1>\r\n"
						"</center>\r\n"
						"</body>\r\n"
						"</html>\r\n"
						;
			
			post_payload_size = strlen(fake_packet);
			
			// choose output content
			warning_page = 5; // for test redirecting
			if ( warning_page == 5 ){
				memcpy ( (char*)packet + 40, fake_packet , post_payload_size ) ;
			}
			
			// renewal after post_payload_size for calculate TCP checksum
			pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

			// calculate TCP header checksum
			tcphdr->check = in_cksum( (u_short *)pseudo_header,
			               sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);// checksum field in tcp_header

			
			// line
			print_chars('\t',6);
			
			// IP header setting
			iphdr->version = 4;// version field in ip_header
			iphdr->ihl = 5;// IHL field in ip_header
			iphdr->protocol = IPPROTO_TCP;// protocol field in ip_header(reset)
			iphdr->tot_len = htons(40 + post_payload_size);// total length field in ip_header
			iphdr->id = ((struct iphdr *)(pre_packet + 14))->id + htons(1);//identification field in ip_header(increase 1)
			
			// 0x40 -> don't use flag
			memset( (char*)iphdr + 6 ,  0x40  , 1 );// IP_flags field in ip_header
			iphdr->ttl = 60;// TTL field in ip_header(reset)
			iphdr->saddr = source_address.s_addr;// src_ip field in ip_header(change value)
			iphdr->daddr = dest_address.s_addr;// dst_ip field in ip_header(change value)
			
			// calculate IP header checksum
			iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));// checksum field in ip_header(reset)
			
			// for sendto
			address.sin_family = AF_INET;
			address.sin_port = tcphdr->dest ;
			address.sin_addr.s_addr = dest_address.s_addr;

			prt_sendto_payload = 1 ;
		
			if( prt_sendto_payload == 1 ) {

				#ifdef SUPPORT_OUTPUT
				printf("\n\n");
				print_chars('\t',6);
				printf("----------------sendto Packet data----------------\n");

				print_chars('\t',6);
				printf("    From: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( source_address ),
								((char*)&source_address.s_addr)[0],
								((char*)&source_address.s_addr)[1],
								((char*)&source_address.s_addr)[2],
								((char*)&source_address.s_addr)[3]
						);
				print_chars('\t',6);
				printf("      To: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( dest_address ),
								((char*)&dest_address.s_addr)[0],
								((char*)&dest_address.s_addr)[1],
								((char*)&dest_address.s_addr)[2],
								((char*)&dest_address.s_addr)[3]
						);

				switch(iphdr->protocol) {
					case IPPROTO_TCP:
						print_chars('\t',6);
						printf("Protocol: TCP\n");
						break;
					case IPPROTO_UDP:
						print_chars('\t',6);
						printf("Protocol: UDP\n");
						return -1;
					case IPPROTO_ICMP:
						print_chars('\t',6);
						printf("Protocol: ICMP\n");
						return -1;
					case IPPROTO_IP:
						print_chars('\t',6);
						printf("Protocol: IP\n");
						return -1;
					case IPPROTO_IGMP:
						print_chars('\t',6);
						printf("Protocol: IGMP\n");
						return -1;
					default:
						print_chars('\t',6);
						printf("Protocol: unknown\n");
						return -2;
				}

				print_chars('\t',6);
				printf("Src port: %d\n", ntohs(tcphdr->source));
				print_chars('\t',6);
				printf("Dst port: %d\n", ntohs(tcphdr->dest));
				
				#endif

				payload = (u_char *)(packet + sizeof(struct iphdr) + tcphdr->doff * 4 );

				size_payload = ntohs(iphdr->tot_len) - ( sizeof(struct iphdr) + tcphdr->doff * 4 );
				
				#ifdef SUPPORT_OUTPUT
				if (size_payload > 0) {
					printf("\n");
					print_chars('\t',6);
					printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload); // 40
					print_payload_right((const u_char*)&packet, ntohs(iphdr->tot_len) - size_payload);
				}

				if (size_payload > 0) {
					printf("\n");
					print_chars('\t',6);
					printf("   Payload (%d bytes):\n", size_payload);
					print_payload_right(payload, size_payload);
				}
				#endif
				
			} // end -- if -- prt_sendto_payload = 1 ;
			
			if ( mode == 1 ) {
				sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
										(struct sockaddr *)&address, sizeof(address) ) ;
				if ( sendto_result != ntohs(iphdr->tot_len) ) {
					fprintf ( stderr,"ERROR: sendto() - %s  (LINE=%d)\n", strerror(errno) , __LINE__) ;
					ret = -2;
				} else {
					// fprintf ( stdout,"INFO: sendto() success ! \n");
					ret = 0;
				}
			} // end if(mode)


			if ( (unsigned int)iphdr->daddr == (unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" ) {
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf("##########################################################################################################################\n");
				printf( "address1 == %hhu.%hhu.%hhu.%hhu\taddress2 == %X\taddress3 == %X\n",
						*(char*)((char*)&source_address.s_addr + 0),*(char*)((char*)&source_address.s_addr + 1),
						*(char*)((char*)&source_address.s_addr + 2),*(char*)((char*)&source_address.s_addr + 3),
						source_address.s_addr,	(unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" );
			}
			
			close( raw_socket );
        } // end for loop
		
		#ifdef SUPPORT_OUTPUT
		printf("\n");
		print_chars('\t',6);
        printf( "[sendraw] end . \n\n" );
		#endif
	
		
		return ret; // 0 -> normal exit
}
// end sendraw function .


int print_chars(char print_char, int nums)
{
	int i = 0;
	for ( i ; i < nums ; i++) {
		printf("%c",print_char);
	}
	return i;
}


void
print_hex_ascii_line_right(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;
	int tabs_cnt = 6 ;  // default at now , afterward receive from function caller

	/* print 10 tabs for output to right area	*/
	for ( i = 0 ; i < tabs_cnt ; i++ ) {
		printf("\t");
	}

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload_right(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;


	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line_right(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line_right(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line_right(ch, len_rem, offset);
			break;
		}
		//m-debug
		if ( offset > 600 ) {
			print_chars('\t',6);
			printf("INFO: ..........    payload too long (print_payload_right func) \n");
			break;
		}
	}
    return;
}


void mysql_block_list(u_char* domain_str, const u_char *packet) {
		
		// printf("block list start\n");
		cmp_ret = 1; // reset ( for delete block_list ) .
		// compare---------------------------------
		for(int i = 0; i < block_domain_count; i++ ) {

			// if you knew str_len, you choice method like this
			int str1_len = strlen( &block_domain_arr[i][0] ); // block list
			int str2_len = strlen( domain_str );		// domain_string
<<<<<<< HEAD
			printf("domain domain :  %s \n", domain_str);
			printf("block domain :  %s \n", &block_domain_arr[i][0]);
=======
>>>>>>> 07bb9222c352ef32bfd8e15dbf0de8929734041b
			// printf("block : %s \n",&block_domain_arr[i][0]);
			// break different value each other and
			if( str1_len != str2_len && str1_len != 0 ) {
				continue; // move to next array .
			}
			printf("block -> %s \n", &block_domain_arr[i][0]);
			cmp_ret = strcmp( &block_domain_arr[i][0], domain_str );

			if( cmp_ret == 0 )
				break;
		} 

		// block or allow
		if( cmp_ret == 0 ) {
			// printf("DEBUG: domain blocked . \n");
			int sendraw_ret = sendraw(packet , sendraw_mode);
			if ( sendraw_ret != 0 ) {
				fprintf(stderr, "ERROR: emerge in sendraw() !!! (LINE=%d) \n",__LINE__);
			}
		} else {
			// printf("DEBUG: domain allowed . \n");
			cmp_ret = 1; // new show allow 
		} // end if emp_ret .
} // end of mysql_block_list() .

MYSQL_RES* mysql_perform_query(MYSQL *connection, char *sql_query) {
 
	sleep(3); // delay for error
    if(mysql_query(connection, sql_query)) {
        printf("MYSQL query error : %s (LINE=%d) \n",mysql_error(connection), __LINE__);
        exit(1);
    }
    return mysql_use_result(connection);
} // end of mysql_perform_query() .

void mysql_insert(u_char* domain_str)
{
	// INSERT
	char query[DOMAIN_BUF] = { 0x00}; // DOMAIN_BUF 260
	
	// analyze log_cnt value
	if( get_mysql_log_cnt() >= 50 ) {
		mysql_query(connection, "DELETE FROM tb_packet_log ORDER BY created_at ASC LIMIT 1");
	} 
	

	if (  !strcmp(IPbuffer2_str,"192.168.111.150") ) {
		// query setting
		sprintf(query,"INSERT INTO tb_packet_log ( src_ip , src_port , dst_ip , dst_port , domain , result )"
				  "VALUES('%s', '%u', '%s' , '%u' , '%s' , '%d')",
				  IPbuffer_str , 
				  tcp_src_port , 
				  IPbuffer2_str , 
				  tcp_dst_port ,  
				  domain_str , 
				  cmp_ret
				  );

		if( mysql_query(connection, query) != 0 ) {
		fprintf(stderr, "ERROR : mysql_query() is failed !!!  (LINE=%d)\n", __LINE__);
		} else {
			// printf("mysql_query() success :D \n");
		}
	} else {
		printf("connect another server ! ");
	}
} // end of mysql_insert() .


void mysql_select_log()
{
	char query[DOMAIN_BUF] = { 0x00 }; // DOMAIN_BUF 260
	sprintf(query, "SELECT * FROM tb_packet_log");
	
	res = mysql_perform_query(connection, query);

	printf("\n");
	int cnt = 1;
	
	while( (row_check = mysql_fetch_row(res) ) != NULL){
		printf("Mysql contents in tb_packet_log [ row : %d | ID : %s ] \n", cnt++, row[0]);
		printf(" src_ip: %20s | ", row[1]); 
		printf(" src_port: %5s | \n", row[2]);
		printf(" dst_ip: %20s | ", row[3]);
		printf(" dst_port: %5s | \n", row[4]);
		printf(" Domain: %20s | ", row[5]);
		printf(" result: %7s | ", row[6]);
		printf(" created at: %s . \n\n\n", row[7]);
	}
	printf("\n");
	mysql_free_result(res);
} // end of mysql_select_log() .


void print_info(const struct sniff_ethernet *ethernet, 
				const struct sniff_ip *ip, 
				const struct sniff_tcp *tcp,
				u_char* domain_str)
{

	#ifdef SUPPORT_OUTPUT
	// print ethernet
	printf("DATA: dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
		ethernet->ether_dhost[0],
		ethernet->ether_dhost[1],
		ethernet->ether_dhost[2],
		ethernet->ether_dhost[3],
		ethernet->ether_dhost[4],
		ethernet->ether_dhost[5]
	);
	printf("DATA: src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
		ethernet->ether_shost[0],
		ethernet->ether_shost[1],
		ethernet->ether_shost[2],
		ethernet->ether_shost[3],
		ethernet->ether_shost[4],
		ethernet->ether_shost[5]
	);
	#endif

	// print ip
	char *IPbuffer, *IPbuffer2;

	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);
	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);
	
	#ifdef SUPPORT_OUTPUT
	printf("DATA: IP src : %s\n",IPbuffer_str);
	printf("DATA: IP dst : %s\n",IPbuffer2_str);
	#endif
	
	// print port
	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);
	
	#ifdef SUPPORT_OUTPUT
	printf("DATA: src Port : %u\n", tcp_src_port);
	printf("DATA: dst Port : %u\n", tcp_dst_port);	
	
	
	// print domain
	printf("INFO: Domain = %s\n", domain_str);
	#endif
}


int get_mysql_log_cnt()
{
	char query[DOMAIN_BUF] = { 0x00 }; // DOMAIN_BUF 260
	log_cnt = 0;
	sprintf(query, "SELECT * FROM tb_packet_log");	
	res_cnt = mysql_perform_query(connection, query);
	while( (row_cnt = mysql_fetch_row(res_cnt) ) != NULL) {
		log_cnt++;
	}
	mysql_free_result(res_cnt);
	return log_cnt;
} // end of mysql_select_log() .


void *update_block_5m_run()
{
    while(1)
    {
		select_block_list();
        sleep(10); // per seconds ( test 3seconds 	)
	}
} // end of update_block_5m_run() .


int test = 0;

void select_block_list() {
	// printf("select block list start\n");
	// Receive tb_packet_block---------------------------------
	res_block = mysql_perform_query(connection, "SELECT * FROM tb_packet_block");

	block_domain_count = 0;
	// printf(test++);
	while( (row_block = mysql_fetch_row(res_block) ) != NULL){
			// printf("Mysql block_list in tb_packet_block [ row : %d | ID : %s ] \n", block_domain_count, row_block[0]);
			// printf("src_ip: %20s | ", row_block[1]); 			
			// printf("src_port: %5s | \n", row_block[2]);
			// printf("dst_ip: %20s | ", row_block[3]);
			// printf("dst_port: %5s | \n", row_block[4]);
			// printf("Domain: %20s | ", row_block[5]);
			// printf("created at: %s . \n\n\n", row_block[6]); 	// doesn't exist result in block_list
			strcpy( &block_domain_arr[block_domain_count++][0], row_block[5]);	// string copy for compare
		}
}
