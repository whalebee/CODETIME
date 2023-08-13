//와 개쩐다
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
// for mariadb
#include <mariadb/mysql.h>
// for pcap
#include <pcap.h>
// for sendrow
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <math.h>
//#include <netdb.h>


#define ETHER_ADDR_LEN 6
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct sniff_ip {
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;

#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	
	struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip)	(( (ip)->ip_vhl ) & 0x0f)
#define IP_V(ip)	(( (ip)->ip_vhl ) >> 4)


typedef u_int tcp_seq;
struct sniff_tcp {
	u_short th_dport;
	u_short th_sport;
	tcp_seq th_seq;
	tcp_seq th_ack;

	u_char th_offx2;
#define TH_OFF(tcp)	(( (tcp)->th_offx2 & 0xf0) >> 4 )
	u_char th_flags;

	
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CRW 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CRW)

	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

// global variables
MYSQL *connection = NULL;
MYSQL conn;
MYSQL_RES *sql_result;
MYSQL_ROW sql_row;

struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};

// setsockopt 4,5번째 인자로 던져줄 변수들
//char if_bind_global[] = "enp0s3" ;
char if_bind_global[] = "lo" ;
//int if_bind_global_len = 6 ;
int if_bind_global_len = 2 ;


int sendraw_mode = 1; //차단패킷 보내고 안보내고 결정
#define SUPPORT_OUTPUT

// sendraw 관련 함수
int print_chars(char print_char, int nums);
void print_payload(const u_char *payload, int len);
void print_payload_right(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_hex_ascii_line_right(const u_char *payload, int len, int offset);
unsigned short in_cksum ( u_short *addr , int len );
int sendraw( u_char* pre_packet , int mode ) ;

// got_packet 관련 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char* packet);
void print_ethernet(const struct sniff_ethernet *ethernet);
void print_IP(const struct sniff_ip *ip, char *IPbuffer_str, char *IPbuffer2_str);
void print_PORT(const struct sniff_tcp *tcp, unsigned short *tcp_src_port, unsigned short *tcp_dst_port);
void print_domain(u_char* domain_str);
void transfer_from_db(u_char *domain_str, int *cmp_ret);
void transfer_to_db(char *IPbuffer_str, unsigned short *tcp_src_port, char *IPbuffer2_str, unsigned short *tcp_dst_port, u_char* domain_str, int *cmp_ret);


int main( int argc, char *argv[])
{

	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle;

	bpf_u_int32 net;
	bpf_u_int32 mask;

	struct bpf_program fp;
	char filter_exp[] = "port 80";

	struct pcap_pkthdr header;
	const u_char *packet;
	struct pcap_if *devs;

	pcap_findalldevs(&devs, errbuf);
	printf("INFO: dev name = %s\n" , (*devs).name );
	dev = (*devs).name ;

	if( pcap_lookupnet(dev, &net, &mask, errbuf) == -1 ) {
		fprintf(stderr, "could not get netmask for device %s : %s \n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if( handle == NULL ) {
		fprintf(stderr, "could not open device %s : %s \n", dev, errbuf);
		return 2;
	}

	if( pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ) {
		fprintf(stderr, "could not parse filter %s : %s \n", filter_exp, pcap_geterr(handle));
		return 2;
	}

	if( pcap_setfilter(handle, &fp) == -1 ) {
		fprintf(stderr, "could not install filter %s : %s \n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	
	/*----------------sql_connect----------------*/
	mysql_init(&conn);
	connection = mysql_real_connect(
			&conn,			// mariadb/mysql handler
			"localhost",	// host address
			"dbuser",		// db id
			"dbuserpass",	// db pass
			"project_db",	// db_name
			3306,			// port
			(char*)NULL,	
			0			
	);
	
	if (connection == NULL) {
		fprintf ( stderr , "ERROR: mariadb connection error: %s\n", mysql_error(&conn));
		return 1;
	} else { 
		fprintf ( stdout , "INFO: mariadb connection OK\n" );
	}

	int result = 0;
	result = pcap_loop(handle, 0, got_packet, NULL);
	if( result != 0 ) {
		fprintf(stderr,"ERROR : pcap_loop() end with error !!! \n");
	} else {
		fprintf(stdout,"INFO : pcap_loop() end without error \n");
	}

	pcap_close(handle);

	return 0;
} // end of main() .


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/*------------------argument------------------*/
	char IPbuffer_str[16];
	char IPbuffer2_str[16];
	unsigned short tcp_src_port = 0;
	unsigned short tcp_dst_port = 0;
	int cmp_ret = 0;
		
	/*------------------ethernet------------------*/
	#define SIZE_ETHERNET 14 /* ethernet headers are always exactly 14 bytes */
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	ethernet = (struct sniff_ethernet*)(packet); // ethernet header
	
	/*---------------------IP---------------------*/
	u_int size_ip;
	const struct sniff_ip *ip; /* The IP header */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET); // IP header
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
		
	/*--------------------PORT--------------------*/
	u_int size_tcp;
	const struct sniff_tcp *tcp; /* The TCP header */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip); // TCP header
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
		
	/*-------------------payload------------------*/
	const char *payload; /* Packet payload */
	unsigned short payload_len = 0; // payload
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	payload_len = ntohs(ip->ip_len) - size_ip - size_tcp;
	
	/*-------------------domain-------------------*/
	u_char* domain = NULL;
	u_char* domain_end = NULL;
	u_char domain_str[256] = {0x00};
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
		print_ethernet(ethernet);
		print_IP(ip, IPbuffer_str, IPbuffer2_str);
		print_PORT(tcp, &tcp_src_port, &tcp_dst_port);
		print_domain(domain_str);
		
		transfer_from_db(domain_str, &cmp_ret);
					    	
		if(cmp_ret){ //check domain blocked/allowed
			printf("DEBUG: domain allowed.\n");
		}
		else {
			printf("DEBUG: domain blocked.\n");
			int sendraw_ret = sendraw(packet , sendraw_mode);
		}
		
		transfer_to_db(IPbuffer_str, &tcp_src_port, IPbuffer2_str, &tcp_dst_port, domain_str, &cmp_ret);
		
		fputc('\n',stdout);	
	}
}
// end of got_pakcet function.

void print_ethernet(const struct sniff_ethernet *ethernet){
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
}

void print_IP(const struct sniff_ip *ip, char *IPbuffer_str, char *IPbuffer2_str){
	char *IPbuffer, *IPbuffer2;

	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);
	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);
	
	printf("DATA: IP src : %s\n",IPbuffer_str);
	printf("DATA: IP dst : %s\n",IPbuffer2_str);
}

void print_PORT(const struct sniff_tcp *tcp, unsigned short *tcp_src_port, unsigned short *tcp_dst_port){
	*tcp_src_port = ntohs(tcp->th_sport);
	*tcp_dst_port = ntohs(tcp->th_dport);
	
	printf("DATA: src Port : %u\n", *tcp_src_port);
	printf("DATA: dst Port : %u\n", *tcp_dst_port);	
}

void print_domain(u_char* domain_str){
	printf("INFO: Domain = %s\n", domain_str);
}

void transfer_from_db(u_char *domain_str,int *cmp_ret){
	int str_len1= 0; // block_IP 길이
	int str_len2= 0; // 접속한 도메인 길이
	int query_stat = 0;
	
	str_len2 = strlen(domain_str);
	
	query_stat = mysql_query(connection,"SELECT domain FROM tb_packet_block");
	if (query_stat != 0) {
		fprintf ( stderr , "ERROR: mariadb SELECT error: %s\n", mysql_error(&conn) );
		return;
	} else {
		fprintf ( stdout , "INFO: mariadb SELECT OK\n" );
	}
	
	sql_result = mysql_store_result(connection); 
	if(sql_result == NULL) fprintf (stderr , "ERROR: mariadb sql_result error: %s\n", mysql_error(&conn));
	else{
		fprintf ( stdout , "INFO: mariadb sql_result OK\n" );
		*cmp_ret = 1;
		while(sql_row = mysql_fetch_row(sql_result)){
			str_len1 = strlen(sql_row[0]);
			if(str_len1 != str_len2) continue;
			*cmp_ret = strcmp(sql_row[0],domain_str);
			if(*cmp_ret == 0) break;
		}
	}
}

void transfer_to_db(char *IPbuffer_str, unsigned short *tcp_src_port, char *IPbuffer2_str, unsigned short *tcp_dst_port, u_char* domain_str, int *cmp_ret){
	int query_stat = 0;
	char query_str[1024] = { 0x00 };
	sprintf(query_str , "INSERT INTO tb_packet_log ( src_ip , src_port , dst_ip , dst_port , domain , result )"
						"VALUES ( '%s' , %u , '%s' , %u , '%s' , %d )" ,
						IPbuffer_str, 	// src_ip
						*tcp_src_port,	// src_port
						IPbuffer2_str,	// dst_ip
						*tcp_dst_port,	// dst_port
						domain_str,		// domain
						*cmp_ret			// result
						);
	query_stat = mysql_query( connection , query_str );
	if (query_stat != 0) {
		fprintf ( stderr , "ERROR: mariadb INSERT error: %s\n", mysql_error(&conn) );
		return;
	} else {
		fprintf ( stdout , "INFO: mariadb INSERT OK\n" );
	}
	
	//mysql_free_result(sql_result);
	//mysql_close(connection);
}

unsigned short in_cksum(u_short *addr, int len) //checksum 계산함수
{
        int         sum=0;
        int         nleft=len;
        u_short     *w=addr;
        u_short     answer=0;
        while (nleft > 1){
            sum += *w++;
            nleft -= 2;
        }

        if (nleft == 1){
            *(u_char *)(&answer) = *(u_char *)w ;
            sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return(answer);
}
// end in_cksum function .


int sendraw( u_char* pre_packet, int mode) 
{
		const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

		u_char packet[1600];
        int raw_socket, recv_socket;
        int on=1, len ;
        char recv_packet[100], compare[100];
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct sockaddr_in address, target_addr;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
        struct hostent *target;
        int port;
        int loop1=0;
        int loop2=0;
        int pre_payload_size = 0 ;
		u_char *payload = NULL ;
		int size_vlan = 0 ;
		int size_vlan_apply = 0 ;
		int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;
	    int rc = 0 ;
	    //struct ifreq ifr ;
		char * if_bind ;
		int if_bind_len = 0 ;
		int setsockopt_result = 0 ;
		int prt_sendto_payload = 0 ;
		char* ipaddr_str_ptr ;

		int warning_page = 1 ;
		int vlan_tag_disabled = 0 ;

		int ret = 0 ;

		#ifdef SUPPORT_OUTPUT //def 조건문
		print_chars('\t',6); // 출력할때 공백추가 역할
		printf( "\n[raw socket sendto]\t[start]\n\n" );

		/*int print_chars(char print_char, int nums)
		{
			int i = 0;
			for ( i ; i < nums ; i++) {
				printf("%c",print_char);
			}
			return i;
		}*/


		if (size_payload > 0 || 1) { // curl로 접속 시도한 패킷(pre_packet->매개변수 확인)을 출력
			print_chars('\t',6);
			printf("   pre_packet whole(L2-packet-data) (%d bytes only):\n", 100);
			print_payload_right(pre_packet, 100); //상위 100개 바이트에 대해서만 출력
		}
		//m-debug
		printf("DEBUG: (u_char*)packet_dmp ( in sendraw func ) == 0x%p\n", pre_packet);
		#endif
	
		// 소켓 관련 코드 시작
        for( port=80; port<81; port++ ) { // 조건을 굳이 왜이렇게 쓰는가
			#ifdef SUPPORT_OUTPUT
			print_chars('\t',6);
			printf("onetime\n");
			#endif
			// raw socket 생성
			raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
			if ( raw_socket < 0 ) {
				print_chars('\t',6);
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				return -2;
			}

			setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

			if ( if_bind_global != NULL ) {
				setsockopt_result = setsockopt( raw_socket, SOL_SOCKET, SO_BINDTODEVICE, if_bind_global, if_bind_global_len );
				//if_bind_global, if_bind_global_len -> 전역변수쪽 확인
				if( setsockopt_result == -1 ) {
					print_chars('\t',6);
					fprintf(stderr,"ERROR: setsockopt() - %s\n", strerror(errno));
					return -2;
				}
				#ifdef SUPPORT_OUTPUT
				else {
					print_chars('\t',6);
					fprintf(stdout,"OK: setsockopt(%s)(%d) - %s\n", if_bind_global, setsockopt_result, strerror(errno));
				}
				#endif

			}
			// 소켓 관련 코드 끝

			// 요청하는 쪽이 vlan인지 normal인지 판단 (보내는 패킷에서 확인)
			ethernet = (struct sniff_ethernet*)(pre_packet);
			if ( ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x81\x00" ) { //vlan 패킷 일 경우
				#ifdef SUPPORT_OUTPUT
				printf("vlan packet\n");
				#endif
				size_vlan = 4;
				memcpy(packet, pre_packet, size_vlan);
				vlan_tag_disabled = 1;
			} else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) { //normal 패킷 일 경우
				#ifdef SUPPORT_OUTPUT
				printf("normal packet\n");
				#endif
				size_vlan = 0;
			} else {
				fprintf(stderr,"NOTICE: ether_type diagnostics failed .......... \n");
			}
			
			// 판단 후 초기화
			if ( vlan_tag_disabled == 1 ) {
				size_vlan_apply = 0 ;
				memset (packet, 0x00, 4) ;
			} else {
				size_vlan_apply = size_vlan ;
			}
			// 접속시도한 서버에서 받은 패킷이 vlan인지 normal인지 판단
			
                // TCP, IP 헤더 초기화
                iphdr = (struct iphdr *)(packet + size_vlan_apply) ;
                memset( iphdr, 0, 20 );
                tcphdr = (struct tcphdr *)(packet + size_vlan_apply + 20);
                memset( tcphdr, 0, 20 );

				#ifdef SUPPORT_OUTPUT
                // TCP 헤더 제작
                tcphdr->source = htons( 777 );
                tcphdr->dest = htons( port );
                tcphdr->seq = htonl( 92929292 );
                tcphdr->ack_seq = htonl( 12121212 );
				#endif

				source_address.s_addr = 
				((struct iphdr *)(pre_packet + size_vlan + 14))->daddr ;
				// twist s and d address
				dest_address.s_addr = ((struct iphdr *)(pre_packet + size_vlan + 14))->saddr ;		// for return response
				iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id ;
				int pre_tcp_header_size = 0;
				char pre_tcp_header_size_char = 0x0;
				pre_tcp_header_size = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->doff ;
				pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + size_vlan + 14))->tot_len ) - ( 20 + pre_tcp_header_size * 4 ) ;

				tcphdr->source = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->dest ;		// twist s and d port
				tcphdr->dest = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->source ;		// for return response
				tcphdr->seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->ack_seq ;
				tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->seq  + htonl(pre_payload_size - 20)  ;
				tcphdr->window = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->window ;

                tcphdr->doff = 5;

                tcphdr->ack = 1;
                tcphdr->psh = 1;

                tcphdr->fin = 1;
                /*// 가상 헤더 생성.
                pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
                pseudo_header->saddr = source_address.s_addr;
                pseudo_header->daddr = dest_address.s_addr;
                pseudo_header->useless = (u_int8_t) 0;
                pseudo_header->protocol = IPPROTO_TCP;
                pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

				#ifdef SUPPORT_OUTPUT
				// m-debug
				printf("DEBUG: &packet == \t\t %p \n" , &packet);
				printf("DEBUG: pseudo_header == \t %p \n" , pseudo_header);
				printf("DEBUG: iphdr == \t\t %p \n" , iphdr);
				printf("DEBUG: tcphdr == \t\t %p \n" , tcphdr);
				#endif

				#ifdef SUPPORT_OUTPUT
                strcpy( (char*)packet + 40, "HAHAHAHAHOHOHOHO\x0" );
				#endif*/

				// choose output content
				warning_page = 5;
				if ( warning_page == 5 ){
					// write post_payload ( redirecting data 2 )
					//post_payload_size = 201 + 67  ;   // Content-Length: header is changed so post_payload_size is increased.
					post_payload_size = 230 + 65  ;   // Content-Length: header is changed so post_payload_size is increased.
                    //memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK" + 0x0d0a + "Content-Length: 1" + 0x0d0a + "Content-Type: text/plain" + 0x0d0a0d0a + "a" , post_payload_size ) ;
					memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK\x0d\x0a"
							"Content-Length: 230\x0d\x0a"
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
		"<img   src=\"http://127.0.0.1:3000/warning.jpg\" alter=\"*WARNING*\">\r\n"
        "<h1>SITE BLOCKED</h1>\r\n"
							"</center>\r\n"
							"</body>\r\n"
							"</html>", post_payload_size ) ;
                }
				pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

                tcphdr->check = in_cksum( (u_short *)pseudo_header,
                                sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);

                iphdr->version = 4;
                iphdr->ihl = 5;
                iphdr->protocol = IPPROTO_TCP;
                //iphdr->tot_len = 40;
                iphdr->tot_len = htons(40 + post_payload_size);

				#ifdef SUPPORT_OUTPUT
				//m-debug
				printf("DEBUG: iphdr->tot_len = %d\n", ntohs(iphdr->tot_len));
				#endif

				iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id + htons(1);
				
				memset( (char*)iphdr + 6 ,  0x40  , 1 );
				
                iphdr->ttl = 60;
                iphdr->saddr = source_address.s_addr;
                iphdr->daddr = dest_address.s_addr;
                // IP 체크섬 계산.
                iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));

                address.sin_family = AF_INET;

				address.sin_port = tcphdr->dest ;
				address.sin_addr.s_addr = dest_address.s_addr;

				prt_sendto_payload = 0;
				#ifdef SUPPORT_OUTPUT
				prt_sendto_payload = 1 ;
				#endif

				if( prt_sendto_payload == 1 ) {

				print_chars('\t',6);
				printf("sendto Packet data :\n");

				print_chars('\t',6);
				printf("       From: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( source_address ),
								((char*)&source_address.s_addr)[0],
								((char*)&source_address.s_addr)[1],
								((char*)&source_address.s_addr)[2],
								((char*)&source_address.s_addr)[3]
						);
				print_chars('\t',6);
				printf("         To: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( dest_address ),
								((char*)&dest_address.s_addr)[0],
								((char*)&dest_address.s_addr)[1],
								((char*)&dest_address.s_addr)[2],
								((char*)&dest_address.s_addr)[3]
						);

				switch(iphdr->protocol) {
					case IPPROTO_TCP:
						print_chars('\t',6);
						printf("   Protocol: TCP\n");
						break;
					case IPPROTO_UDP:
						print_chars('\t',6);
						printf("   Protocol: UDP\n");
						return -1;
					case IPPROTO_ICMP:
						print_chars('\t',6);
						printf("   Protocol: ICMP\n");
						return -1;
					case IPPROTO_IP:
						print_chars('\t',6);
						printf("   Protocol: IP\n");
						return -1;
					case IPPROTO_IGMP:
						print_chars('\t',6);
						printf("   Protocol: IGMP\n");
						return -1;
					default:
						print_chars('\t',6);
						printf("   Protocol: unknown\n");
						//free(packet_dmp);
						return -2;
				}

				print_chars('\t',6);
				printf("   Src port: %d\n", ntohs(tcphdr->source));
				print_chars('\t',6);
				printf("   Dst port: %d\n", ntohs(tcphdr->dest));

				payload = (u_char *)(packet + sizeof(struct iphdr) + tcphdr->doff * 4 );

				size_payload = ntohs(iphdr->tot_len) - ( sizeof(struct iphdr) + tcphdr->doff * 4 );

				printf("DEBUG: sizeof(struct iphdr) == %lu \t , \t tcphdr->doff * 4 == %hu \n",
								sizeof(struct iphdr) , tcphdr->doff * 4);

				if (size_payload > 0 || 1) {
					print_chars('\t',6);
					printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload);
					//print_payload(payload, size_payload);
					print_payload_right((const u_char*)&packet, ntohs(iphdr->tot_len) - size_payload);
				}

				if (size_payload > 0 || 1) {
					print_chars('\t',6);
					printf("   PACKET-HEADER(try2) (%d bytes):\n", 40);
					//print_payload(payload, size_payload);
					print_payload_right((const u_char*)&packet, 40);
				}

				if (size_payload > 0) {
					print_chars('\t',6);
					printf("   Payload (%d bytes):\n", size_payload);
					//print_payload(payload, size_payload);
					print_payload_right(payload, size_payload);
				}
			} // end -- if -- prt_sendto_payload = 1 ;
				if ( mode == 1 ) {
                    sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
                                            (struct sockaddr *)&address, sizeof(address) ) ;
					if ( sendto_result != ntohs(iphdr->tot_len) ) {
						fprintf ( stderr,"ERROR: sendto() - %s\n", strerror(errno) ) ;
						ret = -10 ;
					} else {
						ret = 1 ;
					}
		        } // end if(mode)
                //} // end for loop

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
        printf( "\n[sendraw] end .. \n\n" );
		#endif
		//return 0;
		return ret ;
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

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset); //패킷의 제일 앞 5자리

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);  //패킷의 제일 앞 5자리 뒤 한바이트(두자리)씩 출력
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7) //i = 0부터 시작해서 7까지 총 8개 출력했을때 공백 추가
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

void print_hex_ascii_line_right(const u_char *payload, int len, int offset)
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
void print_payload(const u_char *payload, int len)
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
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}


/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload_right(const u_char *payload, int len)
{

	int len_rem = len; //몇바이트를 출력할건지
	int line_width = 16; //16바이트 단위로->한줄에 16바이트만큼씩 출력	/* number of bytes per line */
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