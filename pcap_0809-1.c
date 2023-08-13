#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <mariadb/mysql.h>

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

// global variables .
MYSQL *connection = NULL;
MYSQL conn;
MYSQL_RES *sql_result;
MYSQL_ROW sql_row;

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
	printf("INFO: dev name = %s .\n" , (*devs).name );
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
			//sendraw();
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