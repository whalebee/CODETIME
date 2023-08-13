#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include "/usr/include/mysql/mysql.h"

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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char* packet);
void print_ethernet(const struct sniff_ethernet *ethernet);
void print_IP(const struct sniff_ip *ip, char *IPbuffer_str, char *IPbuffer2_str);
void print_PORT(const struct sniff_tcp *tcp, unsigned short *tcp_src_port, unsigned short *tcp_dst_port);
void print_domain(u_char* domain_str);
void sql_connect(MYSQL *sql_handle);
void transfer_to_db(MYSQL *sql_handle, char *IPbuffer_str, char *IPbuffer2_str, u_char* domain_str);
int transfer_from_db(MYSQL *sql_handle, MYSQL_RES *res, MYSQL_ROW *row, u_char *domain_str);

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


	dev = pcap_lookupdev(errbuf);
	if( dev == NULL ) {
		fprintf(stderr, "could not find default device %s \n", errbuf);
		return 2;
	}

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
	int allowed_domain;

	/*-----------------mysql_info-----------------*/
	MYSQL *sql_handle; // mysql.h 구조체
	MYSQL_RES *res;	
	MYSQL_ROW row;
	#define host "localhost"
	#define user "root"
	#define password "1234"
	#define database "PROJECT"
	sql_handle = mysql_init(NULL);
		
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
		sql_connect(sql_handle);
		transfer_to_db(sql_handle,IPbuffer_str,IPbuffer2_str,domain_str);
		allowed_domain = transfer_from_db(sql_handle, res, &row, domain_str);
			    	
		if(allowed_domain){ //check domain blocked/allowed
			printf("DEBUG: domain allowed.\n");
		}
		else {
			printf("DEBUG: domain blocked.\n");
			//sendraw();
		}
		
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

void sql_connect(MYSQL *sql_handle){
	if(!sql_handle) {
		printf("init error!\n");
		exit(0);
	}
	sql_handle = mysql_real_connect(sql_handle,host,user,password,database,0,NULL,0);
	if(!(sql_handle)) printf("connect error!\n");
}

void transfer_to_db(MYSQL *sql_handle, char *IPbuffer_str, char *IPbuffer2_str, u_char* domain_str){
	char spr_buf[1024];
	sprintf(spr_buf,"insert into connect_IP values (\"%s\",\"%s\",\"%s\")",IPbuffer_str,IPbuffer2_str,domain_str);
	mysql_query(sql_handle,spr_buf);
}

int transfer_from_db(MYSQL *sql_handle, MYSQL_RES *res, MYSQL_ROW *row, u_char *domain_str){
	int cmp_ret; // strcmp 리턴값 저장 할 변수
	int str_len1; // block_IP 길이
	int str_len2; // 접속한 도메인 길이
	str_len2 = strlen(domain_str);
	
	mysql_query(sql_handle,"select domain from block_IP");
	res = mysql_store_result(sql_handle); 
	if(res == NULL) printf("mysql_store_result error!!\n");
	else{
		cmp_ret = 1;
		while(*row = mysql_fetch_row(res)){
			str_len1 = strlen(*row[0]);
			if(str_len1 != str_len2) continue;
			cmp_ret = strcmp(*row[0],domain_str);
			if(cmp_ret == 0) break;
		}
	}
	
	mysql_free_result(res);
	mysql_close(sql_handle);
	
	return cmp_ret;
}