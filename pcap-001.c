#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char* packet)
{
	#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if( size_ip < 20 ) {
		fprintf(stderr, " * Invalid IP Header Length %u bytes \n", size_ip);
	}

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if( size_tcp < 20 ) {
		fprintf(stderr, " * Invalid TCP Header Length %u bytes \n", size_tcp);
	}

	payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);


	unsigned short int payload_len = 0;
	payload_len = ntohs(ip->ip_len) - size_ip - size_tcp;

//	printf("DATA: payload_len %u \n", payload_len);
//
//	printf("Jacked a packet with Length of [%d] \n", header->len);
//
//
//	printf("DATA: dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
//			ethernet->ether_dhost[0],
//			ethernet->ether_dhost[1],
//			ethernet->ether_dhost[2],
//			ethernet->ether_dhost[3],
//			ethernet->ether_dhost[4],
//			ethernet->ether_dhost[5]
//			);
//
//
//
//	printf("DATA: src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
//			ethernet->ether_shost[0],
//			ethernet->ether_shost[1],
//			ethernet->ether_shost[2],
//			ethernet->ether_shost[3],
//			ethernet->ether_shost[4],
//			ethernet->ether_shost[5]
//			);


	// IP
	char *IPbuffer, *IPbuffer2;
	char IPbuffer_str[16];
	char IPbuffer2_str[16];


	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);

	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);

//	printf("DATA: IP src : %s \n", IPbuffer_str);
//	printf("DATA: IP dst : %s \n", IPbuffer2_str);

	// port
	unsigned short tcp_src_port = 0;
	unsigned short tcp_dst_port = 0;

	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);


//	printf("DATA : src Port %u \n", tcp_src_port);
//	printf("DATA : dst Port %u \n", tcp_dst_port);


	// domain
	u_char *domain = NULL;
	u_char *domain_end = NULL;
	u_char domain_str[256] = { 0x00};

	int domain_len = 0;

	domain = strstr(payload, "Host: ");
	if( domain != NULL ) {
		domain_end = strstr(domain, "\x0d\x0a");
		if( domain_end != NULL ) {
			domain_len = domain_end - domain - 6;
			strncpy(domain_str, domain + 6, domain_len );
//			printf("INFO: Domain : %s \n", domain_str);
		} else {
//			printf("INFO: Host string not found \n");
		}
	}



// new -------------------------------------
struct check_domain_struct {
	char domain[256];
};




// reset method 1 ( if i were have not DB )
//struct chk_domain_struct chk_domain_str[100] = { 0x00 };
//
//char *chk_domain_ptr[100] = { NULL };
//char *chk_strcpy[100] = { NULL };
//
//for(int i = 0; i < 100; i++) {
//	chk_domain_ptr[i] = malloc(256);
//	if( chk_domain_ptr[i] == NULL ) {
//		fprintf(stderr, "ERROR: malloc() fail !! \n");
//	}
//} // end for loop
//
//
//// strcpy & check
//strcpy(chk_domain_ptr[0], "naver.com");
//if( strlen(chk_domain_ptr[0]) == 0 )
//	 fprintf(stderr, "chk_domain_ptr[0] is NULL !! \n");
//strcpy(chk_domain_ptr[1], "kakao.com");
//if( strlen(chk_domain_ptr[1]) == 0 )
//	 fprintf(stderr, "chk_domain_ptr[1] is NULL !! \n");
//strcpy(chk_domain_ptr[2], "mail.naver.com");
//if( strlen(chk_domain_ptr[2]) == 0 )
//	fprintf(stderr, "chk_domain_ptr[2] is NULL !! \n");
//// printf("%s \n", chk_domain_ptr[0]);




// reset method 2 ( declare & reset at the same time )
//struct chk_domain_struct chk_domain_str[100];
//for( int j = 0 ; j < 100 ; j++ ) {
//	strcpy(chk_domain_str[j].domain, "");
//}


//// method 2 strcpy & check .
//strcpy(chk_domain_str[0], "naver.com");
//if( strlen(chk_domain_str[0]) == 0 )
//	 fprintf(stderr, "chk_domain_str[0] is NULL !! \n");
//strcpy(chk_domain_str[1], "kakao.com");
//if( strlen(chk_domain_str[1]) == 0 )
//	 fprintf(stderr, "chk_domain_str[1] is NULL !! \n");
//strcpy(chk_domain_str[2], "mail.naver.com");
//if( strlen(chk_domain_str[2]) == 0 )
//	fprintf(stderr, "chk_domain_str[2] is NULL !! \n");
//// printf("%s \n", chk_domain_str[0]);


// reset method 3 ( use this )
int check_domain_str_count = 10000;
struct check_domain_struct *check_domain_str = NULL;

// malloc
check_domain_str = malloc ( sizeof(struct check_domain_struct) *
			check_domain_str_count
			);
if( check_domain_str == NULL ) {
	fprintf(stderr, "ERROR: malloc fail !!! (line=%d) \n", __LINE__);
} else {
//	fprintf(stdout,"INFO: malloc ok (line=%d) \n", __LINE__);
}


// reset 0
memset( check_domain_str, 0x00, sizeof( struct check_domain_struct ) *
					check_domain_str_count
	);



// method 3 strcpy & check .
strcpy(check_domain_str[0].domain, "naver.com");
if( strlen(check_domain_str[0].domain) == 0 )
	 fprintf(stderr, "check_domain_str[0] is NULL !! \n");
strcpy(check_domain_str[1].domain, "kakao.com");
if( strlen(check_domain_str[1].domain) == 0 )
	 fprintf(stderr, "check_domain_str[1] is NULL !! \n");
strcpy(check_domain_str[2].domain, "mail.naver.com");
if( strlen(check_domain_str[2].domain) == 0 )
	fprintf(stderr, "check_domain_str[2] is NULL !! \n");
// printf("%s \n", check_domain_str[0]);




if( domain_len ) {
	int cmp_ret = 1; // for compare result


	// start for loop 1 .
	for(int i = 0; i < 100; i++ ) {

	// reset method 2
	// cmp_ret = strcmp(check_domain_ptr[i], domain_str);


	
	// if you knew str_len, you choice method like this
	int str1_len = strlen ( check_domain_str[i].domain );
	int str2_len = strlen ( domain_str );

	if( str1_len != str2_len ) {
		continue; // move to next array !
	}

	cmp_ret = strcmp(check_domain_str[i].domain, domain_str);
	printf("DEBUG: domain name check result : %d \n", cmp_ret);

	if( cmp_ret == 0 )
		break; // stop for loop 1 .
	
	// break if meet NULL data in array .
	if( strlen( check_domain_str[i].domain) == 0 ) {
		break; // stop for loop 1.
	}

	} // end for loop 1 .

	printf("DATA: IP src : %s \n", IPbuffer_str);
	printf("DATA: IP dst : %s \n", IPbuffer2_str);

	printf("DATA : src Port %u \n", tcp_src_port);
	printf("DATA : dst Port %u \n", tcp_dst_port);
	
	printf("INFO: Domain : %s . \n", domain_str);

	if( cmp_ret == 0 ) {
		printf("DEBUG: main blocked . \n");
	// sendraw(); // here is block packet function location later
	} else {
		printf("DEBUG: domain allowed . \n");
	} // end if emp_ret .


	if( check_domain_str != NULL ) {
		free(check_domain_str);
		check_domain_str = NULL;
	} else {
		fprintf(stderr, "CRIT: check_domain_str was already free status !! (line=%d) \n", __LINE__);
	} // end check_domain_str

	} // end if domain_len

//	printf("\n");

} // end of got_packet()
