#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char ip_vhl;          /* version << 4 | header length >> 2 */
        u_char ip_tos;          /* type of service */
        u_short ip_len;         /* total length */
        u_short ip_id;          /* identification */
        u_short ip_off;         /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* don't fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char ip_ttl;          /* time to live */
        u_char ip_p;            /* protocol */
        u_short ip_sum;         /* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;       /* source port */
        u_short th_dport;       /* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
        u_char th_offx2;        /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
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
        u_short th_win;         /* window */
        u_short th_sum;         /* checksum */
        u_short th_urp;         /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_Mac(const u_char* packet);
void print_domain_name(const u_char* packet);
void print_ip(const u_char* packet);
void print_tcp(const u_char* packet);

int main(int argc, char *argv[])
{
        pcap_t *handle;                 /* Session handle */
        char *dev;                      /* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
        struct bpf_program fp;          /* The compiled filter */
        char filter_exp[] = "port 80";  /* The filter expression */
        bpf_u_int32 mask;               /* Our netmask */
        bpf_u_int32 net;                /* Our IP */
        struct pcap_pkthdr header;      /* The header that pcap gives us */
        const u_char *packet;           /* The actual packet */

        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
        }
        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
        }
        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(2);
        }
        /* Compile and apply the filter */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
        }

        if ( 0 ) {
        for ( int i = 0 ; i < 10 ; i++ ) {
                /* Grab a packet */
                packet = pcap_next(handle, &header);
                /* Print its length */
                printf("Jacked a packet with "
                        "length of [%d]\n", header.len);
        }
        } // if for comment out .

        int result = 0 ;
        //result = pcap_loop(handle, 10, got_packet, NULL) ;
        result = pcap_loop(handle, 0, got_packet, NULL) ;

        if ( result != 0 ) {
                fprintf(stderr, "ERROR: pcap_loop end with error !!!!\n");
        } else {
                fprintf(stdout, "INFO: pcap_loop end without error .\n");
        }

        /* And close the session */
        pcap_close(handle);
        return(0);
}
// end of main function.


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

        //unsigned short int  payload_len = 0;
        //payload_len = ntohs(ip->ip_len) - size_ip - size_tcp ;
        //printf("INFO: payload_len = %u .\n", payload_len);

        /*printf("Jacked a packet with "
                        "length of [%d]\n", header->len);
   */

        // print Ethernet address .
        //print_Mac(ethernet);
        
        //print IP
        //print_ip(packet);
        
        //print TCP
	//print_tcp(packet);
		
	//print domain
	print_domain_name(packet);
        

        //printf("\n");

} // end of got_packet function .

void print_ip(const u_char* packet)
{
	u_int size_ip;

        const struct sniff_ip *ip; /* The IP header */
        
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                return;
        }
        
        char *IPbuffer, *IPbuffer2;
        char IPbuffer_str[16];
        char IPbuffer2_str[16];

        IPbuffer = inet_ntoa(ip->ip_src);
        strcpy(IPbuffer_str, IPbuffer);

        IPbuffer2 = inet_ntoa(ip->ip_dst);
        strcpy(IPbuffer2_str, IPbuffer2);
        
	//print ip, port info.
	printf("DATA: IP src : %s\n", IPbuffer_str);
	printf("DATA: IP dst : %s\n", IPbuffer2_str);
        
}

void print_tcp(const u_char* packet)
{
	u_int size_ip;
	u_int size_tcp;
	
        const struct sniff_ip *ip; /* The IP header */
        const struct sniff_tcp *tcp; /* The TCP header */
        
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                return;
        }
        
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
        }

	// print tcp port number .
        unsigned short tcp_src_port = 0 ;
        unsigned short tcp_dst_port = 0 ;

	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);

	//print port info.
	printf("DATA : src Port : %u\n" , tcp_src_port );
	printf("DATA : dst Port : %u\n" , tcp_dst_port );
}

void print_domain_name(const u_char* packet)
{
	const char *payload; /* Packet payload */
	
	
	
	u_int size_ip;
	u_int size_tcp;
	
        const struct sniff_ip *ip; /* The IP header */
        const struct sniff_tcp *tcp; /* The TCP header */
        
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                return;
        }
        
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
        }
        
        
	
	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	u_char *domain = NULL;
        u_char *domain_end = NULL;
        u_char domain_str[256] = { 0x00 };

        int domain_len = 0 ;

        domain = strstr(payload , "Host: ");
        if ( domain != NULL ) {
                domain_end = strstr(domain , "\x0d\x0a") ;
                if ( domain_end != NULL ) {
                    //print ip, port info.
                    //printf("DATA: IP src : %s\n", IPbuffer_str);
               //printf("DATA: IP dst : %s\n", IPbuffer2_str);
                    //printf("DATA : src Port : %u\n" , tcp_src_port );
               //printf("DATA : dst Port : %u\n" , tcp_dst_port );
                   
                    //print domain name.
                        domain_len = domain_end - domain - 6 ;
                        strncpy(domain_str , domain + 6 , domain_len );
                        //printf("INFO: Domain = %s .\n" , domain_str ) ;
                }
        } else {
                //printf("INFO: Host string not found \n");
        }
        
        struct check_domain_struct {
           char domain[256];
        };
        
        //struct check_domain_struct check_domain_str[100] = {0x00};
        //struct check_domain_struct check_domain_str[100];
        
        // define variable with malloc .
        int check_domain_str_count = 10000;
        struct check_domain_struct *check_domain_str = NULL;
        check_domain_str = malloc( sizeof(struct check_domain_struct) * check_domain_str_count);
                    
        if(check_domain_str == NULL){
           fprintf(stderr, "ERROR: malloc fail (line = %d)!!!\n",
                       __LINE__);
        } else{
           //fprintf(stdout, "INFO: malloc OK (line = %d)!!!\n", __LINE__);
        }         
        memset(check_domain_str,
           0x00,
           sizeof(struct check_domain_struct)*
              check_domain_str_count
        );
        
        strcpy(check_domain_str[0].domain, "naver.com");
        strcpy(check_domain_str[1].domain, "kakao.com");
        strcpy(check_domain_str[2].domain, "mail.naver.com");
        
        if(domain_len) {
           int cmp_ret = 1;
           
           for(int i = 0; i<100; i++) {
           
              int str1_len = strlen(check_domain_str[i].domain);
              int str2_len = strlen(domain_str);
           
           
              if(str1_len != str2_len){
                 continue; // check next array value .
              }
           
              //cmp_ret = strcmp(check_domain_ptr[i], domain_str);
              cmp_ret = strcmp(check_domain_str[i].domain, domain_str);
              
              printf("DEBUG: domain name check result : %d\n", cmp_ret);
              
              if(cmp_ret == 0) {
                 break; // end for loop .
              }
              
              // break if meet bull data array .
              if(strlen(check_domain_str[i].domain) == 0){
                 break;
              }
              
           } //end for loop .
           
           //print IP
           print_ip(packet);
           
           //print TCP
           print_tcp(packet);

		//print domain name.
		printf("INFO: Domain = %s .\n" , domain_str );
		
		if(cmp_ret == 0) {
		      printf("DEBUG: domain blocked \n");
		      //sendraw();
		   } else {
		      printf("DEBUG: domain allowed \n");   
		   } // end if cmp_ret .
		   
		if( check_domain_str != NULL) {
		   free(check_domain_str);
		   check_domain_str = NULL;
		}else{
		   fprintf(stderr, "CRIT: check_domain_str was already free(line=%d\n", __LINE__);
		}
        }
        
}

void print_Mac(const u_char* packet)
{
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	
	ethernet = (struct sniff_ethernet*)(packet);
	
	printf("Used print_ethernet function\n");
	printf("DATA: dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n" ,
                                ethernet->ether_dhost[0],
                                ethernet->ether_dhost[1],
                                ethernet->ether_dhost[2],
                                ethernet->ether_dhost[3],
                                ethernet->ether_dhost[4],
                                ethernet->ether_dhost[5]
                );

        printf("DATA: src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n" ,
                                ethernet->ether_shost[0],
                                ethernet->ether_shost[1],
                                ethernet->ether_shost[2],
                                ethernet->ether_shost[3],
                                ethernet->ether_shost[4],
                                ethernet->ether_shost[5]
                );
} //end of print_ethernet function