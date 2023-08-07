#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql.h>


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


        MYSQL * conect;
        char * server = "172.0.0.1"; //dbserver ip
        char * user = "root";           //db username
        char * password = "ubuntu";     //db password
        char * database = "pcap";       //db base

        conect = mysql_init(NULL); //reset conect;

        mysql_real_connect(conect, server, user, password, database, 3306, NULL, 0);


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
        result = pcap_loop(handle, 0, got_packet, (u_char*)conect)) ;

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
    char IPbuffer2_str[16];
    unsigned short tcp_dst_port = 0;
    char domain_str[256];

    MYSQL *conect = (MYSQL*)args;

    char query_buffer[1024];
// Ethernet header
    const struct sniff_ethernet *ethernet = (struct sniff_ethernet*)(packet);

    // IP header
    const struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip) * 4;

    // TCP header
    const struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    u_int size_tcp = TH_OFF(tcp) * 4;

    // Extract IP addresses
    char *IPbuffer, *IPbuffer2;
    char IPbuffer_str[16];
    IPbuffer = inet_ntoa(ip->ip_src);
    strcpy(IPbuffer_str, IPbuffer);
IPbuffer2 = inet_ntoa(ip->ip_dst);
    strcpy(IPbuffer2_str, IPbuffer2);

    // Extract TCP ports
    unsigned short tcp_src_port = ntohs(tcp->th_sport);
    tcp_dst_port = ntohs(tcp->th_dport);

    // Extract domain name
    const char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    const char *domain = strstr(payload, "Host: ");
    if (domain != NULL) {
        const char *domain_end = strstr(domain, "\x0d\x0a");
        if (domain_end != NULL) {
            int domain_len = domain_end - domain - 6;
            memcpy(domain_str, domain + 6, domain_len);
            domain_str[domain_len] = '\0'; // NULL 종료 문자 추가
        }
    }

                               // Print information
    printf("DATA: IP src : %s\n", IPbuffer_str);
    printf("DATA: IP dst : %s\n", IPbuffer2_str);
    printf("DATA : src Port : %u\n", tcp_src_port);
    printf("DATA : dst Port : %u\n", tcp_dst_port);
    printf("INFO: Domain = %s .\n", domain_str);

   snprintf(query_buffer, sizeof(query_buffer),
             "INSERT INTO web (domain,ip,port) "
             "VALUES ('%s','%s','%hu')",
             domain_str, IPbuffer2_str, tcp_dst_port);

    if (mysql_real_query(conect, query_buffer, strlen(query_buffer)) != 0)
    {
        fprintf(stderr, "SQL 쿼리 전송 오류: %s\n", mysql_error(conect));
    }
}

                           
