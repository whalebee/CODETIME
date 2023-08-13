void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    	/* ethernet headers are always exactly 14 bytes */
	#define SIZE_ETHERNET 14
		
	u_int size_ip;
	u_int size_tcp;

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */
	
	// ethernet header
	ethernet = (struct sniff_ethernet*)(packet);
	
	// IP header
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	// TCP header
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	// payload
	unsigned short payload_len = 0;
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	payload_len = ntohs(ip->ip_len) - size_ip - size_tcp;
				
	// save IP address.
	char *IPbuffer, *IPbuffer2;
	char IPbuffer_str[16];
	char IPbuffer2_str[16];
	
	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);
	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);
			
	// save tcp port number.
	unsigned short tcp_src_port = 0;
	unsigned short tcp_dst_port = 0;
	
	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);
	
	
	// printf all data
	u_char* domain = NULL;
	u_char* domain_end = NULL;
	u_char domain_str[256] = {0x00};
	int domain_len = 0;
	
	domain = strstr(payload, "Host: ");
	if(domain != NULL){
		domain_end = strstr(domain, "\x0d\x0a");
		if(domain_end != NULL){
			// print ip info
			printf("DATA: IP src : %s\n",IPbuffer_str);
			printf("DATA: IP dst : %s\n",IPbuffer2_str);
			
			// print domain name
			domain_len = domain_end - domain - 6;
			strncpy(domain_str, domain + 6, domain_len);
			printf("INFO: Domain = %s\n", domain_str);
			putc('\n',stdout);
		}
	}
}
// end of got_pakcet function.