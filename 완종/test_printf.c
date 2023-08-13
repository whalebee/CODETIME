void test_print(u_char* packet){
	int count=0;
	count=0;
	printf("test print ip header\n");
	for(int i=0;i<20;i++){
		printf("%02x ",packet[i]);
		count++;
		if (count%8==0) fputc(' ',stdout); 
		if (count%16==0) fputc('\n',stdout); 
	}
	printf("\n\nversion, IHL = %02x\n",packet[0])
	printf("type of service = %02x\n",packet[1])
	printf("Total Length = %02x %02x\n",packet[2],packet[3])
	printf("identification = %02x %02x\n",packet[4],packet[5])
	printf("IP flags, fragment offset= %02x %02x\n",packet[6],packet[7])
	printf("TTL = %02x\n",packet[8])
	printf("protocol = %02x\n",packet[9])
	printf("checksum = %02x %02x\n",packet[10],packet[11])
	printf("src IP = %02x %02x %02x %02x\n",packet[12],packet[13],packet[14],packet[15])
	printf("dst IP = %02x %02x %02x %02x\n",packet[16],packet[17],packet[18],packet[19])

	count=0;
	printf("\ntest print tcp header\n");
	for(int i=20;i<40;i++){
		printf("%02x ",packet[i]);
		count++;
		if (count%8==0) fputc(' ',stdout); 
		if (count%16==0) fputc('\n',stdout); 
	}
	printf("\n\nsrc port = %02x %02x\n",packet[20],packet[21])
	printf("dst port = %02x %02x\n",packet[22],packet[23])
	printf("SEQ num = %02x %02x %02x %02x\n",packet[24],packet[25],packet[26],packet[27])
	printf("ACK num = %02x %02x %02x %02x\n",packet[28],packet[29],packet[30],packet[31])
	printf("offset, reserved = %02x\n",packet[32])
	printf("TCP Flags = %02x\n",packet[33])
	printf("window = %02x %02x\n",packet[34],packet[35])
	printf("checksum = %02x %02x\n",packet[36],packet[37])
	printf("urgent pointer = %02x %02x\n",packet[38],packet[39])
}