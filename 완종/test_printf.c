void test_print(u_char* pre_packet, u_char* packet){
	printf("\n\n----------IP header compare----------\n");
	printf("pre_packet\t\t\t\t");
	printf("packet\n");
	printf("version, IHL = %02x\t\t\t",pre_packet[0+14]);
	printf("version, IHL = %02x\n",packet[0]);
	
	printf("type of service = %02x\t\t\t",pre_packet[1+14]);
	printf("type of service = %02x\n",packet[1]);
	
	printf("Total Length = %02x %02x\t\t\t",pre_packet[2+14],pre_packet[3+14]);
	printf("Total Length = %02x %02x\n",packet[2],packet[3]);
	
	printf("identification = %02x %02x\t\t\t",pre_packet[4+14],pre_packet[5+14]);
	printf("identification = %02x %02x\n",packet[4],packet[5]);
	
	printf("IP flags, fragment offset= %02x %02x\t",pre_packet[6+14],pre_packet[7+14]);
	printf("IP flags, fragment offset= %02x %02x\n",packet[6],packet[7]);
	
	printf("TTL = %02x\t\t\t\t",pre_packet[8+14]);
	printf("TTL = %02x\n",packet[8]);
	
	printf("protocol = %02x\t\t\t\t",pre_packet[9+14]);
	printf("protocol = %02x\n",packet[9]);
	
	printf("checksum = %02x %02x\t\t\t",pre_packet[10+14],pre_packet[11+14]);
	printf("checksum = %02x %02x\n",packet[10],packet[11]);
	
	printf("src IP = %02x %02x %02x %02x\t\t\t",pre_packet[12+14],pre_packet[13+14],pre_packet[14+14],pre_packet[15+14]);
	printf("src IP = %02x %02x %02x %02x\n",packet[12],packet[13],packet[14],packet[15]);
	
	printf("dst IP = %02x %02x %02x %02x\t\t\t",pre_packet[16+14],pre_packet[17+14],pre_packet[18+14],pre_packet[19+14]);
	printf("dst IP = %02x %02x %02x %02x\n",packet[16],packet[17],packet[18],packet[19]);
	
	printf("\n\n----------TCP header compare----------\n");
	printf("pre_packet\t\t\t\t");
	printf("packet\n");
	printf("src port = %02x %02x\t\t\t",pre_packet[20+14],pre_packet[21+14]);
	printf("src port = %02x %02x\n",packet[20],packet[21]);
	
	printf("dst port = %02x %02x\t\t\t",pre_packet[22+14],pre_packet[23+14]);
	printf("dst port = %02x %02x\n",packet[22],packet[23]);
	
	printf("SEQ num = %02x %02x %02x %02x\t\t\t",pre_packet[24+14],pre_packet[25+14],pre_packet[26+14],pre_packet[27+14]);
	printf("SEQ num = %02x %02x %02x %02x\n",packet[24],packet[25],packet[26],packet[27]);
	
	printf("ACK num = %02x %02x %02x %02x\t\t\t",pre_packet[28+14],pre_packet[29+14],pre_packet[30+14],pre_packet[31+14]);
	printf("ACK num = %02x %02x %02x %02x\n",packet[28],packet[29],packet[30],packet[31]);
	
	printf("offset, reserved = %02x\t\t\t",pre_packet[32+14]);
	printf("offset, reserved = %02x\n",packet[32]);
	
	printf("TCP Flags = %02x\t\t\t\t",pre_packet[33+14]);
	printf("TCP Flags = %02x\n",packet[33]);
	
	printf("window = %02x %02x\t\t\t\t",pre_packet[34+14],pre_packet[35+14]);
	printf("window = %02x %02x\n",packet[34],packet[35]);
	
	printf("checksum = %02x %02x\t\t\t",pre_packet[36+14],pre_packet[37+14]);
	printf("checksum = %02x %02x\n",packet[36],packet[37]);
	
	printf("urgent pointer = %02x %02x\t\t\t",pre_packet[38+14],pre_packet[39+14]);
	printf("urgent pointer = %02x %02x\n",packet[38],packet[39]);
}