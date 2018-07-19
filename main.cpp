#include <pcap.h>
#include <stdio.h>

void Print_Dest_MAC(const u_char *packet)
{
	const u_char *p = NULL;
	int i;

	p = packet;
	printf("Destination MAC Address : ");
	for(i=0; i<8; i++)
	{
		if(i < 7)
			printf("%02x:",*(packet + i) );
		else
			printf("%02x", *(packet + i) );
	}

	printf("\n");
}

void Print_Src_MAC(const u_char *packet)
{
	const u_char *p = NULL;
	int i;	

	p = packet;
	printf("Source MAC Address      : ");

	for(i=0; i<8; i++)
	{
		if(i < 7)
			printf("%02x:", *(packet + i + 8) );
		else
			printf("%02x", *(packet + i + 8) );
	}
	printf("\b\n");
}

void Print_Src_IP(const u_char *packet)
{
	const u_char *p = NULL;
	int i;
	
	p = packet;
	printf("Source IP Address       : ");
	
	for(i=0; i<4; i++)
	{
		if(i < 3)
			printf("%d.", *(packet + i + 12));
		else
			printf("%d", *(packet + i + 12));
	}
	printf("\n");
}

void Print_Dest_IP(const u_char *packet)
{
	const u_char *p = NULL;
	int i;

	p = packet;
	printf("Destination IP Address  : ");
	
	for(i=0; i<4; i++)
	{
		if(i < 3)
			printf("%d.", *(packet + i + 16));
		else
			printf("%d", *(packet + i + 16));
	}
	printf("\n");
}

void Print_Src_Port(const u_char *packet)
{
	const u_char *p = NULL;
	unsigned short result;

	p = packet;
	result = *p * 0x100;
	result += *(p + 1);
	printf("Source Port : %d\n",result);
}

void Print_Dest_Port(const u_char *packet)
{
	const u_char *p = NULL;
	unsigned short result;
	
	p = packet;
	result = *(p + 2) * 0x100;
	result += *(p + 3);
	printf("Destination Port : %d\n", result);
}

void Hexdump(const u_char *packet, struct pcap_pkthdr *header)
{
	int i;
	for(i = 1; i <= header->caplen; i++)
        {
                printf("%02x ", *packet);
                if(i % 8 == 0) printf("  ");
                if(i % 16 == 0) printf("\n");
                packet++;
        }
        
        printf("\n");   
        printf("***********************************************\n");

}

void usage(){
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char *argv[]){
	if(argc != 2){
		usage();
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	int res, cnt = 0;
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if(handle == NULL){
		fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
		return -1;
	}
	
	while(true){
	struct pcap_pkthdr *header;
	const u_char *packet, *p = NULL;

	res = pcap_next_ex(handle, &header, &packet);
	if(res == 0) continue;
	if(res == -1 || res == -2) break;	

	printf("\n[*]Capture the Packet! / Index : %d\n", ++cnt);
	printf("[*]Packet pointer : %p\n", packet);
	printf("[*]Packet bytes : %u\n", header->caplen);	
	printf("***********************************************\n");
	Hexdump(packet, header);	
	Print_Src_MAC(packet);	
	Print_Dest_MAC(packet);
	Print_Src_IP(packet + 14);
	Print_Dest_IP(packet + 14);
	Print_Src_Port(packet + 34);
	Print_Dest_Port(packet + 34);	
	printf("***********************************************\n\n");
	}
	pcap_close(handle);

	return 0;
}
