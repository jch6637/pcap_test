#include <pcap.h>
#include <stdio.h>

void Print_MAC_Address(const u_char *packet)
{
	const u_char *p = NULL;
	int i;

	p = packet;

	printf("Source MAC Address      : ");

	for( i = 0; i < 6; i++)
	{
		if(i < 5)
			printf("%02x:", *(packet + i + 6) );
		else
			printf("%02x", *(packet + i + 6) );
	}

	printf("\n");

	printf("Destination MAC Address : ");

	for( i = 0;  i < 6; i++)
	{
		if(i < 5)
			printf("%02x:",*(packet + i) );
		else
			printf("%02x", *(packet + i) );
	}

	printf("\n");
}

void Print_IP_Address(const u_char *packet)
{
	const u_char *p = NULL;
	int i;
	
	p = packet;
	printf("Source IP Address       : ");
	
	for( i = 0; i < 4; i++)
	{
		if(i < 3)
			printf("%d.", *(packet + i + 14));
		else
			printf("%d", *(packet + i + 14));
	}

	printf("\n");
	
	printf("Destination IP Address  : ");
	for( i = 0 ; i < 4; i++)
	{
		if(i < 3)
			printf("%d.", *(packet + i + 18) );
		else
			printf("%d", *(packet + i + 18) );
	}	

	printf("\n");
}

void Print_Port(const u_char *packet)
{
	const u_char *p = NULL;
	unsigned short result;
	
	p = packet;

	result = *p * 0x100;
	result += *(p + 1);
	printf("Source Port      : %d\n", result);

	result = *(p + 2) * 0x100;
	result += *(p + 3);
	printf("Destination Port : %d\n", result);
}

void Hexdump(const u_char *packet, struct pcap_pkthdr *header)
{
	int i;
	for(i = 1; i <= 28 + ( *(packet + 14) % 0x40 ) ; i++)
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
	Print_MAC_Address(packet);
	if(*(packet + 12) == 0x08 && *(packet + 13) == 0x00)	
		Print_IP_Address(packet + 12);
	if(*(packet + 23) ==0x06)
		Print_Port(packet + 34);
	printf("***********************************************\n\n");

	}
	pcap_close(handle);

	return 0;
}
