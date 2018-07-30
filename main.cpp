#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int Print_MAC_Address(const u_char *packet)
{
	struct ether_header* ethernet = (struct ether_header *)packet;  
	int i;

	printf("Source MAC Address      : ");

	for (i = 0; i < 6; i++)
	{
		if (i < 5)
			printf("%02x:", ethernet->ether_shost[i]);
		else
			printf("%02x", ethernet->ether_shost[i]);
	}

	printf("\n");

	printf("Destination MAC Address : ");

	for (i = 0; i < 6; i++)
	{
		if (i < 5)
			printf("%02x:", ethernet->ether_dhost[i]);
		else
			printf("%02x", ethernet->ether_dhost[i]);
	}

	printf("\n");
	if(ntohs(ethernet->ether_type) == ETHERTYPE_IP)
		return 1;

	return 0;
}

int Print_IP_Address(const u_char *packet)
{
	struct iphdr *ip = (struct iphdr *)packet;

	printf("Source IP Address       : %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
	printf("Destination IP Address  : %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
	
	if(ip->protocol == 0x06)
		return 1;

	return 0;
}

void Print_Port(const u_char *packet)
{
	struct tcphdr *tcp = (struct tcphdr *)packet;

	printf("Source Port      : %d\n", ntohs(tcp->source));
	printf("Destination Port : %d\n", ntohs(tcp->dest));
}

void Hexdump(const u_char *packet, struct pcap_pkthdr *header)
{
	int i, total;
	struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
	struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	int data_size = header->caplen - 12 - (ip->ihl * 4) - (tcp->th_off * 4);
	
	printf("[*]Data Size : %d\n", data_size);
	if(data_size > 16) data_size = 16;

	for (i = 1; i <= data_size; i++)
	{
		printf("%02x ", *(packet + i));
		if (i % 8 == 0) printf("  ");
	}

	printf("\n");
	printf("**************************************************\n");

}

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	int res, cnt = 0;
	int ip, tcp = 0;
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr *header;
		const u_char *packet, *p = NULL;

		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		
		printf("**************************************************\n");
		printf("[*]Capture the Packet! / Index : %d\n", ++cnt);
		printf("[*]Packet pointer : %p\n", packet);
		printf("[*]Packet bytes : %u\n", header->caplen);
		printf("**************************************************\n");
		ip = Print_MAC_Address(packet);
		if (ip)
			tcp = Print_IP_Address(packet + sizeof(struct ether_header));
		if (tcp)
			Print_Port(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
		printf("**************************************************\n");
		if(ip == 1 && tcp == 1)
			Hexdump(packet, header);
		printf("\n\n");

	}
	pcap_close(handle);

	return 0;
}
