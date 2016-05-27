#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>

extern void print_icmp_packet(const u_char *, int, struct timeval);
extern void print_udp_packet(const u_char *, int, struct timeval);
extern void print_tcp_packet(const u_char *, int, struct timeval);
extern void print_ethernet(const u_char *, int, struct timeval);
extern bool is_valid(const u_char *, int);
extern void print_arp_acket(struct pcap_pkthdr *, int);
extern char *pattern;

void ip_print(struct pcap_pkthdr *header, const u_char *buffer, struct timeval ts) {

    int size = header->len;
    struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    switch (ip_header->protocol) {
          case 1:
            print_icmp_packet(buffer, size, ts);
            break;
        
	  case 6:
            print_tcp_packet(buffer, size, ts);
            break;
         
          case 17:
            print_udp_packet(buffer, size, ts);
            break;
         
        default: 
            break;
    }
}

void process_packet(struct pcap_pkthdr *header, const u_char *buffer, struct timeval ts) {
    int size = header->len;
    struct ethhdr *ethernet_header = (struct ethhdr *)buffer;

    switch (ntohs(ethernet_header->h_proto)) {
    	case ETHERTYPE_IP:
 		ip_print(header, buffer, ts);
		break;						
	case ETHERTYPE_ARP:
		print_arp_packet(header, size, buffer, ts);
		break;		
	default:
		printf(" OTHER\n");
		break;		
    } 
}

/* Function to read pcap file and dump its data based on the expression */
void dumpPcapFile(char *fileName, char *filterExpression) {
	
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	struct bpf_program fp;        

	pcap = pcap_open_offline(fileName, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "Error in reading pcap file: %s\n", errbuf);
		exit(1);
	}

	if (pcap_compile(pcap, &fp, filterExpression, 0, PCAP_NETMASK_UNKNOWN) == -1)
    	{
        	printf("\npcap_compile() failed. Check for filter expression validity.\n");
        	return;
    	}

   	if (pcap_setfilter(pcap, &fp) == -1)
    	{
       		printf("\nUnable to set filter. pcap_setfilter() failed.\n");
        	exit(1);
    	}
	
	while ((packet = pcap_next(pcap, &header)) != NULL) {
		process_packet(&header, packet, header.ts);
	}

	return;
}

void callback(u_char *useless, const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	static int count = 1;
	process_packet((struct pcap_pkthdr *)pkthdr, packet, pkthdr->ts);
}

void sniffPackets(char *interface, char *filterExpression) {

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;
    bpf_u_int32 pMask;
    bpf_u_int32 pNet;
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;

    if (strcmp(interface, " ") == 0) {
    	interface = pcap_lookupdev(errbuf);
	if (interface == NULL) {
		printf("couldn't find default device: %s\n", errbuf);
		return;
	}
    }
    dev = strdup(interface);
    pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    descr = pcap_open_live(dev, BUFSIZ, 0,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return;
    }

    if(pcap_compile(descr, &fp, filterExpression, 0, pNet) == -1)
    {
        printf("\npcap_compile() failed. Check for filter expression validity.\n");
        return;
    }

    if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("\nUnable to set filter. pcap_setfilter() failed\n");
        exit(1);
    }

    pcap_loop(descr, -1, callback, NULL);

    return;
}
