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

struct sockaddr_in source,dest;
extern char *pattern;

bool is_valid(const u_char *data, int size) {
    int i;
    for (i=0; i<size; i++) {
    	if (memcmp(pattern, data+i, strlen(pattern)) == 0)
		return true;
    }
    return false;
}

void printPayload(const u_char *data, int size) {
    int i, j;
    if (pattern != NULL)
	if (is_valid(data, size) == false)
		return;
    for(i=0; i < size; i++) {
        if(i!=0 && i%16==0) {  
            printf("        ");
            for(j=i-16 ; j<i ; j++) {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c", (unsigned char) data[j]);                  
                else
		    printf(".");
            }
            printf("\n");
        } 
        if(i%16==0) printf("  ");
            printf(" %02X", (unsigned int)data[i]);
                 
        if(i==size-1) { 
            for(j=0; j<15-i%16; j++) 
              printf("  "); 
            printf("        ");
            for(j=i-i%16; j<=i; j++) {
                if(data[j]>=32 && data[j]<=128)
                  printf("%c", (unsigned char) data[j]);
                else
                  printf(".");
            } 
            printf("\n");
        }
    }
    printf("\n");
}

void print_ethernet(const u_char *packet_buffer, int size, struct timeval ts) {

    struct ethhdr *ethernet_header = (struct ethhdr *)packet_buffer;
    printf("   Timestamp = %s ", ctime(&(ts.tv_sec)));  
    printf("  Destination MAC Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X ",
		ethernet_header->h_dest[0], ethernet_header->h_dest[1], ethernet_header->h_dest[2],
			ethernet_header->h_dest[3], ethernet_header->h_dest[4], ethernet_header->h_dest[5]);
    printf("   Source MAC Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
		ethernet_header->h_source[0], ethernet_header->h_source[1], ethernet_header->h_source[2],
			ethernet_header->h_source[3], ethernet_header->h_source[4], ethernet_header->h_source[5]);
    printf("   Type: 0x%X \n", ntohs(ethernet_header->h_proto));
}

void print_ip(const u_char *packet_buffer, int size, struct timeval ts) {
  
    unsigned short length;       
    struct iphdr *ip_header = (struct iphdr *)(packet_buffer  + sizeof(struct ethhdr));
    length =ip_header->ihl*4;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr; 
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header->daddr;

    /* Print to console */
    print_ethernet(packet_buffer, size, ts);

    printf("   IP Version: %d ", (unsigned int)ip_header->version);
    printf("   IP Header Length: %d Bytes ",((unsigned int)(ip_header->ihl))*4);
    printf("   IP Total Length: %d Bytes (Packet Size) ", ntohs(ip_header->tot_len));
    printf("Protocol:");

    if (ip_header->protocol == 6)
   	printf(" TCP\n");
    else if (ip_header->protocol == 17)
   	printf(" UDP\n");
    else if (ip_header->protocol == 1)
   	printf(" ICMP\n");
    else
   	printf(" OTHER\n");

    printf("   Source IP: %s" , inet_ntoa(source.sin_addr));
    printf("   Destination IP: %s\n" , inet_ntoa(dest.sin_addr));
}

void print_udp_packet(const u_char *packet_buffer, int packet_size, struct timeval ts) {
     
    unsigned short length;
    
    struct iphdr *ip_header = (struct iphdr *)(packet_buffer +  sizeof(struct ethhdr));
    length = ip_header->ihl*4;
    struct udphdr *udp_header = (struct udphdr*)(packet_buffer + length  + sizeof(struct ethhdr));
    int size =  sizeof(struct ethhdr) + length + sizeof (udp_header);

    /* Print to console */
    if (pattern != NULL)
    	if (is_valid(packet_buffer + size, packet_size - size) == false) 
		return;

    printf("\n----------------------------------------------- New Packet ----------------------------------------------------------\n");
    print_ip(packet_buffer, packet_size, ts);           
    printf("   Source Port: %d" , ntohs(udp_header->source));
    printf("   Destination Port: %d" , ntohs(udp_header->dest));
    printf("   UDP Length: %d\n\n" , ntohs(udp_header->len));
    printPayload(packet_buffer + size, packet_size - size);
    printf("\n----------------------------------------------- End of Packet ----------------------------------------------------------\n");
}

void print_arp_packet(struct pcap_pkthdr *header, int size, const u_char *packet_buffer, struct timeval ts) {
    
    const struct arphdr *arpheader = NULL;
    arpheader = (struct arphdr *)(header+14); // Point to the ARP header 
    struct ethhdr *ethernet_header = (struct ethhdr *)packet_buffer; 
    if (pattern != NULL)
    	if (is_valid(packet_buffer + sizeof(ethernet_header) + sizeof(arpheader), size - sizeof(ethernet_header) - sizeof(arpheader)) == false) 
		return;

    printf("\n----------------------------------------------- New Packet ----------------------------------------------------------\n");
    print_ethernet(packet_buffer, size, ts);
    printf("\n");
    printPayload(packet_buffer + sizeof(ethernet_header) + sizeof(arpheader), size - sizeof(ethernet_header) - sizeof(arpheader));
    printf("\n----------------------------------------------- End of Packet ----------------------------------------------------------\n");
}

void print_tcp_packet(const u_char * packet_buffer, int packet_size, struct timeval ts) {
   
    unsigned short length;  
    struct iphdr *ip_header = (struct iphdr *)(packet_buffer + sizeof(struct ethhdr));
    length = ip_header->ihl*4;
    struct tcphdr *tcp_header=(struct tcphdr*)(packet_buffer + length + sizeof(struct ethhdr));
    int size =  sizeof(struct ethhdr) + length + tcp_header->doff*4;

    /* Print to console */       
    if (pattern != NULL)
    	if (is_valid(packet_buffer + size, packet_size - size) == false) 
		return;

    printf("\n----------------------------------------------- New Packet ----------------------------------------------------------\n");
    print_ip(packet_buffer, size, ts);
    printf("   Source Port: %u ", ntohs(tcp_header->source));
    printf("   Destination Port: %u \n", ntohs(tcp_header->dest));
    printf("   Sequence Number: %u ", ntohl(tcp_header->seq));
    printf("   Acknowledge Number: %u ", ntohl(tcp_header->ack_seq));
    printf("   TCP Header Length: %d Bytes\n\n", (unsigned int)tcp_header->doff*4);
    printPayload(packet_buffer + size, packet_size - size);
    printf("\n----------------------------------------------- End of Packet ----------------------------------------------------------\n");
}

void print_icmp_packet(const u_char * packet_buffer, int packet_size, struct timeval ts) {
    
    unsigned short length;
    struct iphdr *ip_header = (struct iphdr *)(packet_buffer  + sizeof(struct ethhdr));
    length = ip_header->ihl * 4;
    struct icmphdr *icmp_header = (struct icmphdr *)(packet_buffer + length  + sizeof(struct ethhdr));   
    int size =  sizeof(struct ethhdr) + length + sizeof icmp_header;
  
    /* Print to console */
    if (pattern != NULL)
  	  if (is_valid(packet_buffer + size, packet_size - size) == false) 
		return;

    printf("\n----------------------------------------------- New Packet ----------------------------------------------------------\n");
    print_ip(packet_buffer, packet_size, ts);
    printf("\n");
    printPayload(packet_buffer + size, packet_size - size);
    printf("\n----------------------------------------------- End of Packet ----------------------------------------------------------\n");
}
