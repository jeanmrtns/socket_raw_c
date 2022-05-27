#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <sys/wait.h>
#include <netdb.h>

#include "../includes/socket_raw.h"


struct packet {
       struct icmphdr *hdricmp;
       struct iphdr   *hdrip;
       char           *data;
};

#define MOI     "10.132.3.10"
#define IP_MAXPACKET 65535

int main() {
        char *ip_addr;
        struct sockaddr_in serv;
        struct iphdr       *ip;
        struct icmphdr     *icmp;
        char domain[255] = {""};
        unsigned int dst[4] = {0};
        char* domain_ip;
        size_t len;
        int sd = -1, optval = 1;
        const char *addr, *packet;

        addr = (char *) calloc(1, 16 * sizeof(*addr));
        printf("\nSending an ICMP echo request packet ...\nEnter the address to ping: ");

        printf("Enter domain\n");
        scanf("%s", domain);

        domain_ip = getIp(domain, ip_addr);

        packet = (char *) calloc(1, sizeof(*ip) + sizeof(*icmp));

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(*ip));

        build_ip(ip, domain_ip);
        build_icmp(icmp);

        if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
             perror("Unable to create the socket");
             exit(1);
        }

        setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

        if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0) {
            perror("Request nonblocking I/O");
        }

        icmp->checksum = in_cksum((unsigned short *) icmp, sizeof(*icmp));
        ip->check = in_cksum((unsigned short *) ip, sizeof(*ip));
        len = ntohs(ip->tot_len);

        memset(&serv, '\0', sizeof(struct sockaddr_in));
        serv.sin_family = PF_INET;
        serv.sin_addr.s_addr = inet_addr(addr);

        if (fork() == 0) { 
            receive();
        } else {           
            sendto(sd, packet, len, 0, (struct sockaddr *) &serv, sizeof(struct sockaddr));
            printf("package sent [parent process id: %u].\n", getpid());
        }
        wait(0);

        close(sd);
        return(0);
}
