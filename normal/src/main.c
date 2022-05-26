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
#include "socket_raw.h"

int main()
{
    struct sockaddr_in serv;
    struct iphdr *ip;
    struct icmphdr *icmp;
    unsigned int dst[4] = {0};
    size_t len;
    int sd = -1, optval = 1;
    const char *addr, *packet;

    addr = (char *)calloc(1, 16 * sizeof(*addr));
    printf("\nSending an ICMP echo request packet ...\nEnter the address to ping: ");
    scanf("%16s", (char *)addr);

    if (sscanf(addr, "%u.%u.%u.%u", &dst[0], &dst[1], &dst[2], &dst[3]) != 4)
    {
        perror("Invalid ip address");
        return (0);
    }

    printf("Target address: %u.%u.%u.%u ... ", dst[0], dst[1], dst[2], dst[3]);
    packet = (char *)calloc(1, sizeof(*ip) + sizeof(*icmp));

    ip = (struct iphdr *)packet;
    icmp = (struct icmphdr *)(packet + sizeof(*ip));

    build_ip(ip, addr);
    build_icmp(icmp);

    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("Unable to create the socket");
        exit(1);
    }

    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

    if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0)
    {
        perror("Request nonblocking I/O");
    }

    icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(*icmp));
    ip->check = in_cksum((unsigned short *)ip, sizeof(*ip));
    len = ntohs(ip->tot_len);

    memset(&serv, '\0', sizeof(struct sockaddr_in));
    serv.sin_family = PF_INET;
    serv.sin_addr.s_addr = inet_addr(addr);

    if (fork() == 0)
    {
        receive();
    }
    else
    {
        sendto(sd, packet, len, 0, (struct sockaddr *)&serv, sizeof(struct sockaddr));
        printf("package sent [parent process id: %u].\n", getpid());
    }
    wait(0);

    close(sd);
    return (0);
}