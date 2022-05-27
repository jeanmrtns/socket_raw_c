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
#include <netdb.h>
#include <syslog.h>
#include <linux/icmp.h>
#include <sys/wait.h>

struct addrinfo {
        int              ai_flags;
        int              ai_family;
        int              ai_socktype;
        int              ai_protocol;
        socklen_t        ai_addrlen;
        struct sockaddr *ai_addr;
        char            *ai_canonname;
        struct addrinfo *ai_next;
};

struct packet
{
        struct icmphdr *hdricmp;
        struct iphdr *hdrip;
        char *data;
};
struct iphdr *build_ip(struct iphdr *, const char *);
struct icmphdr *build_icmp(struct icmphdr *);

#define MOI "10.132.3.10"
#define IP_MAXPACKET 65535

/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
        register int sum = 0;
        short answer = 0;
        register short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)
        {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1)
        {
                *(char *)(&answer) = *(char *)w;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
        sum += (sum >> 16);                 /* add carry */
        answer = ~sum;                      /* truncate to 16 bits */
        return (answer);
}

void print_icmphdr(unsigned char *buffer)
{
        struct iphdr *ip;
        struct icmphdr *icmp;
        unsigned char bytes[4];

        ip = (struct iphdr *)buffer;
        icmp = (struct icmphdr *)(buffer + sizeof(*ip));

        printf("\nTamanho do cabecalho: %d\n", ip->ihl);
        printf("Versao do cabecalho: %d\n", ip->version);
        printf("Tipo de servico recebido: %d\n", ip->tos);
        printf("Tamanho total do cabecalho: %d\n", ip->tot_len);
        printf("ID do cabecalho: %d\n", ip->id);
        printf("Tempo de vida: %d\n", ip->ttl);
        printf("Protocolo: %d\n", ip->protocol);

        bytes[0] = ip->saddr & 0xFF;
        bytes[1] = (ip->saddr >> 8) & 0xFF;
        bytes[2] = (ip->saddr >> 16) & 0xFF;
        bytes[3] = (ip->saddr >> 24) & 0xFF;

        printf("Endereco origem: %u.%u.%u.%u\n", bytes[0], bytes[1], bytes[2], bytes[3]);

        bytes[0] = ip->daddr & 0xFF;
        bytes[1] = (ip->daddr >> 8) & 0xFF;
        bytes[2] = (ip->daddr >> 16) & 0xFF;
        bytes[3] = (ip->daddr >> 24) & 0xFF;

        printf("Endereco de destino: %u.%u.%u.%u\n", bytes[0], bytes[1], bytes[2], bytes[3]);
        printf("Checksum: %d\n", ip->check);

        printf("\nCabecalho ICMP\n");
        printf("\nTipo: %d\n", icmp->type);
        printf("Codigo: %d\n", icmp->code);
        printf("ID: %d\n", icmp->un.echo.id);
        printf("Numero de sequencia: %d\n", icmp->un.echo.sequence);
        printf("Checksum: %d\n", icmp->checksum);
}

int receive(void)
{
        struct sockaddr saddr;
        size_t len = 0, nbytes = -1;
        int sd = -1;
        unsigned char *buffer;

        if ((sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        {
                perror("Unable to create the socket!");
                exit(1);
        }

        if (fcntl(sd, F_SETFL, O_SYNC) != 0)
        {
                perror("Request synchronous writes!");
        }

        buffer = (unsigned char *)malloc(IP_MAXPACKET);
        memset(buffer, 0, IP_MAXPACKET);

        len = sizeof(struct sockaddr);

        do
        {
                if ((nbytes = recvfrom(sd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&saddr, (socklen_t *)&len)) == -1)
                {
                        perror("receive error...");
                }
                else
                {
                        printf("Received an ICMP echo reply packet with data... \n");
                        print_icmphdr(buffer);
                }

                memset(buffer, 0, IP_MAXPACKET);
        } while (nbytes > 0);

        free(buffer);

        return (close(sd));
}

/* IP and ICMP package forger */
struct iphdr *build_ip(struct iphdr *ip, const char *addr)
{
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(*ip) + sizeof(struct icmphdr));
        ip->id = htons(getpid());
        ip->ttl = 255;
        ip->protocol = IPPROTO_ICMP;
        ip->saddr = inet_addr(MOI);
        ip->daddr = inet_addr(addr);
        ip->check = 0;
        return (ip);
}

struct icmphdr *build_icmp(struct icmphdr *icmp)
{
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = 0;
        icmp->un.echo.sequence = 0;
        icmp->checksum = 0;
        return (icmp);
}

char* getIp(char domain[], char *xip_addr)
{
        printf("Procurando pelo domínio => %s\n\n", domain);
        
        char ip_addr[INET6_ADDRSTRLEN] = {};
        int status, socketfd;
        struct sockaddr_in *remote;
        struct addrinfo hints = {}, *res, *p;
        const char *port = NULL;

        xip_addr = ip_addr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_TCP;

        /*xip_addr = malloc(INET6_ADDRSTRLEN);
        memset(ip_addr, 0, INET6_ADDRSTRLEN);*/
        memset(&hints, 0, sizeof hints);
        
        if ((status = getaddrinfo(domain, port, &hints, &res)) != 0)
        {
                perror("getaddrinfo failed ");
                return (-1);
        }

        for (p = res; p != NULL; p = p->ai_next)
        {
                void *addr;

                remote = (struct sockaddr_in *)p->ai_addr;
                addr = &(remote->sin_addr);

                inet_ntop(p->ai_family, addr, ip_addr, sizeof(ip_addr));

                printf("--> %s\n", ip_addr);

                if (strlen(ip_addr) > 0) {
                        break;
                }
        }

        if ((socketfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
        {
                perror("Failed creating socket!");
                return (-1);
        }

        printf("res: ==> %s\n", ip_addr);
        return xip_addr;       
}