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

unsigned short in_cksum(unsigned short *addr, int len)
{
	register int sum = 0;
	short answer = 0;
	register short unsigned int *w = addr;
	register int nleft = len;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(char *)(&answer) = *(char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

void print_icmphdr(unsigned char *buffer)
{
	struct iphdr *ip;
	struct icmphdr *icmp;
	unsigned char bytes[4];

	ip = (struct iphdr *)buffer;
	icmp = (struct icmphdr *)(buffer + sizeof(*ip));

	printf("\n\nCabeçalho IP\n");
	printf("\nTamanho do cabeçalho: %d\n", ip->ihl);
	printf("Vers~so: %d\n", ip->version);
	printf("Tipo de serviço: %d\n", ip->tos);
	printf("Tamanho total: %d\n", ip->tot_len);
	printf("ID: %d\n", ip->id);
	printf("Tempo de vida: %d\n", ip->ttl);
	printf("Protocolo: %d\n", ip->protocol);

	bytes[0] = ip->saddr & 0xFF;
	bytes[1] = (ip->saddr >> 8) & 0xFF;
	bytes[2] = (ip->saddr >> 16) & 0xFF;
	bytes[3] = (ip->saddr >> 24) & 0xFF;

	printf("Endereço de origem: %u.%u.%u.%u\n", bytes[0], bytes[1], bytes[2], bytes[3]);

	bytes[0] = ip->daddr & 0xFF;
	bytes[1] = (ip->daddr >> 8) & 0xFF;
	bytes[2] = (ip->daddr >> 16) & 0xFF;
	bytes[3] = (ip->daddr >> 24) & 0xFF;

	printf("Endereço de destino: %u.%u.%u.%u\n", bytes[0], bytes[1], bytes[2], bytes[3]);
	printf("Checksum: %d\n", ip->check);

	printf("\nCabeçalho ICMP\n");
	printf("\nTipo: %d\n", icmp->type);
	printf("Código: %d\n", icmp->code);
	printf("ID: %d\n", icmp->un.echo.id);
	printf("Numero de sequencia: %d\n", icmp->un.echo.sequence);
	printf("Checksum: %d\n", icmp->checksum);
}

int receive(void)
{
	struct sockaddr saddr;
	size_t len = 0, nbytes = 0;
	int sd = -1;
	unsigned char *buffer;

	if ((sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		perror("Unable to create the socket!");
		exit(1);
	}

	if (fcntl(sd, F_SETFL, O_SYNC) != 0)
		perror("Request synchronous writes!");

	buffer = (unsigned char *)malloc(IP_MAXPACKET);
	memset(buffer, 0, IP_MAXPACKET);
	len = sizeof(struct sockaddr);

	do
	{
		if ((nbytes = recvfrom(sd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&saddr, (socklen_t *)&len)) == 0)
			perror("receive error...");
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