#ifndef _H_TESTE
#define _H_TESTE

#define MOI "10.132.3.10"
#define IP_MAXPACKET 65535

struct packet
{
  struct icmphdr *hdricmp;
  struct iphdr *hdrip;
  char *data;
};

struct iphdr *build_ip(struct iphdr *, const char *);
struct icmphdr *build_icmp(struct icmphdr *);

int receive(void);
void print_icmphdr(unsigned char *);
unsigned short in_cksum(unsigned short *, int);

#endif