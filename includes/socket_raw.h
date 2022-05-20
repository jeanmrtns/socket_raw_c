void print_icmphdr(unsigned char *);

/*
 * Checksum declaration: shadows@whitefang.com
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short in_cksum(unsigned short *, int);
int receive(void);