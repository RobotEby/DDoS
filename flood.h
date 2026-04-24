#ifndef FLOOD_H
#define FLOOD_H

#include <stdint.h>
#include <stddef.h>

/* Returns a random port in [1024, 65535] to avoid reserved ports */
uint16_t rand_port(void);

/* Fills buf with a random IPv4 string (e.g. "192.168.1.1") */
void rand_ip(char *buf, size_t len);

/* Returns 1 if ip is a valid IPv4 address, 0 otherwise */
int valid_ip(const char *ip);

/* Computes the internet checksum (RFC 1071) over nbytes of data */
unsigned short checksum(const unsigned short *ptr, int nbytes);

#endif /* FLOOD_H */