#ifndef OUTPUT_H
#define OUTPUT_H

#include "error.h"
#include <time.h>
#include <stdio.h>
#include "server/dns.h"
#include <sys/socket.h>

void logDNSMessage(struct sockaddr_storage* address_in, uint32_t address_in_size, char* qname_in, size_t qname_in_size, uint8_t qtype_in, uint8_t state_in, int8_t rcode_in);

#endif // OUTPUT_H