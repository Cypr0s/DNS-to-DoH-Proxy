#ifndef OUTPUT_H
#define OUTPUT_H

#include "error.h"
#include <time.h>
#include <stdio.h>
#include "server/dns.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void logDNSMessage(struct sockaddr_storage* address_in, DNSStatePtr dns_state, int8_t rcode_in);

#endif // OUTPUT_H