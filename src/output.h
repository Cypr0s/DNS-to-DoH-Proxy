#ifndef OUTPUT_H
#define OUTPUT_H

#include "error.h"
#include "common.h"
#include <time.h>
#include <stdio.h>
#include "server/dns.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void createLogLine(char* out, size_t out_size, struct sockaddr_storage* address_in, DNSStatePtr dns_state, int8_t rcode_in);

void printLogLine(char* line);

#endif // OUTPUT_H