#ifndef FORWARD_H
#define FORWARD_H

#include <stdint.h>
#include <curl/curl.h>
#include "proxy_server.h"


typedef enum {
    FORWARD_IS_TCP = 0x01,
    FORWARD_IS_UDP = 0x02,
    FORWARD_RESPONSE_OVERFLOW = 0x04,
} ForwardFlags;


typedef struct {
    CURL* easy;
    uint8_t flags;
    int socket_fd;
    struct sockaddr_storage client;
    socklen_t client_size;

    char* query;
    size_t query_size;
    char* response;
    size_t response_size;
    DNSState dns_state;
} ForwardRequest, *ForwardRequestPtr;

typedef struct {
    ForwardRequestPtr forwarded_requests[MAX_FORWARDED_REQUESTS];
    size_t current_size;
} ForwardRequestArray;


ForwardRequestPtr forwardRequestCreate(const char* query, 
    size_t query_size,
    uint8_t flags, 
    int socket_fd,
    struct sockaddr_storage client,
    socklen_t client_size,
    DNSState dns_state);


void forwardRequestDestroy(ForwardRequestPtr req);

ExitStatus forwardDNSQuery(ProxyServerPtr server, ForwardRequestPtr req);
#endif // FORWARD_H