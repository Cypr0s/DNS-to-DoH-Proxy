/**
 * @file    forward.c
 * @author  Kristian Luptak
 * @brief   Contains declarations of functions which work with forwarding dns queries
 *          
 * @date    2026-10-23
 */

#ifndef FORWARD_H
#define FORWARD_H

#include <stdint.h>
#include <sys/socket.h>
#include <curl/curl.h>
#include "server/dns.h"
#include "output.h"

struct proxy_server; // defined in proxy_server.h

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
} ForwardRequestArray, *ForwardRequestArrayPtr;


/**
 * @brief               Creates forward request
 * 
 * @param query         DNS query bytes
 * @param query_size    DNS query size
 * @param flags         Request flags
 * @param socket_fd     Client socket
 * @param client        Client address
 * @param client_size   Client address size
 * @param dns_state     Parsed DNS state
 * @return              ForwardRequestPtr, NULL on failure
 */
ForwardRequestPtr forwardRequestCreate(char* query, 
    size_t query_size,
    uint8_t flags, 
    int socket_fd,
    struct sockaddr_storage client,
    socklen_t client_size,
    DNSState dns_state
);

/**
 * @brief           Deletes forward request at index
 * 
 * @param server    Proxy server
 * @param index     Request index
 */
void forwardRequestDelete(struct proxy_server* server, size_t index);

/**
 * @brief           Forwards DNS query to DoH server
 * 
 * @param server    Proxy server
 * @param req       Forward request
 * @return          ExitStatus 
 */
ExitStatus forwardDNSQuery(struct proxy_server* server, ForwardRequestPtr req);

/**
 * @brief           Handles finished DoH transfers
 * 
 * @param server    Proxy server
 * @return          ExitStatus 
 */
ExitStatus receiveForwardedQueries(struct proxy_server* server);


/**
 * @brief           Deletes all forward requests
 * 
 * @param server    Proxy server
 */
void forwardCleanup(struct proxy_server* server);


/**
 * @brief               Sends DoH answer back to client
 * 
 * @param server        Proxy server
 * @param req           Forward request
 * @param result        Curl transfer result
 * @param http_code     HTTP response code
 * @return              ExitStatus 
 */
ExitStatus handleForwardRequestAnswer(struct proxy_server* server, ForwardRequestPtr req, CURLcode result, long http_code);

#endif // FORWARD_H