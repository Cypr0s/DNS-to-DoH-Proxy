/**
 * @file    proxy.h
 * @author  Kristian Luptak
 * @brief   Contains Declarations of proxy server structure
 *          
 * @date    2026-10-23
 */

#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include "parsing/zonefile.h"
#include "parsing/blocklist.h"
#include "parsing/argument.h"
#include "data-structures/reply-queue.h"
#include "server/forward.h"
#include "server/dns.h"
#include "server/socket.h"


typedef struct {
    ConnectionVector connections;   // poll connections
    HashTable block_list;  // block list check
    ZoneFileListTreePtr zone_file_root; // zone files check
    // forwarding
    char* forward_address;  
    size_t forward_address_size;
    int16_t forward_timeout;
    uint8_t insecure;
    CURLM* multi_handle;
    struct curl_slist* forward_header; // usefull, built only once
    ForwardRequestArray forwarded_requests;
} ProxyServer, *ProxyServerPtr;

/**
 * @brief               Initializes proxy server 
 * 
 * @param parsed_args   Prepared parsed arguments
 * @param server        Target proxyServer
 * @return ExitStatus 
 */
ExitStatus proxyServerCtor(ParsedArgsPtr parsed_args, ProxyServerPtr server);

/**
 * @brief               Initializes proxy server 
 * 
 * @param parsed_args   Prepared parsed arguments
 * @param server        Target proxyServer
 * @return ExitStatus 
 */
void proxyServerDtor(ProxyServerPtr server);

#endif // PROXY_SERVER_H