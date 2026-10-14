#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include "parsing/zonefile.h"
#include "parsing/blocklist.h"
#include "parsing/argument.h"
#include "data-structures/reply-queue.h"
#include "server/forward.h"
#include "server/dns.h"
#include "server/socket.h"


typedef struct proxy_server {
    ConnectionVector connections;
    BlockListTreePtr block_list_root;
    ZoneFileListTreePtr zone_file_root;
    char* forward_address;
    size_t forward_address_size;
    int16_t forward_timeout;
    uint8_t insecure;
    CURLM* multi_handle;
    struct curl_slist* forward_header; // usefull, built only once
    ForwardRequestArray forwarded_requests;
} ProxyServer, *ProxyServerPtr;


ExitStatus proxyServerInit(ParsedArgsPtr parsed_args, ProxyServerPtr server);

void proxyServerDtor(ProxyServerPtr server);

#endif // PROXY_SERVER_H