#ifndef SERVER_PROXY_H
#define SERVER_PROXY_H

#include "server/socket.h"
#include "parsing/zonefile.h"
#include "parsing/blocklist.h"
#include "parsing/argument.h"
#include "server/dns.h"
#include "output.h"
#include "data-structures/reply-queue.h"
typedef struct {
    ConnectionVector connections;
    BlockListTreePtr block_list_root;
    ZoneFileListTreePtr zone_file_root;
} ProxyServer, *ProxyServerPtr;

ExitStatus proxyServerInit(ParsedArgsPtr parsed_args, ProxyServerPtr server);

ExitStatus proxyServerStart(ProxyServerPtr server);

void proxyServerDtor(ProxyServerPtr server);

#endif // SERVER_PROXY_H