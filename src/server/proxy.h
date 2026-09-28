#include "server/sockets.h"
#include "parsing/zonefile.h"
#include "parsing/blocklist.h"
#include "parsing/argument.h"

typedef struct {
    ConnectionVectorPtr connections;
    BlockListTreePtr block_list_root;
    ZoneFileListTreePtr zone_file_root;
} ProxyServer, *ProxyServerPtr;

ExitStatus proxyServerInit(ParsedArgsPtr parsed_args, ProxyServerPtr server);

ExitStatus proxyServerStart(ProxyServerPtr server);

void proxyServerDtor(ProxyServerPtr server);