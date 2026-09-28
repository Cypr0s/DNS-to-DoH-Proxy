#include "server/proxy.h"

static ExitStatus handleEvents(ProxyServerPtr server, int event_count) {
    for(size_t i = 0; i < server->connections->curr_size; i++) {
        if(event_count == 0) {
            break;
        }
        switch (server->connections->connections[i].type) {
        case UDP_LISTEN:
            size_t size = recvfrom();
            break;
        case TCP_LISTEN;
            accept();
        default:
            break;
        }
    }
}

ExitStatus proxyServerInit(ParsedArgsPtr parsed_args, ProxyServerPtr server) {
    server->block_list_root = blockListTreeCreateNode(NULL, 0);
    if(server->block_list_root == NULL) {
        return STATUS_MALLOC_FAILURE;
    }

    ExitStatus e = parseBlockList(&(parsed_args->block_lists), server->block_list_root);
    CHECK_ERR_AND_FREE(e, blockListTreeDelete(server->block_list_root););

    server->zone_file_root = zoneFileTreeCreateNode(NULL, 0); // TODO

    e = parseZoneFile(&(parsed_args->block_lists), server->zone_file_root);
    CHECK_ERR_AND_FREE(e, proxyServerDtor(server););

    e = connectionVectorInit(server->connections);
    CHECK_ERR_AND_FREE(e, proxyServerDtor(server););

    e = prepareSockets(parsed_args, server->connections);
    CHECK_ERR_AND_FREE(e, proxyServerDtor(server););

    return STATUS_SUCCESS;
}

ExitStatus proxyServerStart(ProxyServerPtr server) {
    while(1) {
        int events = poll(server->connections->poll_fds, server->connections->curr_size, POLL_MILISECONDS);
        if(events > 0) {
            ExitStatus e = handleEvents(server, events);
            CHECK_ERR(e);
        } else if(events == 0) {
            continue;
        } else {
            return STATUS_FAILURE;
        }
    }
}


void proxyServerDtor(ProxyServerPtr server) {
    zoneFileTreeDelete(server->zone_file_root);
    blockListTreeDelete(server->block_list_root);
    connectionVectorClean(server->connections);
}