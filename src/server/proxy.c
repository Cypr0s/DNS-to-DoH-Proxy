#include "server/proxy.h"

// https://www.ibm.com/docs/en/i/7.1.0?topic=designs-using-poll-instead-select
static ExitStatus acceptConnections(int fd, ConnectionVectorPtr connections) {
    int new_fd = -1;
    while(1) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(struct sockaddr_storage);
        new_fd = accept(fd, (struct sockaddr*)&addr, &addr_len);
        if(new_fd < 0)  {
            if(errno == EWOULDBLOCK || errno == EAGAIN) {
                break;
            }
            // TODO PRINT
            return STATUS_FAILURE;
        }
        Connection c = {.type = TCP_CLIENT, .timeout = 0, .address = addr, .address_size = addr_len};
        struct pollfd poll_fd = {.fd = new_fd, .events = POLLIN, .revents = 0}; 
        ExitStatus e = connectionVectorInsert(connections, poll_fd, c);
    }
    return STATUS_SUCCESS;
}

static ExitStatus processUDPMessages(int fd, ProxyServerPtr server) {

}


static ExitStatus handleEvents(ProxyServerPtr server, int event_count) {
    for(size_t i = 0; i < server->connections->curr_size; i++) {
        if(event_count == 0) {
            break;
        }
        if(server->connections->poll_fds[i].revents & POLLIN) {
            switch (server->connections->connections[i].type) {
            case UDP_LISTEN:
                processUDPMessages(server->connections->poll_fds[i].fd, server);
                break;
            case TCP_LISTEN:
                ExitStatus e = acceptConnections(server->connections->poll_fds[i].fd, server);
            default:
                break;
            }
            event_count--;
        }
    }
}

static ExitStatus handleDNSQuery(ProxyServer server, char* bytes, size_t message_size) {
    return;
}

ExitStatus proxyServerInit(ParsedArgsPtr parsed_args, ProxyServerPtr server) {
    server->block_list_root = blockListTreeCreateNode(NULL, 0);
    if(server->block_list_root == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }

    ExitStatus e = parseBlockList(&(parsed_args->block_lists), server->block_list_root);
    CHECK_ERR_AND_FREE(e, blockListTreeDelete(server->block_list_root););

    server->zone_file_root = zoneFileTreeCreateNode(NULL);
    if(server->zone_file_root == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }

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
        int events = poll(server->connections->poll_fds, server->connections->curr_size, POLL_TIMEOUT);
        if(events > 0) {
            ExitStatus e = handleEvents(server, events);
            CHECK_ERR(e);
        } else if(events == 0) {
            continue;
        } else {
            return STATUS_FAILURE;
        }
    }
    return STATUS_SUCCESS;
}


void proxyServerDtor(ProxyServerPtr server) {
    zoneFileTreeDelete(server->zone_file_root);
    blockListTreeDelete(server->block_list_root);
    connectionVectorClean(server->connections);
}