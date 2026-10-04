#include "server/proxy.h"

static ExitStatus acceptConnections(int fd, ConnectionVectorPtr connections);
static ExitStatus processUDPMessages(int fd, ProxyServerPtr server);
static ExitStatus handleEvents(ProxyServerPtr server, int event_count);
static ExitStatus handleDNSQuery(char* bytes, size_t message_size, ProxyServerPtr server, DNSStatePtr dns_state);

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
        CHECK_ERR(e);
    }
    return STATUS_SUCCESS;
}


static ExitStatus processUDPMessages(int fd, ProxyServerPtr server) {
    uint8_t bytes[DNS_QUERY_UDP_SIZE];
    struct sockaddr_storage address;
    socklen_t address_size = sizeof(struct sockaddr_storage);
    while(1) {
        ssize_t msg_size = recvfrom(fd, bytes, DNS_QUERY_UDP_SIZE, 0, (struct sockaddr *)&address, &address_size);
        if(msg_size < 0) {
            if(errno == EAGAIN) {
                break;
            }
            // actual error
            return STATUS_FAILURE;
        }
        DNSState dns_state = {0};
        ExitStatus e = handleDNSQuery((char*)bytes, msg_size, server, &dns_state);
        CHECK_ERR(e);
        // response
        if(dns_state.reply != NULL) {
            msg_size = sendto(fd, dns_state.reply, dns_state.reply_max_size, 0, (struct sockaddr*) &address, &address_size);
            if(msg_size < 0) {
                return STATUS_FAILURE;
            }
            
        }
    }
    return STATUS_SUCCESS;
}


static ExitStatus handleEvents(ProxyServerPtr server, int event_count) {
    ExitStatus e = STATUS_SUCCESS;
    for(size_t i = 0; i < server->connections.curr_size; i++) {
        if(event_count == 0) {
            break;
        }
        if(server->connections.poll_fds[i].revents & POLLIN) {
            switch (server->connections.connections[i].type) {
            case UDP_LISTEN:
                e = processUDPMessages(server->connections.poll_fds[i].fd, server);
                CHECK_ERR(e);
                break;
            case TCP_LISTEN:
                e = acceptConnections(server->connections.poll_fds[i].fd, &server->connections);
                CHECK_ERR(e);
            default:
                break;
            }
            event_count--;
        }
    }
    return e;
}

static ExitStatus handleDNSQuery(char* bytes, size_t message_size, ProxyServerPtr server, DNSStatePtr dns_state) {
    ExitStatus e = parseDNSQuery(bytes, message_size, dns_state);
    CHECK_ERR(e);
    if(dns_state->state == DNS_STATE_DROPPED) {
        return STATUS_SUCCESS;
    }
    e = createDNSAnswer(dns_state); // blank reply
    uint16_t response_header_flags = bytesToUShort(dns_state->reply + 2);
    switch(dns_state->state){
        case DNS_STATE_INVALID_FORMERR:
            response_header_flags |= RCODE_FORMERR;
            break;
        case DNS_STATE_INVALID_NOTIMP:
            response_header_flags |= RCODE_NOTIMP;
            break;
        case DNS_STATE_INVALID_REFUSED:
            response_header_flags |= RCODE_REFUSED;
            break;
        case DNS_STATE_VALID: {
            ZoneFileListTreePtr zone = NULL;
            ZoneFileListTreePtr name = NULL;
            // local
            uint8_t return_flag = isInZone(server->zone_file_root, &dns_state->query.question.labels, &zone, &name);
            if(return_flag) {
                response_header_flags |= AA;
                dns_state->state = DNS_STATE_LOCAL;
                // NAME DOESNT EXIST
                ZoneEntryPtr entry = NULL;
                if(name == NULL) {
                    response_header_flags |= RCODE_NXDOMAIN;
                    // add SOA
                    entry = getEntry(&zone->list, ENTRY_SOA); // NULL cannot happen here we found a zone(it must have one SOA)
                    CHECK_ERR(e);
                    ExitStatus e = addAnswerField(dns_state, zone->full_domain_name, entry, DNS_AUTHORITY);
                    CHECK_ERR(e);
                    break;
                }

                // any entry
                if(dns_state->query.question.qtype == ENTRY_ANY) {
                    ZoneListIterator it = {0};
                    zoneListIterInit(&it, &name->list);
                    while((entry = zoneListIterNext(&it)) != NULL) {
                        ExitStatus e = addAnswerField(dns_state,name->full_domain_name, entry, DNS_ANSWER);
                        CHECK_ERR(e);
                    }
                    break;
                }
        
                // requested
                entry = getEntry(&name->list, dns_state->query.question.qtype);
                if(entry != NULL) {
                    ZoneListIterator it = {0};
                    zoneListIterInit(&it, &name->list);
                    while((entry = zoneListIterNext(&it)) != NULL) {
                        if(entry->entry_type == dns_state->query.question.qtype) {
                            ExitStatus e = addAnswerField(dns_state, name->full_domain_name, entry, DNS_ANSWER);
                            CHECK_ERR(e);
                        }
                    }
                    break;
                }

                // doesnt exist, check cname
                entry = getEntry(&name->list, ENTRY_CNAME);

                if(entry != NULL) {
                    ZoneFileListTreePtr current_name = name;
                    ZoneFileListTreePtr current_zone = zone;
                    for(int8_t i = 0; i < 8; i++) {
                        ZoneEntryPtr cname = getEntry(&current_name->list, ENTRY_CNAME);
                        if(cname == NULL) {
                            break;
                        }

                        ExitStatus e = addAnswerField(dns_state,current_name->full_domain_name,cname,DNS_ANSWER);
                        CHECK_ERR(e);

                        // TODO check if exists, ...

                    }

                    break;
                }
            }
            // blocked
            return_flag = isBlocked(server->block_list_root, &dns_state->query.question.labels);
            if(return_flag) {
                dns_state->state = DNS_STATE_BLOCKED;
                response_header_flags |= RCODE_NXDOMAIN;
                break;
            }
            // forward 
            free(dns_state->reply);
            dns_state->state = DNS_STATE_FORWARDED;
            dns_state->reply = NULL;
            return STATUS_SUCCESS;
        }
        default: 
            return STATUS_FAILURE;
    }
    uShortToBytes(response_header_flags, dns_state->reply + 2);    
    return STATUS_SUCCESS;
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

    e = parseZoneList(&(parsed_args->zone_files), server->zone_file_root);
    CHECK_ERR(e);

    e = connectionVectorInit(&server->connections);
    CHECK_ERR(e);

    e = prepareSockets(parsed_args, &server->connections);
    CHECK_ERR(e);

    return STATUS_SUCCESS;
}


ExitStatus proxyServerStart(ProxyServerPtr server) {
    while(1) {
        int events = poll(server->connections.poll_fds, server->connections.curr_size, POLL_TIMEOUT);
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
    server->zone_file_root = NULL;
    blockListTreeDelete(server->block_list_root);
    server->block_list_root = NULL;
    connectionVectorClean(&server->connections);
}