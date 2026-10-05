#include "server/proxy.h"

static ExitStatus acceptConnections(int fd, ConnectionVectorPtr connections);
static ExitStatus processUDPMessages(int fd, ProxyServerPtr server);
static ExitStatus handleEvents(ProxyServerPtr server);
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
        struct timespec last_event;
        ExitStatus e = getTime(&last_event);
        CHECK_ERR(e);
        Connection c = {.type = TCP_CLIENT, .last_event = last_event, .address = addr, .address_size = addr_len};
        struct pollfd poll_fd = {.fd = new_fd, .events = POLLIN, .revents = 0}; 
        e = connectionVectorInsert(connections, poll_fd, c);
        CHECK_ERR(e);
    }
    return STATUS_SUCCESS;
}


static ExitStatus processUDPMessages(int fd, ProxyServerPtr server) {
    uint8_t bytes[DNS_QUERY_MAX_SIZE];
    struct sockaddr_storage address;
    socklen_t address_size = sizeof(struct sockaddr_storage);
    while(1) {
        address_size = sizeof(struct sockaddr_storage);
        ssize_t msg_size = recvfrom(fd, bytes, DNS_QUERY_MAX_SIZE, 0, (struct sockaddr *)&address, &address_size);
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
        int8_t rcode = -1;
        // response
        if(dns_state.reply != NULL) {
            msg_size = sendto(fd, dns_state.reply, dns_state.reply_max_size, 0, (struct sockaddr*) &address, address_size);
            if(msg_size < 0) {
                return STATUS_FAILURE;
            }
            uint16_t flags = bytesToUShort(dns_state.reply + 2);
            rcode = flags & 0x000f;
            free(dns_state.reply);
        }
        logDNSMessage(&address, address_size, dns_state.query.question.question, dns_state.query.question.question_size, dns_state.query.question.qtype, dns_state.state, rcode);
    }
    return STATUS_SUCCESS;
}

static ExitStatus processTCPMessages(int fd, ProxyServerPtr server) {
    //TODO
    ssize_t bytes = recv(fd);
    return STATUS_SUCCESS;
}


static ExitStatus getTime(struct timespec* time) {
    if(clock_gettime(CLOCK_MONOTONIC, time) != 0) {
        return STATUS_FAILURE;
    }
    return STATUS_SUCCESS;
}


// https://github.com/Cypr0s/L4scan/blob/main/src/util.c
static ExitStatus getTimeDifference(struct timespec start_time, size_t* out_val) {
    struct timespec current_time;

    if(clock_gettime(CLOCK_MONOTONIC, &current_time) != 0) {
        return STATUS_FAILURE;
    }

    *out_val = (size_t)((current_time.tv_sec - start_time.tv_sec) * 1000L + (current_time.tv_nsec - start_time.tv_nsec) / 1000000L);
    return STATUS_SUCCESS;
}

static ExitStatus handleEvents(ProxyServerPtr server) {
    ExitStatus e = STATUS_SUCCESS;
    for(size_t i = 0; i < server->connections.curr_size; i++) {
        if(server->connections.poll_fds[i].revents == 0) {
            continue;
        }
        switch(server->connections.connections[i].type) {
            case UDP_LISTEN:
                e = processUDPMessages(server->connections.poll_fds[i].fd, server);
                CHECK_ERR(e);
                break;
            case TCP_LISTEN:
                e = acceptConnections(server->connections.poll_fds[i].fd, &server->connections);
                CHECK_ERR(e);
                break;
            case TCP_CLIENT:
                e = processTCPMessages(server->connections.poll_fds[i].fd, server);
                CHECK_ERR(e);
                if(server->connections.connections[i].type == TCP_CLIENT) {
                    // check timeout, close connection
                    // firstly check if no outstanding connections
                    size_t time_difference;
                    e = getTimeDifference(server->connections.connections[i].last_event, &time_difference);
                    if(time_difference > TCP_CONNECTION_TIMEOUT * 1000) {
                        e = connectionVectorDelete(&server->connections, server->connections.poll_fds[i].fd);
                        CHECK_ERR(e);
                        i--;
                        continue;
                    }
                }
                break;
            default:
                break;
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
    CHECK_ERR(e);
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
                    ZoneFileListTreePtr seen[8] = {0};
                    int8_t seen_count = 0;
                    for(int8_t i = 0; i < 8; i++) {
                        uint8_t flag = 0;
                        for(int8_t j = 0; j < seen_count; j++) {
                            if(seen[j] == current_name) {
                                flag = 1;
                                response_header_flags |= RCODE_NOERROR;
                                break;
                                // end search
                            }
                        }

                        seen[seen_count++] = current_name;
                        if(flag == 1) {
                            break;
                        }
                        ZoneEntryPtr cname = getEntry(&current_name->list, ENTRY_CNAME);
                        if(cname == NULL) {
                            break;
                        }

                        ExitStatus e = addAnswerField(dns_state, current_name->full_domain_name, cname, DNS_ANSWER);
                        CHECK_ERR(e);

                        return_flag = isInZone(server->zone_file_root, &cname->entry.cname_entry.list, &current_zone, &current_name);
                        if(!return_flag) {
                            break;
                        }

                        if(current_name == NULL) {
                            response_header_flags |= RCODE_NXDOMAIN;
                            ZoneEntryPtr soa = getEntry(&current_zone->list,ENTRY_SOA);
                            e = addAnswerField(dns_state, current_zone->full_domain_name, soa, DNS_AUTHORITY);
                            CHECK_ERR(e);
                            break;
                        }

                        entry = getEntry(&current_name->list, dns_state->query.question.qtype);
                        if(entry != NULL) {
                            response_header_flags |= RCODE_NOERROR;
                            ZoneListIterator it = {0};
                            zoneListIterInit(&it, &current_name->list);
                            while((entry = zoneListIterNext(&it)) != NULL) {
                                if(entry->entry_type == dns_state->query.question.qtype) {
                                    e = addAnswerField(dns_state, current_name->full_domain_name, entry,DNS_ANSWER);
                                    CHECK_ERR(e);
                                }
                            }
                            break;
                        }   
                    }
                }
                break;
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
            ExitStatus e = handleEvents(server);
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