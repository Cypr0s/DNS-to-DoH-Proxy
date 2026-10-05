#ifndef CONNECTION_DYNAMIC_ARR_H
#define CONNECTION_DYNAMIC_ARR_H

#include <stdio.h>
#include "common.h"
#include <poll.h>
#include "error.h"
#include <unistd.h> // close
#include <stdint.h>
#include <sys/socket.h>

typedef enum {
    UDP_LISTEN,
    TCP_LISTEN,
    TCP_CLIENT,
} ConnectionType;

typedef struct connection_node {
    struct timespec last_event;
    ConnectionType type;
    struct sockaddr_storage address;
    int32_t address_size;
    char message_buffer[DNS_QUERY_MAX_SIZE];
    uint16_t currently_received;
    uint16_t message_size;
} Connection, *ConnectionPtr;

typedef struct {
    struct pollfd *poll_fds;
    ConnectionPtr connections;
    size_t capacity;
    size_t curr_size;
} ConnectionVector, *ConnectionVectorPtr;

ExitStatus connectionVectorInit(ConnectionVectorPtr vector);

ExitStatus connectionVectorInsert(ConnectionVectorPtr vector, struct pollfd poll_fd, Connection con);

ExitStatus connectionVectorDelete(ConnectionVectorPtr vector, int fd);

void connectionVectorClean(ConnectionVectorPtr vector);

#endif // CONNECTION_DYNAMIC_ARR_H
