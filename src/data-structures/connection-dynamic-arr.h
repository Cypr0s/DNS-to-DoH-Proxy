#include <stdio.h>
#include "common.h"
#include <poll.h>
#include "error.h"
#include <unistd.h> // close

typedef enum {
    UDP_LISTEN,
    TCP_LISTEN,
    TCP_CLIENT,
    TCP_UPSTREAM,
    UDP_UPSTREAM
} ConnectionType;

typedef struct connection_node {
    int32_t timeout;
    ConnectionType type;
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
