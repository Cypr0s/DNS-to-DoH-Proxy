#include "error.h"  
#include <sys/socket.h> // sockets
#include <unistd.h> // close
#include <netinet/in.h>
#include <arpa/inet.h>
#include "parsing/argument.h"
#include "data-structures/connection-dynamic-arr.h"

typedef enum {
    TRANSPORT_TCP = SOCK_STREAM,
    TRANSPORT_UDP = SOCK_DGRAM,
 } TransportType;

typedef enum {
    NETWORK_IPV6 = AF_INET6,
    NETWORK_IPV4 = AF_INET,
    NETWORK_BOTH = AF_INET6,
} NetworkType;

#define CONNECTION_REQUESTS_MAX 64 // 1 udp, 1 tcp - 64 client
#define UDP_SOCKET_POS 0
#define TCP_SOCKET_POS 1

ExitStatus prepareSockets(ParsedArgsPtr parsed_arguments, ConnectionVectorPtr connections);