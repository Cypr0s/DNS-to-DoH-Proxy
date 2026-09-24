#include "error.h"  
#include <sys/socket.h> // sockets
#include <unistd.h> // close
#include <netinet/in.h>
#include <arpa/inet.h>

typedef enum {
    TRANSPORT_TCP,
    TRANSPORT_UDP,
 } TransportType;

typedef enum {
    NETWORK_IPV6,
    NETWORK_IPV4,
    NETWORK_BOTH,
}NetworkType;