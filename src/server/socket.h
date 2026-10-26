/**
 * @file    socket.h
 * @author  Kristian Luptak
 * @brief   Contains declarations of functions for working with sockets
 *          
 * @date    2026-10-23
 */


#ifndef SERVER_SOCKET_H
#define SERVER_SOCKET_H

#include "error.h"  
#include <sys/socket.h> // sockets
#include <sys/ioctl.h>
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
    NETWORK_IPV6 = 3,
    NETWORK_IPV4 = 2,
    NETWORK_BOTH = 1,
} NetworkType;

#define CONNECTION_REQUESTS_MAX 64 //  64 client

/**
 * @brief                   Creates UDP and TCP listening sockets
 * 
 * @param parsed_arguments  Parsed program arguments
 * @param connections       Connection vector to insert sockets into
 * @return                  ExitStatus 
 */
ExitStatus prepareSockets(ParsedArgsPtr parsed_arguments, ConnectionVectorPtr connections);

#endif // SERVER_SOCKET_H