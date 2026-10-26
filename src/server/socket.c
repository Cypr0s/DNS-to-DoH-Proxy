/**
 * @file    socket.c
 * @author  Kristian Luptak
 * @brief   Contains functions for working with sockets
 *          
 * @date    2026-10-23
 */

#include "server/socket.h"

/**
 * @brief       Creates non-blocking socket
 * 
 * @param t     Transport type (UDP/TCP)
 * @param n     Network type (IPv4/IPv6/both)
 * @param fd    Output file descriptor
 * @return      ExitStatus 
 */
static ExitStatus createSocket(TransportType t, NetworkType n, int32_t* fd);

/**
 * @brief           Binds socket to address and port, starts listening for TCP
 * 
 * @param fd        Socket file descriptor
 * @param address   Local address, NULL for any
 * @param port      Local port
 * @param n         Network type (IPv4/IPv6/both)
 * @param t         Transport type (UDP/TCP)
 * @return          ExitStatus 
 */
static ExitStatus bindSocket(int* fd, char* address, uint16_t port, NetworkType n, TransportType t);


static ExitStatus createSocket(TransportType t, NetworkType n, int32_t* fd) {
    int8_t network_type = n == NETWORK_IPV4 ? AF_INET : AF_INET6; 
    *fd = socket(network_type, t, 0);
    if(*fd == -1) {
        PRINT_ERROR("Cant open socket");
        return STATUS_FAILURE;
    }

    int val = 0;
    // dual socket
    // taken from https://stackoverflow.com/questions/22075363/dual-stack-with-one-socket
    if(n == NETWORK_BOTH) {
        if(setsockopt(*fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) < 0) {
            close(*fd);
            PRINT_ERROR("Cant open dual socket");
            return STATUS_FAILURE;
        }
    }

    // make socket non-blocking: taken from https://www.ibm.com/docs/en/i/7.1.0?topic=designs-using-poll-instead-select
    val = 1;
    int rc = ioctl(*fd, FIONBIO, (char *)&val);
    if (rc < 0) {
        close(*fd);
        PRINT_ERROR("Cant make socket non-blocking");
        return STATUS_FAILURE;
    }

    if(setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        close(*fd);
        PRINT_ERROR("Cant set reuse addr");
        return STATUS_FAILURE;
    }
    return STATUS_SUCCESS;
}


static ExitStatus bindSocket(int* fd, char* address, uint16_t port, NetworkType n, TransportType t) {
    int8_t network_type = n == NETWORK_IPV4 ? AF_INET : AF_INET6; 
    struct sockaddr_storage addr = {0};

    if(n == NETWORK_IPV4) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
        if(address == NULL) {
            ipv4->sin_addr.s_addr = htonl(INADDR_ANY);
        } else if(inet_pton(network_type, address, &ipv4->sin_addr) != 1) {
            PRINT_ARGUMENT_PARSE_ERROR("`%s` address is invalid", address);
            return STATUS_EX_USAGE;
        }

        ipv4->sin_family = network_type;
        ipv4->sin_port = htons(port);
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;

        if(address == NULL) {
            ipv6->sin6_addr = in6addr_any;
        } else if(inet_pton(network_type, address, &ipv6->sin6_addr) != 1) {
            PRINT_ARGUMENT_PARSE_ERROR("`%s` address is invalid", address);
            return STATUS_EX_USAGE;
        }

        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
    }

    socklen_t addr_len = n == NETWORK_IPV4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    // bind socket
    if(bind(*fd, (struct sockaddr *)&addr, addr_len) < 0) {
        const char* shown = address ? address : (n == NETWORK_IPV4 ? "0.0.0.0" : "::");
        PRINT_ARGUMENT_PARSE_ERROR("Cant bind to address `%s`", shown);
        return STATUS_EX_UNAVAIABLE;
    }

    // make socket able to accept connections
    if(t == TRANSPORT_TCP) {
        if(listen(*fd, CONNECTION_REQUESTS_MAX) == -1) {
            PRINT_ERROR("Cant listen on socket");
            return STATUS_FAILURE;
        }
    }

    // print listening
    if(n == NETWORK_IPV4) {
        PRINT_LISTENING_SOCKET(address, port);
    } else {
        if(address == NULL) {
            PRINT_LISTENING_SOCKET("0.0.0.0", port);
            PRINT_LISTENING_SOCKET_V6("::", port);
        } else {
            PRINT_LISTENING_SOCKET_V6(address, port);
        }
    }
    return STATUS_SUCCESS;
}


ExitStatus prepareSockets(ParsedArgsPtr parsed_arguments, ConnectionVectorPtr connections) {
    NetworkType n;
    if(parsed_arguments->flags & ARG_ADDRESS) {
        if(parsed_arguments->address == NULL) {
            PRINT_ERROR("Missing local address");
            return STATUS_EX_USAGE;
        }
        char* c = strchr(parsed_arguments->address, ':');
        if(c == NULL) {
            n = NETWORK_IPV4;
        } else {
            n = NETWORK_IPV6;
        }
    } else {
        n = NETWORK_BOTH;
    }

    // udp
    int udp_fd;
    ExitStatus e = createSocket(TRANSPORT_UDP, n, &udp_fd);
    CHECK_ERR(e);
    e = bindSocket(&udp_fd, parsed_arguments->address, parsed_arguments->port, n, TRANSPORT_UDP);
    CHECK_ERR(e);
    struct pollfd fd = {.fd = udp_fd, .events = POLLIN, .revents = 0};
    Connection c = {.type = UDP_LISTEN};
    e = connectionVectorInsert(connections, fd, c);
    CHECK_ERR(e);

    // tcp listening
    int tcp_fd;
    e = createSocket(TRANSPORT_TCP, n, &tcp_fd);
    CHECK_ERR(e);
    e = bindSocket(&tcp_fd, parsed_arguments->address, parsed_arguments->port, n, TRANSPORT_TCP);
    CHECK_ERR(e);
    fd = (struct pollfd){.fd = tcp_fd, .events = POLLIN, .revents = 0};
    c = (Connection){.type = TCP_LISTEN}; // {0} would make it UDP_LISTEN (first enum value)
    e = connectionVectorInsert(connections, fd, c);
    CHECK_ERR(e);

    return STATUS_SUCCESS;
}