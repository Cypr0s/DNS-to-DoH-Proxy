#include "server/socket.h"

ExitStatus createSocket(TransportType t, NetworkType n, int32_t* fd) {
    *fd = socket(n, t, 0);
    if(*fd == -1) {
        // todo
        return STATUS_FAILURE;
    }

    int val = 0;
    // https://stackoverflow.com/questions/22075363/dual-stack-with-one-socket
    if(n == NETWORK_BOTH) {
        if(setsockopt(*fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) < 0) {
            close(*fd);
            return STATUS_FAILURE;
        }
    }

    // https://www.ibm.com/docs/en/i/7.1.0?topic=designs-using-poll-instead-select
    val = 1;
    int rc = ioctl(*fd, FIONBIO, (char *)&val);
    if (rc < 0) {
        close(*fd);
        return STATUS_FAILURE;
    }
    return STATUS_SUCCESS;
}


ExitStatus bindSocket(int* fd, char* address, uint16_t port, NetworkType n, TransportType t) {

    struct sockaddr_storage addr = {0};

    if(n == NETWORK_IPV4) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
        if(address == NULL) {
            ipv4->sin_addr.s_addr = htonl(INADDR_ANY);
        } else if(inet_pton(n, address, &ipv4->sin_addr) != 1) {
            // TODO
            return STATUS_FAILURE;
        }

        ipv4->sin_family = n;
        ipv4->sin_port = htons(port);
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;

        if(address == NULL) {
            ipv6->sin6_addr = in6addr_any;
        } else if(inet_pton(n, address, &ipv6->sin6_addr) != 1) {
            // TODO
            return STATUS_FAILURE;
        }

        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
    }

    socklen_t addr_len = n == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    if (bind(*fd, (struct sockaddr *)&addr, addr_len) < 0) {
        return STATUS_EX_UNAVAIABLE;
    }

    if(t == TRANSPORT_TCP) {
        if(listen(*fd, CONNECTION_REQUESTS_MAX) == -1) {
            return STATUS_FAILURE;
        }
    }
    

    return STATUS_SUCCESS;
}


ExitStatus prepareSockets(ParsedArgsPtr parsed_arguments, ConnectionVectorPtr connections) {
    NetworkType n;
    if(parsed_arguments->flags & ARG_ADDRESS) {
        if(parsed_arguments->address == NULL) {
            return STATUS_FAILURE;
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

    int udp_fd;
    ExitStatus e = createSocket(TRANSPORT_UDP, n, &udp_fd);
    CHECK_ERR(e);
    e = bindSocket(&udp_fd, parsed_arguments->address, parsed_arguments->port, n, TRANSPORT_UDP);
    CHECK_ERR(e);
    struct pollfd fd = {.fd = udp_fd, .events = POLLIN, .revents = 0};
    Connection c = {0};
    e = connectionVectorInsert(connections, fd, c);
    CHECK_ERR(e);
    // PRINT LISTEN HERE

    int tcp_fd;
    e = createSocket(TRANSPORT_TCP, n, &tcp_fd);
    CHECK_ERR(e);
    e = bindSocket(&tcp_fd, parsed_arguments->address, parsed_arguments->port, n, TRANSPORT_TCP);
    CHECK_ERR(e);
    fd = (struct pollfd){.fd = tcp_fd, .events = POLLIN, .revents = 0};
    c = (Connection){0};
    e = connectionVectorInsert(connections, fd, c);
    CHECK_ERR(e);
    // PRINT LISTEN HERE

    return STATUS_SUCCESS;
}