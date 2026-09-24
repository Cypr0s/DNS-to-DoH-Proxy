#include "server/sockets.h"

ExitStatus createSocket(TransportType t, NetworkType n, int32_t* fd) {
    //ipv4 sockets
    int t_type = (t == TRANSPORT_TCP) ? SOCK_STREAM : SOCK_DGRAM;
    int n_type = (n == NETWORK_IPV4) ? AF_INET : AF_INET6;

    *fd = socket(t_type, n_type, 0);
    if(*fd == -1) {
        // todo
        return STATUS_FAILURE;
    }

    int val = 0;
    // https://stackoverflow.com/questions/22075363/dual-stack-with-one-socket
    if(n_type == NETWORK_BOTH) {
        if(setsockopt(*fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) < 0) {
            close(*fd);
            return STATUS_FAILURE;
        }
    }
    return STATUS_SUCCESS;
}


ExitStatus bindSocket(int32_t* fd, char* address, uint16_t port, NetworkType n) {
    int family_type = (n == NETWORK_IPV4) ? AF_INET : AF_INET6;


    struct sockaddr_storage addr = {0};

    if(family_type == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
        if(address == NULL) {
            ipv4->sin_addr.s_addr = htonl(INADDR_ANY);
        } else if(inet_pton(AF_INET, address, &ipv4->sin_addr) != 1) {
            // TODO
            return STATUS_FAILURE;
        }

        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(port);
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;

        if(address == NULL) {
            ipv6->sin6_addr = in6addr_any;
        } else if(inet_pton(AF_INET6, address, &ipv6->sin6_addr) != 1) {
            return STATUS_FAILURE;
        }

        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
    }

    socklen_t addr_len =  family_type == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0) {
        return STATUS_EX_UNAVAIABLE;
    }

    return STATUS_SUCCESS;
}
