#ifndef SERVER_PROXY_H
#define SERVER_PROXY_H

#include "output.h"
#include "data-structures/proxy_server.h"
#include <signal.h>
extern volatile sig_atomic_t shutdown_status;


ExitStatus proxyServerStart(ProxyServerPtr server);

#endif // SERVER_PROXY_H