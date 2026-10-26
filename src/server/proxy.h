/**
 * @file    proxy.h
 * @author  Kristian Luptak
 * @brief   Contains declaration Main function loop receiving and sending queries
 *          
 * @date    2026-10-23
 */

#ifndef SERVER_PROXY_H
#define SERVER_PROXY_H

#include "output.h"
#include "data-structures/proxy-server.h"
#include <signal.h>
extern volatile sig_atomic_t shutdown_status;

/**
 * @brief           Runs main server loop
 * 
 * @param server    Proxy server
 * @return          ExitStatus 
 */
ExitStatus proxyServerStart(ProxyServerPtr server);

#endif // SERVER_PROXY_H