/**
 * @file    output.h
 * @author  Kristian Luptak
 * @brief   Contains printing declarations
 *          
 * @date    2026-10-23
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include "error.h"
#include "common.h"
#include <time.h>
#include <stdio.h>
#include "server/dns.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * @brief               Create log line string
 * 
 * @param out           Out string
 * @param out_size      Out string size   
 * @param address_in    Input struct address
 * @param dns_state     Input state of the message
 * @param rcode_in      Input Rcode
 */
void createLogLine(char* out, size_t out_size, struct sockaddr_storage* address_in, DNSStatePtr dns_state, int8_t rcode_in);

/**
 * @brief       Prints line on stdout and flushes stdout
 * 
 * @param line  Line
 */
void printLogLine(char* line);

#endif // OUTPUT_H