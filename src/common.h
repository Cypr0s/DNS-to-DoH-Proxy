/**
 * @file    common.h
 * @author  Kristian Luptak
 * @brief   Contains shared information about the project
 *          
 * @date    2026-10-23
 */

#ifndef COMMON_H
#define COMMON_H

// data structures
#define ARRAY_SIZE(arr) sizeof(arr) / sizeof(arr[0])
#define VECTOR_DEFAULT_SIZE 8 // items
#define VECTOR_UPSIZE_DOWNSIZE 2 // items

// networking
#define DNS_MAX_TOKEN_LENGTH 254 // char
#define DNS_MAX_LABEL_COUNT 127 // chars
#define DNS_MAX_LABEL_LENGTH 63 // chars
#define TCP_MESSAGE_SIZE_BYTES 2
#define LONGEST_IPV6 45 // bytes
#define POLL_TIMEOUT 150 // 
#define DNS_QUERY_MIN_LENGHT 12 // octets
#define TCP_CONNECTION_TIMEOUT 10 // seconds
#define DNS_QUERY_MAX_SIZE 65536
#define IP_ADDRESS_BYTES 4
#define IPV6_ADDRESS_BYTES 16
#define MAX_FORWARDED_REQUESTS 128


// printing
#define LONGEST_POSSIBLE_QNAME 1005 // ((63 * 3) + 61) * 4 + 4 * ('.') == 1005
#define LOG_LINE_MAX 1150 // 25 time + 53 client + 1005 qname +  9 qtype + 9 verdict + 8 rcode + 6 spaces + newline + gap

// util 

// HELP MESSAGE IS AI GENERATED
#define HELP_MESAGE \
"Usage:\n" \
"  isa-dnsproxy -u DOH_URL [-p PORT] [-a ADDRESS] [-z ZONEFILE]... [-b BLOCKLIST]...\n" \
"               [-w TIMEOUT] [--insecure]\n" \
"  isa-dnsproxy -h | --help\n" \
"\n" \
"DNS proxy that serves local zones, blocks listed domains and forwards\n" \
"everything else to a DNS-over-HTTPS upstream (RFC 8484).\n" \
"\n" \
"Options:\n" \
"  -u DOH_URL     upstream DoH endpoint, https:// (or http:// for testing). Required.\n" \
"  -p PORT        UDP and TCP port to listen on, 1..65535 (default 53).\n" \
"  -a ADDRESS     literal IPv4 or IPv6 address to bind (default: all addresses).\n" \
"  -z ZONEFILE    zone file to serve; may be repeated.\n" \
"  -b BLOCKLIST   blocklist file; blocked names get NXDOMAIN; may be repeated.\n" \
"  -w TIMEOUT     upstream timeout in seconds, 1..3600 (default 3).\n" \
"  --insecure     do not verify the upstream TLS certificate or hostname.\n" \
"  -h, --help     show this help and exit.\n"

#define BINARY_NAME "isa-dnsproxy"

#endif // COMMON_H