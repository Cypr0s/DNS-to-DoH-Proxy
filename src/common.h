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

// util
#define HELP_MESAGE "aaaaaa"
#define BINARY_NAME "isa-dnsproxy"

#endif // COMMON_H