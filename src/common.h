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
#define LONGEST_IPV6 45 // bytes
#define POLL_TIMEOUT 150 // 
#define DNS_QUERY_MIN_LENGHT 12 // octets
#define TCP_CONNECTION_TIMEOUT 10 // seconds
#define DNS_QUERY_UDP_SIZE 512
// util
#define HELP_MESAGE "aaaaaa"
#define BINARY_NAME "isa-dnsproxy"

#endif // COMMON_H
