#ifndef SERVER_DNS_H
#define SERVER_DNS_H

#include <stdio.h>
#include <stdint.h>
#include "util/string.h"
#include "data-structures/string-linked-list.h"

typedef enum {
    QR = 0x8000,
    AA = 0x0400,
    TC = 0x0200,
    RD = 0x0100,
    RA = 0x0080,
    Z = 0x0040,
    AD = 0x0020,
    CD = 0x0010
} DNSHeaderFlags;

typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DNSHeader, *DNSHeaderPtr;

typedef struct {
    char* qname;
    size_t qname_size;
    uint16_t qtype;
    uint16_t qclass;
    StringList labels;
} DNSQuestion, *DNSQuestionPtr;

typedef struct {
    DNSHeader header;
    DNSQuestion question;
} DNSQuery, *DNSQueryPtr;

#endif // SERVER_DNS_H

#define GET_OPCODE(value) (((value) >> 11) & 0x000F)
