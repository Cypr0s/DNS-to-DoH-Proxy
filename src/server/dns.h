#ifndef SERVER_DNS_H
#define SERVER_DNS_H

#include <stdio.h>
#include <stdint.h>
#include "util/string.h"
#include "data-structures/string-linked-list.h"
#include "data-structures/zone-file-tree.h"

typedef enum {
    QR = 0x8000,
    OPCODE = 0x7800, // mask
    AA = 0x0400,
    TC = 0x0200,
    RD = 0x0100,
    RA = 0x0080,
    Z = 0x0040,
    AD = 0x0020,
    CD = 0x0010
} DNSHeaderFlags;

typedef enum {
    RCODE_NOERROR = 0,
    RCODE_FORMERR = 1,
    RCODE_SERVFAIL = 2,
    RCODE_NXDOMAIN = 3,
    RCODE_NOTIMP = 4,
    RCODE_REFUSED = 5,
    RCODE_YXDOMAIN = 6,
} RcodeEnum;

typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DNSHeader, *DNSHeaderPtr;

typedef struct {
    char* question;
    size_t question_size;
    uint16_t qtype;
    uint16_t qclass;
    StringList labels;
} DNSQuestion, *DNSQuestionPtr;

typedef struct {
    DNSHeader header;
    DNSQuestion question;
    uint16_t opt_size;
} DNSQuery, *DNSQueryPtr;

typedef enum {
    DNS_STATE_DROPPED,
    DNS_STATE_INVALID_NOTIMP,
    DNS_STATE_INVALID_FORMERR,
    DNS_STATE_INVALID_REFUSED,
    DNS_STATE_LOCAL,
    DNS_STATE_BLOCKED,
    DNS_STATE_FORWARDED,
    DNS_STATE_VALID, // will be transfromed into blocked, forwarded or local
} DNSQueryReturnState, *DNSQueryReturnStatePtr;

typedef enum {
    DNS_FLAG_OPT = 0x01,
    DNS_FLAG_IS_ROOT = 0x02,
    DNS_FLAG_PARSED_QUESTION = 0x04,
    DNS_FLAG_PARSED_RRS = 0x08,
    DNS_FLAG_ENTRY_NOT_FOUND = 0x10,
    DNS_FLAG_NAME_DOESNT_EXIST = 0x20,
} DNSFlags, *DNSFlagsPtr;
typedef struct {
    DNSQuery query;
    char* reply;
    size_t reply_max_size;
    size_t reply_current_size;
    DNSQueryReturnState state;
    DNSFlags flags;
} DNSState, *DNSStatePtr;

#define GET_OPCODE(value) (((value) >> 11) & 0x000f)
#define GET_RCODE(value) ((value) & 0x000f)
#define OPT_TYPE_RECORD 41
#define OPT_BARE_SIZE 11 // 1 for qname + 2(class) + 2(type) + 4(ttl) + 2(rdata)
#define OPT_MAX_SIZE 1232
#define DNS_UDP_WITHOUT_OPT 512
#define QCLASS_IN 1
#define QTYPE_AXFR 252
#define QTYPE_IXFR 251

typedef enum {
    DNS_ANSWER,
    DNS_AUTHORITY,
    DNS_ADDITIONAL,
} DNSFieldType;

ExitStatus parseDNSQuery(char* bytes, size_t size, DNSStatePtr dns_state);

ExitStatus createDNSAnswer(DNSStatePtr dns_state);

ExitStatus addAnswerField(DNSStatePtr dns_state, char* owner, size_t owner_size, ZoneEntryPtr zone_entry, DNSFieldType type);

void addOPT(DNSStatePtr dns_state);

void truncateUDP(DNSStatePtr dns_state);

void dnsStateDtor(DNSStatePtr dns_state);

#endif // SERVER_DNS_H