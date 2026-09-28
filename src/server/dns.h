#include <stdio.h>
#include <stdint.h>
#include "util/strings.h"

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
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} DNSHeader;

typedef struct {
    char* q_name;
    uint16_t q_type;
    uint16_t q_class;
} DNSQuestion;

typedef struct {
    DNSHeader header;
    DNSQuestion question;
} DNSQuery;
