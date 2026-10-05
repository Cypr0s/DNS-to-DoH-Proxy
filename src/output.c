#include "output.h"


static char* getVerdict(uint8_t state) {
    switch(state) {
        case DNS_STATE_DROPPED:
            return "dropped";

        case DNS_STATE_BLOCKED:
            return "blocked";

        case DNS_STATE_INVALID_FORMERR:
        case DNS_STATE_INVALID_NOTIMP:
        case DNS_STATE_INVALID_REFUSED:
            return "invalid";

        case DNS_STATE_LOCAL:
            return "local";

        case DNS_STATE_FORWARDED:
            return "forwarded";
        default:
            return NULL;
    }
}

static char* getRcode(int8_t rcode_in) {
    switch(rcode_in) {
        case RCODE_NOERROR:
            return "NOERROR";

        case RCODE_FORMERR:
            return "FORMERR";

        case RCODE_SERVFAIL:
            return "SERVFAIL";

        case RCODE_NXDOMAIN:
            return "NXDOMAIN";

        case RCODE_NOTIMP:
            return "NOTIMP";

        case RCODE_REFUSED:
            return "REFUSED";

        case -1:
            return "-";

        default:
            return NULL;
    }
}


static char* getQtype(uint16_t qtype) {
    switch(qtype) {
        case ENTRY_A:
            return "A";

        case ENTRY_AAAA:
            return "AAAA";

        case ENTRY_NS:
            return "NS";

        case ENTRY_SOA:
            return "SOA";

        case ENTRY_CNAME:
            return "CNAME";

        case ENTRY_MX:
            return "MX";

        case ENTRY_ANY:
            return "ANY";

        default:
            return NULL;
    }
}


void logDNSMessage(struct sockaddr_storage* address_in, uint32_t address_in_size, char* qname_in, size_t qname_in_size, uint8_t qtype_in, uint8_t state_in, int8_t rcode_in) {
    // https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset
    time_t now;
    time(&now);
    struct tm *p = localtime(&now);
    char time[100];
    size_t len = strftime(time, sizeof(time) - 1, "%FT%T%z", p);
    // move last 2 digits
    if (len > 1) {
        char minute[] = { time[len-2], time[len-1], '\0' };
        sprintf(time + len - 2, ":%s", minute);
    }

    (void)address_in;
    (void)address_in_size;
    (void)qname_in;
    (void)qname_in_size;

    char* verdict = getVerdict(state_in);

    char qtype[10];
    char* value = getQtype(qtype_in);
    if(value != NULL) {
        strcpy(qtype, value);
    } else {
        snprintf(qtype, sizeof(qtype), "TYPE%d", qtype_in);
    }


    char rcode[10];
    value = getRcode(rcode_in);
    if(value != NULL) {
        strcpy(rcode, value);
    } else {
        snprintf(rcode, sizeof(rcode), "RCODE%d", (uint8_t)rcode_in);
    }

    printf("%s %s %s %s %s %s\n", time, "address", "qname", qtype, verdict, rcode);
}
