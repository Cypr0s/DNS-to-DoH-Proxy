/**
 * @file    output.c
 * @author  Kristian Luptak
 * @brief   Contains printing functions
 *          
 * @date    2026-10-23
 */

#include "output.h"

/**
 * @brief       Converts state to string verdict
 * 
 * @param state Input state 
 * @return      char* 
 */
static char* getVerdict(uint8_t state);


/**
 * @brief       Converts rcode to string rcode or -
 * 
 * @param state Input state 
 * @return      char* 
 */
static char* getRcode(int8_t rcode_in);




/**
 * @brief       Converts q to string qtype or NULL
 * 
 * @param state Input state 
 * @return      char* 
 */
static void formatClient(struct sockaddr_storage* address, char* out, size_t out_size);

static void formatQname(char* str_in, char* str_out, size_t out_size);

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

        case RCODE_YXDOMAIN:
            return "YXDOMAIN";

        case -1:
            return "-";

        default:
            return NULL;
    }
}

static void formatClient(struct sockaddr_storage* address, char* out, size_t out_size) {
    char ip[INET6_ADDRSTRLEN]; // 46, also can hold 16 of IPV4
    // ipv4
    if(address->ss_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)address;
        inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip));
        snprintf(out, out_size, "%s:%u", ip, (unsigned)ntohs(ipv4->sin_port));
        //ipv6
    } else if(address->ss_family == AF_INET6) {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)address;
        // ipv4 mapped
        if(IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr)) {
            inet_ntop(AF_INET, &ipv6->sin6_addr.s6_addr[12], ip, sizeof(ip));
            snprintf(out, out_size, "%s:%u", ip, (unsigned)ntohs(ipv6->sin6_port));
        // ipv6
        } else {
            inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, sizeof(ip));
            snprintf(out, out_size, "[%s]:%u", ip, (unsigned)ntohs(ipv6->sin6_port));
        }
    }
}


static void formatQname(char* str_in, char* str_out, size_t out_size) {
    size_t in_pos = 0;
    size_t out_pos = 0;
    while(str_in[in_pos] != '\0') {
        uint8_t label_length = (uint8_t)str_in[in_pos++];
        for(uint8_t i = 0; i < label_length; i++) {
            unsigned char c = (unsigned char)str_in[in_pos++];
            if(c >= 'A' && c <= 'Z') {
                str_out[out_pos++] = (char)(c - 'A' + 'a');
            } else if( c == '.' || c == ';' || c == '(' || c == ')' || c == '@' || c == '$' || c == '\"' || c == '\\') {
                str_out[out_pos++] = '\\';
                str_out[out_pos++] = c; 
            } else if(c < 0x21 || c > 0x7E) {
                out_pos += (size_t)snprintf(str_out + out_pos, out_size - out_pos, "\\%03u", (unsigned)c);
            } else {
                str_out[out_pos++] = (char)c;
            }
        }
        str_out[out_pos++] = '.';
    }

    if(out_pos == 0) {
        str_out[out_pos++] = '.'; // root
    }
    str_out[out_pos] = '\0';
}


void createLogLine(char* out, size_t out_size, struct sockaddr_storage* address_in, DNSStatePtr dns_state, int8_t rcode_in) {
    // Time formatting taken from https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset
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

    // clieant addr
    char client[INET6_ADDRSTRLEN + 10] = "\0"; // "[" + address + "]:" + port
    formatClient(address_in, client, sizeof(client));

    // qname and qtype
    char qname[LONGEST_POSSIBLE_QNAME] = "-";
    char qtype[16] = "-";
    if(dns_state->flags & DNS_FLAG_PARSED_QUESTION) {
        formatQname(dns_state->query.question.question, qname, sizeof(qname));

        char* type = getZoneTypeName(dns_state->query.question.qtype);
        if(type != NULL) {
            strcpy(qtype, type);
        } else {
            snprintf(qtype, sizeof(qtype), "TYPE%u", (unsigned)dns_state->query.question.qtype);
        }
    }

    // verdict
    char* verdict = getVerdict(dns_state->state);

    // Rcode
    char rcode[10];
    char* value = getRcode(rcode_in);
    if(value != NULL) {
        strcpy(rcode, value);
    } else {
        snprintf(rcode, sizeof(rcode), "RCODE%d", (uint8_t)rcode_in);
    }

    snprintf(out, out_size, "%s %s %s %s %s %s\n", time, client, qname, qtype, verdict, rcode);
}


void printLogLine(char* line) {
    fprintf(stdout, "%s", line);
    fflush(stdout);
}