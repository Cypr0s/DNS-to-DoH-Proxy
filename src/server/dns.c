#include "server/dns.h"

static ExitStatus skipDNSResourceRecords(char* bytes, size_t size, size_t* current_position, DNSStatePtr dns_state);
static void parseDNSHeader(char* bytes, DNSHeaderPtr query_header);
static ExitStatus parseDNSQuestion(char* bytes,size_t size, DNSQuestionPtr query_question, size_t* current_position);
static ExitStatus parseLabels(char* bytes, size_t size, StringListPtr labels, size_t* current_position);
static ExitStatus skipDNSRR(char* bytes, size_t size, size_t* current_position, DNSFlagsPtr flags);

ExitStatus parseDNSQuery(char* bytes, size_t size, DNSStatePtr dns_state) {
    // check 1: shorter than 12 octets → dropped;
    if(size < DNS_QUERY_MIN_LENGHT) {
        dns_state->state = DNS_STATE_DROPPED;
        return STATUS_SUCCESS;
    }

    parseDNSHeader(bytes, &(dns_state->query.header));
    // check 2: QR = 1 → dropped;
    if(dns_state->query.header.flags & QR) {
        dns_state->state = DNS_STATE_BLOCKED;
        return STATUS_SUCCESS;
    }
    // check 3: OPCODE ≠ QUERY → invalid, NOTIMP;
    uint16_t opcode = GET_OPCODE(dns_state->query.header.flags);
    if(opcode != 0) { // 0 == QUERY, 1 == IQuery ,...
        dns_state->state = DNS_STATE_INVALID_NOTIMP;
        return STATUS_SUCCESS;
    }
    // check 4: QDCOUNT ≠ 1 → invalid, FORMERR (RFC 9619; QDCOUNT = 0 by this specification);
    if(dns_state->query.header.qdcount != 1) {
        dns_state->state = DNS_STATE_INVALID_FORMERR;
        return STATUS_SUCCESS;
    }

    // check 5: parse question
    size_t current_position = DNS_QUERY_MIN_LENGHT;
    ExitStatus e = parseDNSQuestion(bytes, size, &(dns_state->query.question), &current_position);
    if(e == STATUS_FAILURE) {
        dns_state->state = DNS_STATE_INVALID_FORMERR;
        return STATUS_SUCCESS;
    } else if(e == STATUS_MALLOC_FAILURE) {
        return e;
    }
    dns_state->flags |= DNS_FLAG_PARSED_QUESTION;
    // check 6: skip RRs, check OPT RECORDS
    e = skipDNSResourceRecords(bytes, size, &current_position, dns_state);
    if(e != STATUS_SUCCESS) {
        dns_state->state = DNS_STATE_INVALID_FORMERR;
        return STATUS_SUCCESS;
    }
    dns_state->flags |= DNS_FLAG_PARSED_RRS;
    // check 7: QCLASS ≠ IN (including ANY) → invalid, NOTIMP;
    if(dns_state->query.question.qclass != QCLASS_IN) {
        dns_state->state = DNS_STATE_INVALID_NOTIMP;
        return STATUS_SUCCESS;
    }

    // check 8: QTYPE = AXFR or IXFR → invalid, REFUSED;
    if(dns_state->query.question.qtype == QTYPE_AXFR || dns_state->query.question.qtype == QTYPE_IXFR) {
        dns_state->state = DNS_STATE_INVALID_REFUSED;
        return STATUS_SUCCESS;
    }

    // check: 9 will be done after this (not a parsing check)
    dns_state->state = DNS_STATE_VALID;
    return STATUS_SUCCESS;
}


static void parseDNSHeader(char* bytes, DNSHeaderPtr query_header) {
    uint16_t* field = (uint16_t*) query_header;
    for(uint8_t i = 0; i < DNS_QUERY_MIN_LENGHT / 2; i++) {
        field[i] = bytesToUShort(bytes + (i * 2));
    }
}


static ExitStatus parseDNSQuestion(char* bytes,size_t size, DNSQuestionPtr query_question, size_t* current_position) {
    stringListInit(&(query_question->labels));
    ExitStatus e = parseLabels(bytes, size, &(query_question->labels), current_position);
    CHECK_ERR_AND_FREE(e, stringListDestroyFree(&(query_question->labels)););
    if (*current_position + 4 > size) {
        return STATUS_FAILURE;
    }

    query_question->qname = bytes + DNS_QUERY_MIN_LENGHT;
    query_question->qname_size = *current_position - DNS_QUERY_MIN_LENGHT;

    query_question->qtype = bytesToUShort(bytes + *current_position);
    *current_position += 2;

    query_question->qclass = bytesToUShort(bytes + *current_position);
    *current_position += 2;
    return STATUS_SUCCESS;
}


static ExitStatus parseLabels(char* bytes, size_t size, StringListPtr labels, size_t* current_position) {
    size_t name_length = 0;
    while(1) {
        if (*current_position >= size) {
            return STATUS_FAILURE;
        }
        uint8_t label_length = bytes[*current_position];
        name_length += label_length;

        // due to one octet being the size of label
        name_length++;
        (*current_position)++;

        if(label_length == 0) {
            break;
        }

        if (label_length > 191) {
            if (labels != NULL || *current_position >= size) {
                return STATUS_FAILURE;
            }
            (*current_position)++;
            return STATUS_SUCCESS;
        }

        if (label_length > 63 || 
            *current_position + label_length > size ||
            name_length > DNS_MAX_TOKEN_LENGTH + 1
        ) {
            return STATUS_FAILURE;
        }


        if (labels != NULL) {
            char *label = malloc(label_length + 1);
            if (label == NULL) {
                return STATUS_MALLOC_FAILURE;
            }

            memcpy(label, bytes + *current_position, label_length);
            label[label_length] = '\0';

            ExitStatus e = stringListInsert(labels, label);
            CHECK_ERR_AND_FREE(e, free(label););
        }

        *current_position += label_length;
    }
    return STATUS_SUCCESS;
}


static ExitStatus skipDNSRR(char* bytes, size_t size, size_t* current_position, DNSFlagsPtr dns_flags) {
    size_t start_position = *current_position;
    ExitStatus e = parseLabels(bytes, size, NULL, current_position);
    CHECK_ERR(e);

    if(*current_position + 10 > size) {
        return STATUS_FAILURE;
    }

    uint16_t type = bytesToUShort(bytes + *current_position);
    if (type == OPT_TYPE_RECORD) { // OPT
        *dns_flags |= DNS_FLAG_OPT;
        if(start_position + 1 == *current_position) {
            *dns_flags |= DNS_FLAG_IS_ROOT;
        }
    }
    *current_position += 2;

    // CLASS(2) + TLL(4)
    *current_position += 6;
    uint16_t rdlength = bytesToUShort(bytes + *current_position);
    *current_position += 2;

    if (*current_position + rdlength > size) {
        return STATUS_FAILURE;
    }
    *current_position += rdlength;
    return STATUS_SUCCESS;
}


static ExitStatus skipDNSResourceRecords(char* bytes, size_t size, size_t* current_position, DNSStatePtr dns_state) {
    for(uint16_t i = 0; i < dns_state->query.header.ancount; i++) {
        ExitStatus e = skipDNSRR(bytes, size, current_position, &dns_state->flags);
        CHECK_ERR(e);
        if(dns_state->flags & DNS_FLAG_OPT) {
            return STATUS_FAILURE;
        }
    }

    for(uint16_t i = 0; i <  dns_state->query.header.nscount; i++) {
        ExitStatus e = skipDNSRR(bytes, size, current_position, &dns_state->flags);
        CHECK_ERR(e);
        if(dns_state->flags & DNS_FLAG_OPT) {
            return STATUS_FAILURE;
        }
    }
    uint8_t opt_cnt = 0;
    for(uint16_t i = 0; i <  dns_state->query.header.arcount; i++) {
        dns_state->flags &= ~(DNS_FLAG_OPT | DNS_FLAG_IS_ROOT);
        ExitStatus e = skipDNSRR(bytes, size, current_position, &dns_state->flags);
        CHECK_ERR(e);
        if (dns_state->flags & DNS_FLAG_OPT) {
            opt_cnt++;

            if (opt_cnt > 1 || !(dns_state->flags & DNS_FLAG_IS_ROOT)) {
                return STATUS_FAILURE;
            }
        }
    }

    return STATUS_SUCCESS;
}


static ExitStatus createDnsAnswer(DNSStatePtr dns_state) {
    dns_state->reply = malloc(DNS_QUERY_UDP_SIZE); // dns only for now
    if(dns_state->reply == NULL) {
        return STATUS_MALLOC_FAILURE;
    }

    size_t offset = 0;
    // copy ID
    uShortToBytes(dns_state->query.header.id, dns_state->reply + offset);
    offset += 2;
    uint16_t flags = QR | RA;

    flags |= dns_state->query.header.flags & OPCODE;
    flags |= dns_state->query.header.flags & RD;
    flags |= dns_state->query.header.flags & CD;
    uShortToBytes(flags, dns_state->reply + offset);
    // TODO: copy question if parsed, then basic skelet is finished
}
