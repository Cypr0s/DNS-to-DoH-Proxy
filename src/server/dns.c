#include "server/dns.h"

static ExitStatus skipDNSResourceRecords(char* bytes, size_t size, size_t* current_position, DNSStatePtr dns_state);
static void parseDNSHeader(char* bytes, DNSHeaderPtr query_header);
static ExitStatus parseDNSQuestion(char* bytes,size_t size, DNSQuestionPtr query_question, size_t* current_position);
static ExitStatus parseLabels(char* bytes, size_t size, StringListPtr labels, size_t* current_position);
static ExitStatus skipDNSRR(char* bytes, size_t size, size_t* current_position, DNSFlagsPtr flags, uint16_t* opt_size);

ExitStatus parseDNSQuery(char* bytes, size_t size, DNSStatePtr dns_state) {
    // check 1: shorter than 12 octets → dropped;
    if(size < DNS_QUERY_MIN_LENGHT) {
        dns_state->state = DNS_STATE_DROPPED;
        return STATUS_SUCCESS;
    }

    parseDNSHeader(bytes, &(dns_state->query.header));
    // check 2: QR = 1 → dropped;
    if(dns_state->query.header.flags & QR) {
        dns_state->state = DNS_STATE_DROPPED;
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
    query_header->id = bytesToUShort(bytes + 0);
    query_header->flags = bytesToUShort(bytes + 2);
    query_header->qdcount = bytesToUShort(bytes + 4);
    query_header->ancount = bytesToUShort(bytes + 6);
    query_header->nscount = bytesToUShort(bytes + 8);
    query_header->arcount = bytesToUShort(bytes + 10);
}


static ExitStatus parseDNSQuestion(char* bytes,size_t size, DNSQuestionPtr query_question, size_t* current_position) {
    stringListInit(&(query_question->labels));
    ExitStatus e = parseLabels(bytes, size, &(query_question->labels), current_position);
    CHECK_ERR_AND_FREE(e, stringListDestroyFree(&(query_question->labels)););
    if (*current_position + 4 > size) {
        return STATUS_FAILURE;
    }

    query_question->qtype = bytesToUShort(bytes + *current_position);
    *current_position += 2;

    query_question->qclass = bytesToUShort(bytes + *current_position);
    *current_position += 2;

    query_question->question = bytes + DNS_QUERY_MIN_LENGHT;
    query_question->question_size = *current_position - DNS_QUERY_MIN_LENGHT;
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


static ExitStatus skipDNSRR(char* bytes, size_t size, size_t* current_position, DNSFlagsPtr dns_flags, uint16_t* opt_size) {
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
        *opt_size = bytesToUShort(bytes + *current_position + 2);
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
        ExitStatus e = skipDNSRR(bytes, size, current_position, &dns_state->flags, &dns_state->query.opt_size);
        CHECK_ERR(e);
        if(dns_state->flags & DNS_FLAG_OPT) {
            return STATUS_FAILURE;
        }
    }

    for(uint16_t i = 0; i <  dns_state->query.header.nscount; i++) {
        ExitStatus e = skipDNSRR(bytes, size, current_position, &dns_state->flags, &dns_state->query.opt_size);
        CHECK_ERR(e);
        if(dns_state->flags & DNS_FLAG_OPT) {
            return STATUS_FAILURE;
        }
    }
    uint8_t opt_cnt = 0;
    for(uint16_t i = 0; i <  dns_state->query.header.arcount; i++) {
        dns_state->flags &= ~(DNS_FLAG_OPT | DNS_FLAG_IS_ROOT);
        ExitStatus e = skipDNSRR(bytes, size, current_position, &dns_state->flags, &dns_state->query.opt_size);
        CHECK_ERR(e);
        if (dns_state->flags & DNS_FLAG_OPT) {
            opt_cnt++;

            if (opt_cnt > 1 || !(dns_state->flags & DNS_FLAG_IS_ROOT)) {
                return STATUS_FAILURE;
            }
        }
    }

    if(opt_cnt == 1) {
        dns_state->flags |= DNS_FLAG_OPT;
    }

    return STATUS_SUCCESS;
}


ExitStatus createDNSAnswer(DNSStatePtr dns_state) {
    dns_state->reply = malloc(DNS_QUERY_MAX_SIZE); // dns only for now
    if(dns_state->reply == NULL) {
        return STATUS_MALLOC_FAILURE;
    }
    memset(dns_state->reply, 0, DNS_QUERY_MAX_SIZE);
    // copy ID
    uShortToBytes(dns_state->query.header.id, dns_state->reply + dns_state->reply_current_size);
    dns_state->reply_current_size += 2;
    uint16_t flags = QR | RA;

    flags |= dns_state->query.header.flags & OPCODE;
    flags |= dns_state->query.header.flags & RD;
    flags |= dns_state->query.header.flags & CD;
    uShortToBytes(flags, dns_state->reply + dns_state->reply_current_size);

    // qcounts 
    dns_state->reply_current_size += 2;
    uint16_t qcount = 0;
    if(dns_state->flags & DNS_FLAG_PARSED_QUESTION) {
        qcount = 1;
        uShortToBytes(qcount, dns_state->reply + dns_state->reply_current_size);
        dns_state->reply_current_size += 8;
        memcpy(dns_state->reply + dns_state->reply_current_size, dns_state->query.question.question, dns_state->query.question.question_size);
        dns_state->reply_current_size += dns_state->query.question.question_size;
    } else {
        uShortToBytes(qcount, dns_state->reply + dns_state->reply_current_size);
        dns_state->reply_current_size += 8;
    }
    return STATUS_SUCCESS;
}


ExitStatus addAnswerField(DNSStatePtr dns_state, char* owner, size_t owner_size, ZoneEntryPtr zone_entry, DNSFieldType type) {
    if(type == DNS_ANSWER) {
        uint16_t answer_count = bytesToUShort(dns_state->reply + 6);
        answer_count++;
        uShortToBytes(answer_count, dns_state->reply + 6);
    } else {
        uint16_t authority_count = bytesToUShort(dns_state->reply + 8);
        authority_count++;
        uShortToBytes(authority_count, dns_state->reply + 8);
    }
    // owner
    memcpy(dns_state->reply + dns_state->reply_current_size, owner, owner_size);
    dns_state->reply_current_size += owner_size;

    // type
    uShortToBytes(zone_entry->entry_type, dns_state->reply + dns_state->reply_current_size);
    dns_state->reply_current_size += 2;

    // class
    uShortToBytes(dns_state->query.question.qclass, dns_state->reply + dns_state->reply_current_size);
    dns_state->reply_current_size += 2;

    // ttl
    if(dns_state->flags & (DNS_FLAG_NAME_DOESNT_EXIST | DNS_FLAG_ENTRY_NOT_FOUND)) {
        uint32_t val = zone_entry->entry.soa_entry.minimum < zone_entry->ttl ? zone_entry->entry.soa_entry.minimum : zone_entry->ttl;
        uIntToBytes(val, dns_state->reply + dns_state->reply_current_size);
    } else {
        uIntToBytes(zone_entry->ttl, dns_state->reply + dns_state->reply_current_size);
    }
    dns_state->reply_current_size += 4;
    // rdata
    uShortToBytes(zone_entry->rdata_size, dns_state->reply + dns_state->reply_current_size);
    dns_state->reply_current_size += 2;

    switch(zone_entry->entry_type) {
        case ENTRY_A:
            memcpy(dns_state->reply + dns_state->reply_current_size, zone_entry->entry.a_entry.address, IP_ADDRESS_BYTES);
            dns_state->reply_current_size += IP_ADDRESS_BYTES;
            break;
        case ENTRY_AAAA:
            memcpy(dns_state->reply + dns_state->reply_current_size, zone_entry->entry.aaaa_entry.address, IPV6_ADDRESS_BYTES);
            dns_state->reply_current_size += IPV6_ADDRESS_BYTES;
            break;
        case ENTRY_CNAME:
            memcpy(dns_state->reply + dns_state->reply_current_size, zone_entry->entry.cname_entry.cname, zone_entry->entry.cname_entry.cname_size);
            dns_state->reply_current_size += zone_entry->entry.cname_entry.cname_size;
            break;
        case ENTRY_MX:
            uShortToBytes(zone_entry->entry.mx_entry.preference, dns_state->reply + dns_state->reply_current_size);
            dns_state->reply_current_size+=2;

            memcpy(dns_state->reply + dns_state->reply_current_size, zone_entry->entry.mx_entry.exchange, zone_entry->entry.mx_entry.exchange_size);
            dns_state->reply_current_size += zone_entry->entry.mx_entry.exchange_size;
            break;
        case ENTRY_NS:
            memcpy(dns_state->reply + dns_state->reply_current_size, zone_entry->entry.ns_entry.nsdname, zone_entry->entry.ns_entry.nsdname_size);
            dns_state->reply_current_size += zone_entry->entry.ns_entry.nsdname_size;
            break;
        case ENTRY_SOA:
            //mname 
            memcpy(dns_state->reply + dns_state->reply_current_size, zone_entry->entry.soa_entry.mname, zone_entry->entry.soa_entry.mname_size);
            dns_state->reply_current_size += zone_entry->entry.soa_entry.mname_size;
            //rname
            memcpy(dns_state->reply + dns_state->reply_current_size, zone_entry->entry.soa_entry.rname, zone_entry->entry.soa_entry.rname_size);
            dns_state->reply_current_size += zone_entry->entry.soa_entry.rname_size;
            // serial
            uIntToBytes(zone_entry->entry.soa_entry.serial, dns_state->reply + dns_state->reply_current_size);
            dns_state->reply_current_size += 4;
            // refresh
            uIntToBytes(zone_entry->entry.soa_entry.refresh, dns_state->reply + dns_state->reply_current_size);
            dns_state->reply_current_size += 4;
            // retry
            uIntToBytes(zone_entry->entry.soa_entry.retry, dns_state->reply + dns_state->reply_current_size);
            dns_state->reply_current_size += 4;
            // expire
            uIntToBytes(zone_entry->entry.soa_entry.expire, dns_state->reply + dns_state->reply_current_size);
            dns_state->reply_current_size += 4;
            // minimum
            uIntToBytes(zone_entry->entry.soa_entry.minimum, dns_state->reply + dns_state->reply_current_size);
            dns_state->reply_current_size += 4;
            break;
    }
    return STATUS_SUCCESS;
}


void addOPT(DNSStatePtr dns_state) {
    char* curr_reply = dns_state->reply + dns_state->reply_current_size;
    memset(curr_reply, 0, OPT_BARE_SIZE); // 11 bytes of '0' for qname, tll and rdatalen
    // type
    uShortToBytes(OPT_TYPE_RECORD, curr_reply + 1);
    // class (size)
    uShortToBytes(OPT_MAX_SIZE, curr_reply + 3);
     // additional
    uint16_t additional_count = bytesToUShort(dns_state->reply + 10);
    additional_count++;
    uShortToBytes(additional_count, dns_state->reply + 10);
    dns_state->reply_current_size += OPT_BARE_SIZE;
}


void truncateUDP(DNSStatePtr dns_state) {
    size_t size = DNS_UDP_WITHOUT_OPT;
    if(dns_state->flags & DNS_FLAG_OPT && dns_state->flags & DNS_FLAG_PARSED_RRS) {
        size = dns_state->query.opt_size;
        if(size < DNS_UDP_WITHOUT_OPT) {
            size = DNS_UDP_WITHOUT_OPT;
        }
        if(size > OPT_MAX_SIZE) {
            size = OPT_MAX_SIZE;
        }
    }
    if(dns_state->reply_current_size <= size) {
        return;
    }
    // set TC
    uint16_t flags = bytesToUShort(dns_state->reply + 2);
    flags |= TC;
    uShortToBytes(flags, dns_state->reply + 2);
    // reset ar,ns,an
    memset(dns_state->reply + 6, 0, 6);                    
    dns_state->reply_current_size = DNS_QUERY_MIN_LENGHT + dns_state->query.question.question_size;
    // add opt
    if(dns_state->flags & DNS_FLAG_OPT && dns_state->flags & DNS_FLAG_PARSED_RRS) {
        addOPT(dns_state);
    }
}


void dnsStateDtor(DNSStatePtr dns_state) {
    free(dns_state->reply);
    dns_state->reply = NULL;
    stringListDestroyFree(&(dns_state->query.question.labels));
}
