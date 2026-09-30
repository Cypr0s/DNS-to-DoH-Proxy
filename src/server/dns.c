#include "server/dns.h"

void parseDNSQuery(char* bytes, size_t size, DNSQueryPtr query_out) {
    // check 1: shorter than 12 octets → dropped;
    if(size < DNS_QUERY_MIN_LENGHT) {
        return;
    }

    parseDNSHeader(bytes, &(query_out->header));
    // check 2: QR = 1 → dropped;
    if(query_out->header.flags & QR) {
        return;
    }
    // check 3: OPCODE ≠ QUERY → invalid, NOTIMP;
    uint16_t opcode = GET_OPCODE(query_out->header.flags);
    if(opcode != 0) { // 0 == QUERY, 1 == IQuery ,...
        return;
    }
    // check 4: QDCOUNT ≠ 1 → invalid, FORMERR (RFC 9619; QDCOUNT = 0 by this specification);
    if(query_out->header.qdcount != 1) {
        return;
    }

    // check 5: parse question
    size_t current_position = DNS_QUERY_MIN_LENGHT;
    ExitStatus e = parseDNSQuestion(bytes, size, &(query_out->question), &current_position);
    CHECK_ERR(e);
    
    // check 6: skip RRs, check OPT RECORDS
    e = skipDNSResourceRecords(bytes, size, &current_position, query_out->header);
    CHECK_ERR(e);

    // check 7: QCLASS ≠ IN (including ANY) → invalid, NOTIMP;
    if(query_out->question.qclass != QCLASS_IN) {
        return;
    }

    // check 8: QTYPE = AXFR or IXFR → invalid, REFUSED;
    if(query_out->question.qtype == QTYPE_AXFR || query_out->question.qtype == QTYPE_IXFR) {
        return;
    }

    // check: 9 will be done after this (not a parsing check)
    return;
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


static ExitStatus skipDNSRR(char* bytes, size_t size, size_t* current_position, DNSOPTinfoPtr info) {
    size_t start_position = *current_position;
    ExitStatus e = parseLabels(bytes, size, NULL, current_position);
    CHECK_ERR(e);

    if(*current_position + 10 > size) {
        return STATUS_FAILURE;
    }

    uint16_t type = bytesToUShort(bytes + *current_position);
    if (type == OPT_TYPE_RECORD) { // OPT
        info->opt_counter++;
        if(start_position + 1 == *current_position) {
            info->owner_is_root = 1;
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


static ExitStatus skipDNSResourceRecords(char* bytes, size_t size, size_t* current_position, DNSHeader header) {
    DNSOPTinfo info = {0};
    for(uint16_t i = 0; i < header.ancount; i++) {
        ExitStatus e = skipDNSRR(bytes, size, current_position, &info);
        CHECK_ERR(e);
        if(info.opt_counter > 0) {
            return STATUS_FAILURE;
        }
    }

    for(uint16_t i = 0; i < header.nscount; i++) {
        ExitStatus e = skipDNSRR(bytes, size, current_position, &info);
        CHECK_ERR(e);
        if(info.opt_counter > 0) {
            return STATUS_FAILURE;
        }
    }

    for(uint16_t i = 0; i < header.arcount; i++) {
        ExitStatus e = skipDNSRR(bytes, size, current_position, &info);
        CHECK_ERR(e);
        if(info.opt_counter > 1 || (info.opt_counter == 1 && !info.owner_is_root)) {
            return STATUS_FAILURE;
        }
    }

    return STATUS_SUCCESS;
}