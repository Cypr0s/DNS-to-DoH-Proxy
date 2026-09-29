#include "server/dns.h"

void parseDNSQuery(const char* bytes, size_t size, DNSQueryPtr query_out) {
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

    // parse question 
}

void parseDNSHeader(char* bytes, DNSHeaderPtr query_header) {
    uint16_t* field = (uint16_t*) query_header;
    for(uint8_t i = 0; i < DNS_QUERY_MIN_LENGHT / 2; i++) {
        field[i] = bytesToUShort(bytes + (i * 2));
    }
}


void parseDNSQuestion(char* bytes,size_t size, DNSQuestionPtr query_question) {
    size_t current_name_pos = DNS_QUERY_MIN_LENGHT;
    size_t name_length = 0;

    stringListInit(&(query_question->labels));

    while(1) {
        if (current_name_pos >= size) {
            return;
        }
        uint8_t label_length = bytes[current_name_pos];
        name_length += label_length;

        // due to one octet being the size of label
        name_length++;
        current_name_pos++;

        // end of NAME
        if(label_length == 0) {
            break;
        }

        // name error, label length error, size error
        if((label_length >= 64) || 
            (current_name_pos + label_length > size) || 
            name_length > DNS_MAX_TOKEN_LENGTH + 1) 
        {
            return;
        }

        char* label = malloc(sizeof(char) * (label_length + 1));
        if(label == NULL) {
            return;
        }

        memcpy(label, bytes + current_name_pos, label_length);
        label[label_length] = '\0';
        ExitStatus e = stringListInsert(&(query_question->labels), label);
        CHECK_ERR(e);
        current_name_pos += label_length;
    }

    if (current_name_pos + 4 > size) {
        return;
    }

    query_question->qtype = bytesToUShort(bytes + current_name_pos);
    current_name_pos += 2;

    query_question->qclass = bytesToUShort(bytes + current_name_pos);
    current_name_pos += 2;

    query_question->qname = bytes + DNS_QUERY_MIN_LENGHT;
    query_question->qname_size = name_length;

    return;
}