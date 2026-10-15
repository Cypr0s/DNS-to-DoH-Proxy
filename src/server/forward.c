#include "server/forward.h"
#include "data-structures/proxy_server.h"

 
static size_t cb(char* data, size_t size, size_t nmemb, void* clientp);
static CURLcode setupTransferHandle(ProxyServerPtr server, ForwardRequestPtr req);
static uint8_t isValidResponse(ForwardRequestPtr req);


// https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
static size_t cb(char *data, size_t size, size_t nmemb, void *clientp) {

    ForwardRequestPtr req = clientp;
    size_t chunk = size * nmemb;
    if(chunk > DNS_QUERY_MAX_SIZE - req->response_size - 1) {
        req->flags |= FORWARD_RESPONSE_OVERFLOW;
        return 0;
    }
    char *ptr = realloc(req->response, req->response_size + chunk);
    if(ptr == NULL) {
        return 0;
    }
    req->response = ptr;
    memcpy(req->response + req->response_size, data, chunk);
    req->response_size += chunk;
 
    return chunk;
}

ForwardRequestPtr forwardRequestCreate(char* query, 
    size_t query_size,
    uint8_t flags, 
    int socket_fd,
    struct sockaddr_storage client,
    socklen_t client_size,
    DNSState dns_state) 
{
    ForwardRequestPtr req = calloc(1, sizeof(ForwardRequest));
    if(req == NULL) {
        return NULL;
    }
    req->query = malloc(query_size); // not strdup: a DNS message is binary and contains zero bytes
    if(req->query == NULL) {
        free(req);
        return NULL;
    }
    memcpy(req->query, query, query_size);
    req->query_size = query_size;
    uShortToBytes(0, req->query);
    req->flags = flags;
    req->socket_fd = socket_fd;
    req->client = client;
    req->client_size = client_size;
    req->dns_state = dns_state;
    req->dns_state.query.question.question = req->query + DNS_QUERY_MIN_LENGHT; // the original pointed into the receive buffer
    return req;
}


void forwardRequestDelete(ProxyServerPtr server, size_t index) {
    ForwardRequestPtr req = server->forwarded_requests.forwarded_requests[index];
    server->forwarded_requests.forwarded_requests[index] = server->forwarded_requests.forwarded_requests[server->forwarded_requests.current_size - 1];
    server->forwarded_requests.current_size--;
 
    if(req->easy != NULL) {
        curl_multi_remove_handle(server->multi_handle, req->easy);
        curl_easy_cleanup(req->easy);
    }
    free(req->query);
    free(req->response);
    dnsStateDtor(&req->dns_state);
    free(req);
}

static CURLcode setupTransferHandle(ProxyServerPtr server, ForwardRequestPtr req) {
    req->easy = curl_easy_init();
    if(req->easy == NULL) {
        return CURLE_FAILED_INIT;
    }
 
    // setup curl address, data
    CURLcode curl_exit = curl_easy_setopt(req->easy, CURLOPT_URL, server->forward_address);
    CHECK_CURL(curl_exit);
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_POST, 1L);
    CHECK_CURL(curl_exit);
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_POSTFIELDS, req->query);
    CHECK_CURL(curl_exit);
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_POSTFIELDSIZE, (long)req->query_size);
    CHECK_CURL(curl_exit);
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_HTTPHEADER, server->forward_header);
    CHECK_CURL(curl_exit);
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_WRITEFUNCTION, cb);
    CHECK_CURL(curl_exit);
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_WRITEDATA, req);
    CHECK_CURL(curl_exit);
    // util
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_PRIVATE, req);
    CHECK_CURL(curl_exit);
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_TIMEOUT, (long)server->forward_timeout);
    CHECK_CURL(curl_exit);
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_FOLLOWLOCATION, 0L);
    CHECK_CURL(curl_exit);
    curl_exit = curl_easy_setopt(req->easy, CURLOPT_NOSIGNAL, 1L);
    CHECK_CURL(curl_exit);
    // insecure
    char* ca_file = getenv("SSL_CERT_FILE");
    if(server->insecure) {
        curl_exit = curl_easy_setopt(req->easy, CURLOPT_SSL_VERIFYPEER, 0L);
        CHECK_CURL(curl_exit);
        curl_exit = curl_easy_setopt(req->easy, CURLOPT_SSL_VERIFYHOST, 0L);
        CHECK_CURL(curl_exit);
    } else if(ca_file != NULL && ca_file[0] != '\0') {
        curl_exit = curl_easy_setopt(req->easy, CURLOPT_CAINFO, ca_file);
        CHECK_CURL(curl_exit);
    }
    // add to handler
    if(curl_multi_add_handle(server->multi_handle, req->easy) != CURLM_OK) {
      return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
}

ExitStatus forwardDNSQuery(ProxyServerPtr server, ForwardRequestPtr req) {
    ForwardRequestArray* array = &server->forwarded_requests;
    array->forwarded_requests[array->current_size++] = req;

    if(setupTransferHandle(server, req) != CURLE_OK) {
        req->dns_state = (DNSState){0};
        forwardRequestDelete(server, array->current_size - 1);
        return STATUS_SUCCESS;
    }
    return STATUS_FORWARDED_QUERY_SENT;
}

static uint8_t isValidResponse(ForwardRequestPtr req) {
    if(req->response == NULL) {
        return 0;
    }
    if(req->response_size < DNS_QUERY_MIN_LENGHT || req->response_size > DNS_QUERY_MAX_SIZE - 1) {
        return 0;
    }

    uint16_t flags = bytesToUShort(req->response + 2);
    // qr, opcode
    if(!(flags & QR) || GET_OPCODE(flags) != 0) {
        return 0;
    }
    // qdcount
    if(bytesToUShort(req->response + 4) != 1) {
        return 0;
    }

    // question 
    size_t qsize = req->dns_state.query.question.question_size;
    if(qsize < 5 || req->response_size < DNS_QUERY_MIN_LENGHT + qsize) {
        return 0;
    }

    size_t name_size = qsize - 4;
    for(size_t i = 0; i < name_size; i++) {
        if(tolower(req->query[DNS_QUERY_MIN_LENGHT + i]) != tolower(req->response[DNS_QUERY_MIN_LENGHT + i])) {
            return 0;
        }
    }
    return memcmp(req->query + DNS_QUERY_MIN_LENGHT + name_size, req->response + DNS_QUERY_MIN_LENGHT + name_size, 4) == 0;
}


ExitStatus handleForwardRequestAnswer(ProxyServerPtr server, ForwardRequestPtr req, CURLcode result, long http_code) {
    char* reply = req->dns_state.reply;
    size_t reply_size = req->dns_state.reply_current_size;

    if(result == CURLE_OK && http_code >= 200 && http_code < 300 && isValidResponse(req)) {
        reply = req->response;
        reply_size = req->response_size;
        uShortToBytes(req->dns_state.query.header.id, reply); // get id back
    }
    
    int8_t rcode = GET_RCODE(bytesToUShort(reply + 2));

    if(req->flags & FORWARD_IS_UDP) { // udp
        if(reply == req->response) {
            memcpy(req->dns_state.reply, req->response, reply_size);
            req->dns_state.reply_current_size = reply_size;
            reply = req->dns_state.reply;
        }
        truncateUDP(&req->dns_state);
        reply_size = req->dns_state.reply_current_size;

        sendto(req->socket_fd, reply, reply_size, 0, (struct sockaddr*)&req->client, req->client_size);
        char log[LOG_LINE_MAX];
        createLogLine(log, LOG_LINE_MAX, &req->client, &req->dns_state, rcode);
        printLogLine(log);
    } else { // tcp
        ssize_t index = -1;
        for(size_t i = 0; req->socket_fd >= 0 && i < server->connections.curr_size; i++) {
            if(server->connections.poll_fds[i].fd == req->socket_fd && server->connections.connections[i].type == TCP_CLIENT) {
                index = (ssize_t)i;
                break;
            }
        }
        if(index < 0) {
            return STATUS_SUCCESS; // not found
        }
        ConnectionPtr con = &server->connections.connections[index];
        char log[LOG_LINE_MAX];
        createLogLine(log, LOG_LINE_MAX, &req->client, &req->dns_state, rcode);
        ExitStatus e = tcpReplyQueuePush(&con->reply_queue, reply, reply_size, log);
        CHECK_ERR(e);
        server->connections.poll_fds[index].events |= POLLOUT;
        if(clock_gettime(CLOCK_MONOTONIC, &con->last_event) != 0) {
            return STATUS_FAILURE; // reset clock
        }
    }
    return STATUS_SUCCESS;
}


ExitStatus receiveForwardedQueries(ProxyServerPtr server) {
    int left = 0;
    CURLMsg* msg = NULL;
    while((msg = curl_multi_info_read(server->multi_handle, &left)) != NULL) {
        CURL* easy = msg->easy_handle;
        CURLcode result = msg->data.result; // transport result

        ForwardRequestPtr req = NULL;
        long http_code = 0;
        curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char**)&req);
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_code);

        ExitStatus e = handleForwardRequestAnswer(server, req, result, http_code);
        for(size_t i = 0; i < server->forwarded_requests.current_size; i++) {
            if(server->forwarded_requests.forwarded_requests[i] == req) {
                forwardRequestDelete(server, i);
                break;
            }
        }
        CHECK_ERR(e);
    }
    return STATUS_SUCCESS;
}


void forwardCleanup(ProxyServerPtr server) {
    while(server->forwarded_requests.current_size > 0) {
        forwardRequestDelete(server, server->forwarded_requests.current_size - 1);
    }
}