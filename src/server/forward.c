#include "server/forward.h"

 
static size_t cb(char* data, size_t size, size_t nmemb, void* clientp);
static CURLcode setupTransferHandle(ProxyServerPtr server, ForwardRequestPtr req);


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

ForwardRequestPtr forwardRequestCreate(const char* query, 
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
    req->query = strdup(query);
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
    return req;
}


void forwardRequestDestroy(ForwardRequestPtr req) {
    if(req == NULL) {
        return;
    }
    if(req->easy != NULL) {
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
    if(server->forwarded_requests.current_size >= MAX_FORWARDED_REQUESTS) {
        return STATUS_SUCCESS;
    }
 
    if(setupTransferHandle(server, req) != CURLE_OK) {
        if(req->easy != NULL) {
            curl_easy_cleanup(req->easy);
            req->easy = NULL;
        }
        return STATUS_SUCCESS;
    }
 
    server->forwarded_requests.forwarded_requests[server->forwarded_requests.current_size++] = req;
    return STATUS_FORWARDED_QUERY_SENT;
}