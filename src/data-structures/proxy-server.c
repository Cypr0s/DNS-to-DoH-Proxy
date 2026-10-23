/**
 * @file    proxy.c
 * @author  Kristian Luptak
 * @brief   Implements proxy server functions
 *          
 * @date    2026-10-23
 */

#include "data-structures/proxy-server.h"

ExitStatus proxyServerCtor(ParsedArgsPtr parsed_args, ProxyServerPtr server) {
    if(parsed_args == NULL || server == NULL) {
        return STATUS_FAILURE;
    }
    // starting vals
    server->insecure = (parsed_args->flags & ARG_INSECURE) != 0;
    server->forward_timeout = parsed_args->timeout_time;
    server->forward_address = parsed_args->dns;
    server->forward_address_size = strlen(server->forward_address);

    // blocklist
    ExitStatus e = hashTableCtor(&server->block_list);
    CHECK_ERR(e);

    e = parseBlockList(&(parsed_args->block_lists), &server->block_list);
    CHECK_ERR(e);

    // zone file
    server->zone_file_root = zoneFileTreeCreateNode(NULL);
    if(server->zone_file_root == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }

    e = parseZoneList(&(parsed_args->zone_files), server->zone_file_root);
    CHECK_ERR(e);

    // connections
    e = connectionVectorInit(&server->connections);
    CHECK_ERR(e);

    // multi handles for proxy server
    server->multi_handle = curl_multi_init();
    if(server->multi_handle == NULL) {
        PRINT_ERROR("Failed to init multi handle");
        return STATUS_FAILURE;
    }

    if(curl_multi_setopt(server->multi_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, (long)MAX_FORWARDED_REQUESTS) != CURLM_OK) {
        PRINT_ERROR("Failed to set multi handle opt");
        return STATUS_FAILURE;
    }

    PRINT_ERROR("outstanding upstream request cap: %d", MAX_FORWARDED_REQUESTS);

    struct curl_slist* tmp = curl_slist_append(server->forward_header, "Content-Type: application/dns-message");
    if(tmp == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }
    server->forward_header = tmp;

    tmp = curl_slist_append(server->forward_header, "Accept: application/dns-message");
    if(tmp == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }
    server->forward_header = tmp;

    e = prepareSockets(parsed_args, &server->connections);
    CHECK_ERR(e);
    return STATUS_SUCCESS;
}


void proxyServerDtor(ProxyServerPtr server) {
    zoneFileTreeDelete(server->zone_file_root);
    server->zone_file_root = NULL;
    hashTableDtor(&server->block_list);
    forwardCleanup(server);
    connectionVectorClean(&server->connections);
    curl_slist_free_all(server->forward_header);
    curl_multi_cleanup(server->multi_handle);
}