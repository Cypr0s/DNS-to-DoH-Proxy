#include "data-structures/proxy_server.h"

ExitStatus proxyServerInit(ParsedArgsPtr parsed_args, ProxyServerPtr server) {
    server->insecure = (parsed_args->flags & ARG_INSECURE) != 0;
    server->forward_timeout = parsed_args->timeout_time;
    server->forward_address = parsed_args->dns;
    server->forward_address_size = strlen(server->forward_address);
    server->block_list_root = blockListTreeCreateNode(NULL, 0);
    if(server->block_list_root == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }

    ExitStatus e = parseBlockList(&(parsed_args->block_lists), server->block_list_root);
    CHECK_ERR(e);


    server->zone_file_root = zoneFileTreeCreateNode(NULL);
    if(server->zone_file_root == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }

    e = parseZoneList(&(parsed_args->zone_files), server->zone_file_root);
    CHECK_ERR(e);

    e = connectionVectorInit(&server->connections);
    CHECK_ERR(e);

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
    blockListTreeDelete(server->block_list_root);
    server->block_list_root = NULL;
    connectionVectorClean(&server->connections);
    curl_slist_free_all(server->forward_header);
    curl_multi_cleanup(server->multi_handle);
}