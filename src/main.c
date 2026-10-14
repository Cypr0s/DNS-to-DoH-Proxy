
#include "main.h"

int main(int argc, char* argv[]) {
    ParsedArgs parsed_args;
    parsedArgsCtor(&parsed_args);
    ProxyServer server = {0};

    ExitStatus e = parseArguments(argc, argv, &parsed_args);
    CHECK_ERR_AND_FREE(e, parsedArgsDtor(&parsed_args));
    if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        parsedArgsDtor(&parsed_args);
        return STATUS_FAILURE;
    }
    e = proxyServerInit(&parsed_args, &server);
    CHECK_ERR_AND_FREE(e, proxyServerDtor(&server); parsedArgsDtor(&parsed_args););

    e = proxyServerStart(&server);
    proxyServerDtor(&server);
    parsedArgsDtor(&parsed_args);
    curl_global_cleanup();
    return e;
}
