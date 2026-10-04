#include "main.h"

int main(int argc, char* argv[]) {
    ParsedArgs parsed_args;
    parsedArgsCtor(&parsed_args);

    ExitStatus e = parseArguments(argc, argv, &parsed_args);
    CHECK_ERR_AND_FREE(e, parsedArgsDtor(&parsed_args));
    ProxyServer server = {0};
    e = proxyServerInit(&parsed_args, &server);
    CHECK_ERR_AND_FREE(e, proxyServerDtor(&server); parsedArgsDtor(&parsed_args););
    e = proxyServerStart(&server);

    CHECK_ERR_AND_FREE(e, proxyServerDtor(&server););
    proxyServerDtor(&server);
    return STATUS_SUCCESS;
}
