
#include "main.h"

volatile sig_atomic_t shutdown_status = 0; // https://en.wikipedia.org/wiki/C_signal_handling

static void catch_function(int signo) {
    shutdown_status = signo;
}

int main(int argc, char* argv[]) {
    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        PRINT_ERROR("");
        return STATUS_FAILURE;
    }
    // https://en.wikipedia.org/wiki/C_signal_handling setup handling signals
    if(signal(SIGINT, catch_function) == SIG_ERR) {
        PRINT_ERROR("");
        return STATUS_FAILURE;
    }

    if(signal(SIGTERM, catch_function) == SIG_ERR) {
        PRINT_ERROR("");
        return STATUS_FAILURE;
    }

    ParsedArgs parsed_args;
    parsedArgsCtor(&parsed_args);
    ProxyServer server = {0};
    ExitStatus e = parseArguments(argc, argv, &parsed_args);
    if(parsed_args.flags & ARG_HELP) {
        fprintf(stdout, "%s", HELP_MESAGE);
        fflush(stdout);
        parsedArgsDtor(&parsed_args);
        return STATUS_SUCCESS;
    }

    CHECK_ERR_AND_FREE(e, PRINT_ERROR(HELP_MESAGE); parsedArgsDtor(&parsed_args));

    if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        parsedArgsDtor(&parsed_args);
        return STATUS_FAILURE;
    }
    e = proxyServerInit(&parsed_args, &server);
    CHECK_ERR_AND_FREE(e, proxyServerDtor(&server); parsedArgsDtor(&parsed_args););
    if(shutdown_status) {
        proxyServerDtor(&server); 
        parsedArgsDtor(&parsed_args);
        curl_global_cleanup();
        return STATUS_FAILURE;
    }

    e = proxyServerStart(&server);
    proxyServerDtor(&server);
    parsedArgsDtor(&parsed_args);
    curl_global_cleanup();
    return e;
}
