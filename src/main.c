#include "main.h"

int main(int argc, char*argv[]) {
    ParsedArgs parsed_args;
    parsedArgsCtor(&parsed_args);
    ExitStatus e = parseArguments(argc, argv, &parsed_args);
    parsedArgsDtor(&parsed_args);
    return EXIT_SUCCESS;
}