#include "main.h"

int main(int argc, char*argv[]) {
    ParsedArgs parsed_args;
    parsedArgsCtor(&parsed_args);
    ExitStatus e = parseArguments(argc, argv, &parsed_args);
    if(e != STATUS_SUCCESS) {
        parsedArgsDtor(&parsed_args);
        return e;
    }
    BlockListTreePtr root = blockListCreateNode(NULL);
    if(root != NULL) {
        parsedArgsDtor(&parsed_args);
        return e;
    }
    e = parseBlockList(&parsed_args.block_lists, root);

    if(e != STATUS_SUCCESS) {
        parsedArgsDtor(&parsed_args);
        blockListDeleteTree(root);
        return e;
    }
    parsedArgsDtor(&parsed_args);
    return EXIT_SUCCESS;
}