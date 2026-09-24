#include <stdint.h> // uint8_t, unint16_t, ...
#include "data-structures/string-linked-list.h" // linked list implementation
#include "error.h" // status codes
#include "stdbool.h" // bool
#include "common.h" // ARRAY_SIZE
#include "util/strings.h"


#define ARGUMENT_DEFAULT_PORT 53
#define ARGUMENT_DEFAULT_TIMEOUT 3
#define ARGUMENT_TIMEOUT_MAX 3600
#define ARGUMENT_PORT_MAX UINT16_MAX
#define ARGUMENT_MIN_PORT_TIMEOUT 1

typedef enum {
    ARG_DOH_URL = 0x01,
    ARG_PORT = 0x02,
    ARG_ADDRESS = 0x04,
    ARG_ZONEFILE = 0x08,
    ARG_BLOCKLIST = 0x10,
    ARG_TIMEOUT = 0x20,
    ARG_INSECURE = 0x40,
    ARG_HELP = 0x80
} ArgFlagsEnum;


typedef struct {
    uint8_t flags;
    uint16_t port;
    uint16_t timeout_time;
    StringList zone_files;
    StringList block_lists;
    char* address;
    char* dns;
} ParsedArgs, *ParsedArgsPtr;

typedef struct argument {
    char* name;
    uint8_t flag;
    bool value_required;
    bool may_be_used_only_once;
} Arg, *ArgPtr;

void parsedArgsCtor(ParsedArgsPtr parsed_args);

void parsedArgsDtor(ParsedArgsPtr parsed_args);

ExitStatus parseArguments(int argc, char** argv, ParsedArgsPtr parsed_args);

