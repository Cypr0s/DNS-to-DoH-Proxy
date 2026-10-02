#include "parsing/argument.h"

static Arg arguments[] = {
    {"-u", ARG_DOH_URL, true, true},
    {"-p", ARG_PORT, true, true},
    {"-a", ARG_ADDRESS, true, true},
    {"-z", ARG_ZONEFILE, true, false},
    {"-b", ARG_BLOCKLIST, true, false},
    {"-w", ARG_TIMEOUT, true, true},
    {"--insecure", ARG_INSECURE, false, true},
    {"-h", ARG_HELP, false, false},
    {"--help", ARG_HELP, false, false}
};

static ExitStatus setValue(ArgFlagsEnum flag, char* arg, ParsedArgsPtr parsed_args);
static inline ArgPtr getArgument(char* argv);


void parsedArgsCtor(ParsedArgsPtr parsed_args) {
    memset(parsed_args, 0, sizeof(ParsedArgs));
    parsed_args->port = ARGUMENT_DEFAULT_PORT;
    parsed_args->timeout_time = ARGUMENT_DEFAULT_TIMEOUT;
    stringListInit(&parsed_args->block_lists);
    stringListInit(&parsed_args->zone_files);
}


void parsedArgsDtor(ParsedArgsPtr parsed_args) {
    stringListDestroy(&parsed_args->block_lists);
    stringListDestroy(&parsed_args->zone_files);
}


ExitStatus parseArguments(int argc, char**argv, ParsedArgsPtr parsed_args) {
    if(argc < 2 ) {
        return STATUS_EX_USAGE;
    }

    for(int i = 1; i < argc; i++) {
        ArgPtr arg = getArgument(argv[i]);
        if(arg == NULL) {
            PRINT_ARGUMENT_PARSE_ERROR("Argument `%s` is invalid. ", argv[i]);
            return STATUS_EX_USAGE;
        }


        if(arg->may_be_used_only_once && ((parsed_args->flags & arg->flag) != 0)) {
            PRINT_ARGUMENT_PARSE_ERROR("Argument `%s` may be used only once", argv[i]);
            return STATUS_EX_USAGE; // 64
        }
        parsed_args->flags |= arg->flag;

        if(arg->flag == ARG_HELP) {
            return STATUS_SUCCESS;
        }

        if(arg->value_required) {
            if(i + 1 >= argc) {
                PRINT_ARGUMENT_PARSE_ERROR("Argument `%s` is missing a value", argv[i]);
                return STATUS_EX_USAGE;
            }
            ExitStatus e = setValue(arg->flag, argv[++i], parsed_args);
            CHECK_ERR(e);
        }
    }

    // check erq
    if((parsed_args->flags & ARG_DOH_URL) == 0) {
        PRINT_ARGUMENT_PARSE_ERROR("Argument `%s` is required", "-u");
        return STATUS_EX_USAGE;
    }

    return STATUS_SUCCESS;
}


static inline ArgPtr getArgument(char* argv) {
    for(size_t i = 0; i < ARRAY_SIZE(arguments); i++) {
        if(!strcmp(arguments[i].name, argv)) {
            return &(arguments[i]);
        }
    }
    return NULL;
}


static ExitStatus setValue(ArgFlagsEnum flag, char* arg, ParsedArgsPtr parsed_args) {
    switch(flag) {
        case(ARG_DOH_URL): {
            if(strncmp(arg, "http://", 7) && strncmp(arg, "https://", 8)) {
                PRINT_ARGUMENT_PARSE_ERROR("Value of argument `-u` - `%s` is invalid", arg);
                return STATUS_EX_USAGE;
            }
            parsed_args->dns = arg;
            break;
        }

        case(ARG_PORT): {
            long port_num = convertStrToNum(arg, ARGUMENT_MIN_PORT_TIMEOUT, ARGUMENT_PORT_MAX);
            if(port_num == -1) {
                PRINT_ARGUMENT_PARSE_ERROR("Value of argument `-p` - `%s` is invalid", arg);
                return STATUS_EX_USAGE;
            }
            parsed_args->port = (uint16_t) port_num;
            break;
        }

        case(ARG_ADDRESS): {
            parsed_args->address = arg;
            break;
        }

        case(ARG_BLOCKLIST): {
            ExitStatus e = stringListInsert(&(parsed_args->block_lists), arg);
            CHECK_ERR(e);
            break;
        }

        case(ARG_ZONEFILE): {
            ExitStatus e = stringListInsert(&(parsed_args->zone_files), arg);
            CHECK_ERR(e);
            break;
        }

        case(ARG_TIMEOUT): {
            long timeout = convertStrToNum(arg, ARGUMENT_MIN_PORT_TIMEOUT, ARGUMENT_TIMEOUT_MAX);
            if(timeout == -1) {
                PRINT_ARGUMENT_PARSE_ERROR("Value of argument `-w` - `%s` is invalid", arg);
                return STATUS_EX_USAGE;
            }
            parsed_args->timeout_time = (uint16_t) timeout;
            break;         
        }

        default:
            PRINT_ERROR("Internal Error");
            return STATUS_FAILURE;
    }
    return STATUS_SUCCESS;
}



