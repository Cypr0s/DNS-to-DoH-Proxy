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
    parsed_args->port = DEFAULT_PORT;
    parsed_args->timeout_time = DEFAULT_TIMEOUT;
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
            // TODO
            return STATUS_EX_USAGE;
        }


        if(arg->may_be_used_only_once && ((parsed_args->flags & arg->flag) != 0)) {
            // TODO print error
            return STATUS_EX_USAGE; // 64
        }
        parsed_args->flags |= arg->flag;

        if(arg->flag == ARG_HELP) {
            return STATUS_SUCCESS;
        }

        if(arg->value_required) {
            if(i + 1 >= argc) {
                // TODO print error
                return STATUS_EX_USAGE;
            }
            ExitStatus e = setValue(arg->flag, argv[++i], parsed_args);
            if(e) return e;
        }
    }

    // check erq
    if((parsed_args->flags & ARG_DOH_URL) == 0) {
        // 
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
                // TODO
                return STATUS_EX_USAGE;
            }
            parsed_args->dns = arg;
            break;
        }

        case(ARG_PORT): {
            char* end;
            errno = 0;
            long port_num = strtol(arg, &end, 10);
            if(end == arg) {
                //TODO
                return STATUS_EX_USAGE;
            }

            if(errno == ERANGE || port_num < ARGUMENT_MIN_PORT_TIMEOUT || port_num > PORT_MAX) {
                //TODO
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
            if(e) return e;
            break;
        }

        case(ARG_ZONEFILE): {
            ExitStatus e = stringListInsert(&(parsed_args->zone_files), arg);
            if(e) return e;
            break;
        }

        case(ARG_TIMEOUT): {
            char* end;
            errno = 0;
            long timeout = strtol(arg, &end, 10);
            if(end == arg) {
                //TODO
                return STATUS_EX_USAGE;
            }

            if(errno == ERANGE || timeout < ARGUMENT_MIN_PORT_TIMEOUT || timeout > TIMEOUT_MAX) {
                //TODO
                return STATUS_EX_USAGE;
            }
            parsed_args->timeout_time = (uint16_t) timeout;
            break;         
        }

        default:
            return STATUS_EX_USAGE;
    }
    return STATUS_SUCCESS;
}



