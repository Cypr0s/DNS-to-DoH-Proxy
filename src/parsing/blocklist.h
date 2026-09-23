#include "data-structures/string-linked-list.h"
#include "util/file.h"
#include "data-structures/block-list-tree.h"
#include "common.h"
#include <ctype.h>
#include <stdint.h>


#define BLOCKLIST_MAX_TOKEN_LENGTH 254
#define BLOCKLIST_MAX_LABEL_COUNT 127
#define BLOCKLIST_MAX_LABEL_LENGTH 63

ExitStatus parseBlockList(StringListPtr block_list, BlockListTreePtr root);

typedef enum {
    BLOCKLIST_IS_FIRST_TOKEN = 0x01,
    BLOCKLIST_IS_ONLY_NUMBERS = 0x02,
};

typedef struct {
    FilePrintContext file_print;
    uint8_t flags;
    uint8_t label_count;
    uint8_t label_length;
} BlockListCtx, *BlockListCtxPtr;