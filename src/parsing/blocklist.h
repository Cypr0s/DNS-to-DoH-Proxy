#include "data-structures/string-linked-list.h"
#include "util/file.h"
#include "data-structures/block-list-tree.h"
#include "common.h"
#include <ctype.h>
#include <stdint.h>

ExitStatus parseBlockList(StringListPtr block_list, BlockListTreePtr root);