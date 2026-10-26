/**
 * @file    blocklist.c
 * @author  Kristian Luptak
 * @brief   Contains declarations of parsing functions for blocklists
 *          
 * @date    2026-10-23
 */

#ifndef PARSING_BLOCKLIST_H
#define PARSING_BLOCKLIST_H

#include "data-structures/string-linked-list.h"
#include "util/file.h"
#include "data-structures/block-list-table.h"
#include "common.h"
#include <ctype.h>
#include <stdint.h>
#include "util/string.h"


#define BLOCKLIST_MAX_TOKEN_LENGTH 254
#define BLOCKLIST_MAX_LABEL_COUNT 127
#define BLOCKLIST_MAX_LABEL_LENGTH 63

typedef enum {
    BLOCKLIST_IS_FIRST_TOKEN = 0x01
} BlockListFlags;

typedef struct {
    DNSFileContext dns_context;
    BlockListFlags flags;
} BlockListCtx, *BlockListCtxPtr;


/**
 * @brief               Parses all blocklist files into hash table
 * 
 * @param block_list    List of blocklist file names
 * @param table         Hash table of blocked domains
 * @return              ExitStatus 
 */
ExitStatus parseBlockList(StringListPtr block_list, HashTablePtr root);

#endif // PARSING_BLOCKLIST_H