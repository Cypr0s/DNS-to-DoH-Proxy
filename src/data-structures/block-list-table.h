/**
 * @file    block-list-table.h
 * @author  Kristian Luptak
 * @brief   Contains hash table functions declaration
 *          Most of the code is taken from my shell and edited 
 *          https://github.com/Cypr0s/CyprSH/blob/main/src/data-structures/hash-table.ch
 * @date    2026-10-23
 * 
 */


#ifndef BLOCK_LIST_TABLE_H
#define BLOCK_LIST_TABLE_H

#include "error.h"
#include <stdint.h>
#include <strings.h>
#include <string.h>


typedef enum {
    ITEM_STATE_EMPTY,
    ITEM_STATE_FULL,
} HtabState;


typedef struct {
    char* key;
    HtabState state;
} HashTableItem, *HashTableItemPtr;


typedef struct hashtable {
    HashTableItemPtr data;
    uint32_t currentSize;
    uint32_t capacity;
} HashTable, *HashTablePtr;

/** @brief          Initialize open addressing resizable hash table
 * 
 *  @param table    Hash table to initialize
 *  @return         Exit Status code
 */
ExitStatus hashTableCtor(HashTablePtr table);

/** @brief          Destroy hash table and free all memory
 * 
 *  @param table    Hash table to destroy
 */
void hashTableDtor(HashTablePtr table);

/** @brief          Insert new Blocklist entry
 * 
 *  @param table    Target hash table
 *  @param key      String key
 *  @return         Exit Status code
 */
ExitStatus hashTableInsert(HashTablePtr table, const char* key);

/**
 * @brief       Checks if hash table contains key
 *
 * @param table Target hash table
 * @param key   String key
 * @return      1 if table contains it, 0 otherwise
 */
uint8_t hashTableContains(HashTablePtr table, const char* key);


#endif // BLOCK_LIST_TREE_H