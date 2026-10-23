/**
 * @file    string-linked-list.h
 * @author  Kristian Luptak
 * @brief   Contains declarations of string linked list struct
 *          
 * @date    2026-10-23
 */

#ifndef STRING_LINKED_LIST_H
#define STRING_LINKED_LIST_H

#include <stdio.h> // size_t
#include "error.h"
#include <string.h>

typedef struct node {
    char* data;
    struct node* next;
} StringNode, *StringNodePtr;


typedef struct {
    StringNodePtr head;
} StringList, *StringListPtr;


typedef struct {
    StringNodePtr curr;
} StringListIterator, *StringListIteratorPtr;


/**
 * @brief       Initializes string list
 * 
 * @param list  Target list
 */
void stringListInit(StringListPtr list);

ExitStatus stringListInsert(StringListPtr list, char* data);

void stringListPop(StringListPtr list);

void stringListDestroy(StringListPtr list);

void stringListIterInit(StringListIteratorPtr it, StringListPtr list);

char* stringListIterNext(StringListIteratorPtr it);

void stringListDestroyFree(StringListPtr list);

void stringListReverse(StringListPtr list);

#endif // STRING_LINKED_LIST_H