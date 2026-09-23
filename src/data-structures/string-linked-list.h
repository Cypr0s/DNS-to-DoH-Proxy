#include <stdio.h> // size_t
#include "error.h"
#include <string.h>

typedef struct node {
    const char* data;
    struct node* next;
} StringNode, *StringNodePtr;


typedef struct {
    StringNodePtr head;
} StringList, *StringListPtr;


typedef struct {
    StringNodePtr curr;
} StringListIterator, *StringListIteratorPtr;

void stringListInit(StringListPtr list);

ExitStatus stringListInsert(StringListPtr list, const char* data);

void stringListPop(StringListPtr list);

void stringListDestroy(StringListPtr list);

void stringListIterInit(StringListIteratorPtr it, StringListPtr list);

char* stringListIterNext(StringListIteratorPtr it);

void stringListDestroyFree(StringListPtr list);