#ifndef ZONE_ENTRY_LIST_H
#define ZONE_ENTRY_LIST_H

#include <stdint.h>
#include "error.h"

typedef enum {
    ENTRY_SOA,
    ENTRY_NS,
    ENTRY_A,
    ENTRY_AAAA,
    ENTRY_CNAME,
    ENTRY_MX
} ZoneEntryEnum;


typedef struct {
    char* mname;
    char* rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum; // 
} SOAEntry, *SOAEntryPtr;


typedef struct {
    char* nsdmame;
} NSEntry, *NSEntryPtr;


typedef struct {
    char* address;
} AEntry, *AEntryPtr;


typedef struct {
    char* address;
} AAAAEntry, *AAAAEntryPtr;


typedef struct {
    char* cname;
} CNAMEEntry, *CNAMEEntryPtr;


typedef struct {
    int16_t preference;
    char* exchange;
} MXEntry, *MXEntryPtr;

typedef struct {
    int8_t entry_type;
    union {
        MXEntryPtr mx_entry;
        CNAMEEntryPtr cname_entry;
        AAAAEntryPtr aaaa_entry;
        AEntryPtr a_entry;
        NSEntryPtr ns_entry;
        SOAEntryPtr soa_entry;
    } entry;
} ZoneEntry, *ZoneEntryPtr;

typedef struct zone_node {
    ZoneEntryPtr zone_entry;
    struct zone_node* next;
} ZoneNode, *ZoneNodePtr;


typedef struct {
    ZoneNodePtr head;
} ZoneList, *ZoneListPtr;

typedef struct {
    ZoneNodePtr curr;
} ZoneListIterator, *ZoneListIteratorPtr;

void zoneListInit(ZoneListPtr list);

ExitStatus zoneListInsert(ZoneListPtr list, ZoneEntryPtr zone_entry);

void zoneListPop(ZoneListPtr list);

void zoneListDestroy(ZoneListPtr list);

void zoneListIterInit(ZoneListIteratorPtr it, ZoneListPtr list);

ZoneEntryPtr zoneListIterNext(ZoneListIteratorPtr it);

#endif // ZONE_ENTRY_LIST_H