/**
 * @file    zone-entry-list.h
 * @author  Kristian Luptak
 * @brief   Contains declarations of zone-entry-list
 *          
 * @date    2026-10-23
 */

#ifndef ZONE_ENTRY_LIST_H
#define ZONE_ENTRY_LIST_H

#include <stdint.h>
#include "error.h"
#include "common.h"
#include "data-structures/string-linked-list.h"

typedef enum {
    ENTRY_SOA = 6,
    ENTRY_NS = 2,
    ENTRY_A = 1,
    ENTRY_AAAA = 28,
    ENTRY_CNAME = 5,
    ENTRY_MX = 15,
    ENTRY_VALID = 0,
    ENTRY_INVALID = -1,
    ENTRY_ANY = 255
} ZoneEntryEnum;


typedef struct {
    char* mname;
    size_t mname_size;
    char* rname;
    size_t rname_size;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum; // 
} SOAEntry, *SOAEntryPtr;


typedef struct {
    char* nsdname;
    size_t nsdname_size;
} NSEntry, *NSEntryPtr;


typedef struct {
    char address[IP_ADDRESS_BYTES];
} AEntry, *AEntryPtr;


typedef struct {
    char address[IPV6_ADDRESS_BYTES];
} AAAAEntry, *AAAAEntryPtr;


typedef struct {
    char* cname;
    StringList list;
    size_t cname_size;
} CNAMEEntry, *CNAMEEntryPtr;


typedef struct {
    int16_t preference;
    char* exchange;
    size_t exchange_size;
} MXEntry, *MXEntryPtr;

typedef struct {
    int16_t entry_type;
    uint32_t ttl;
    uint16_t rdata_size;
    union {
        MXEntry mx_entry;
        CNAMEEntry cname_entry;
        AAAAEntry aaaa_entry;
        AEntry a_entry;
        NSEntry ns_entry;
        SOAEntry soa_entry;
    } entry;
} ZoneEntry, *ZoneEntryPtr;

typedef struct zone_node {
    ZoneEntry zone_entry;
    struct zone_node* next;
} ZoneNode, *ZoneNodePtr;


typedef struct {
    ZoneNodePtr head;
} ZoneList, *ZoneListPtr;

typedef struct {
    ZoneNodePtr curr;
} ZoneListIterator, *ZoneListIteratorPtr;


/**
 * @brief       Initializes zone list
 * 
 * @param list  Target list
 */
void zoneListInit(ZoneListPtr list);


/**
 * @brief               IInserts one item into the front of list
 * 
 * @param list          Target list
 * @param zone_entry    Zone entry to be inserted
 */
ExitStatus zoneListInsert(ZoneListPtr list, ZoneEntryPtr zone_entry);


/**
 * @brief       Frees one item from the front of list
 * 
 * @param list  Target list
 */
void zoneListPop(ZoneListPtr list);


/**
 * @brief       Destructs whole list
 * 
 * @param list  Target list
 */
void zoneListDestroy(ZoneListPtr list);

/**
 * @brief       Creates iterator which points to front of list
 * 
 * @param it    Iterator
 * @param list  Target list
 */
void zoneListIterInit(ZoneListIteratorPtr it, ZoneListPtr list);


/**
 * @brief       Moves iterator to next item and returns zone entry
 * 
 * @param it    Iterator
 */
ZoneEntryPtr zoneListIterNext(ZoneListIteratorPtr it);


/**
 * @brief               Retruns one entry type which matches the input entry type
 * 
 * @param list  I       nput list
 * @param entry_type    the type of entry eg. SOA, NS, MX ,...
 */
ZoneEntryPtr getEntry(ZoneListPtr list, int8_t entry_type);

#endif // ZONE_ENTRY_LIST_H