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
    ENTRY_A = 1,
    ENTRY_NS = 2,
    ENTRY_MD = 3,
    ENTRY_MF = 4,
    ENTRY_CNAME = 5,
    ENTRY_SOA = 6,
    ENTRY_MB = 7,
    ENTRY_MG = 8,
    ENTRY_MR = 9,
    ENTRY_NULL = 10,
    ENTRY_WKS = 11,
    ENTRY_PTR = 12,
    ENTRY_HINFO = 13,
    ENTRY_MINFO = 14,
    ENTRY_MX = 15,
    ENTRY_TXT = 16,
    ENTRY_RP = 17,
    ENTRY_AFSDB = 18,
    ENTRY_X25 = 19,
    ENTRY_ISDN = 20,
    ENTRY_RT = 21,
    ENTRY_NSAP = 22,
    ENTRY_NSAP_PTR = 23,
    ENTRY_SIG = 24,
    ENTRY_KEY = 25,
    ENTRY_PX = 26,
    ENTRY_GPOS = 27,
    ENTRY_AAAA = 28,
    ENTRY_LOC = 29,
    ENTRY_NXT = 30,
    ENTRY_EID = 31,
    ENTRY_NIMLOC = 32,
    ENTRY_SRV = 33,
    ENTRY_ATMA = 34,
    ENTRY_NAPTR = 35,
    ENTRY_KX = 36,
    ENTRY_CERT = 37,
    ENTRY_A6 = 38,
    ENTRY_DNAME = 39,
    ENTRY_SINK = 40,
    ENTRY_OPT = 41,
    ENTRY_APL = 42,
    ENTRY_DS = 43,
    ENTRY_SSHFP = 44,
    ENTRY_IPSECKEY = 45,
    ENTRY_RRSIG = 46,
    ENTRY_NSEC = 47,
    ENTRY_DNSKEY = 48,
    ENTRY_DHCID = 49,
    ENTRY_NSEC3 = 50,
    ENTRY_NSEC3PARAM = 51,
    ENTRY_TLSA = 52,
    ENTRY_SMIMEA = 53,
    ENTRY_DELEGPARAM = 54,
    ENTRY_HIP = 55,
    ENTRY_NINFO = 56,
    ENTRY_RKEY = 57,
    ENTRY_TALINK = 58,
    ENTRY_CDS = 59,
    ENTRY_CDNSKEY = 60,
    ENTRY_OPENPGPKEY = 61,
    ENTRY_CSYNC = 62,
    ENTRY_ZONEMD = 63,
    ENTRY_SVCB = 64,
    ENTRY_HTTPS = 65,
    ENTRY_DSYNC = 66,
    ENTRY_HHIT = 67,
    ENTRY_BRID = 68,
    ENTRY_UNECE = 69,
    ENTRY_ISO = 70,
    ENTRY_SPF = 99,
    ENTRY_UINFO = 100,
    ENTRY_UID = 101,
    ENTRY_GID = 102,
    ENTRY_UNSPEC = 103,
    ENTRY_NID = 104,
    ENTRY_L32 = 105,
    ENTRY_L64 = 106,
    ENTRY_LP = 107,
    ENTRY_EUI48 = 108,
    ENTRY_EUI64 = 109,
    ENTRY_NXNAME = 128,
    ENTRY_TKEY = 249,
    ENTRY_TSIG = 250,
    ENTRY_IXFR = 251,
    ENTRY_AXFR = 252,
    ENTRY_MAILB = 253,
    ENTRY_MAILA = 254,
    ENTRY_ANY = 255,
    ENTRY_URI = 256,
    ENTRY_CAA = 257,
    ENTRY_AVC = 258,
    ENTRY_DOA = 259,
    ENTRY_AMTRELAY = 260,
    ENTRY_RESINFO = 261,
    ENTRY_WALLET = 262,
    ENTRY_CLA = 263,
    ENTRY_IPN = 264,
    ENTRY_TA = 32768,
    ENTRY_DLV = 32769,
    ENTRY_DELEG = 61440,
    ENTRY_INVALID = -1  /* name is not an IANA type */
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
void zoneListCtor(ZoneListPtr list);


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
void zoneListDtor(ZoneListPtr list);

/**
 * @brief       Creates iterator which points to front of list
 * 
 * @param it    Iterator
 * @param list  Target list
 */
void zoneListIterCtor(ZoneListIteratorPtr it, ZoneListPtr list);


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