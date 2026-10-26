/**
 * @file    zone-file-tree.h
 * @author  Kristian Luptak
 * @brief   Contains declarations of zone-file-tree
 *          
 * @date    2026-10-23
 */


#ifndef ZONE_FILE_TREE_H
#define ZONE_FILE_TREE_H

#include "data-structures/zone-entry-list.h"
#include "data-structures/string-linked-list.h"
#include "server/dns.h"
#include <strings.h>
typedef struct zonefile_tree_node {
    char* value;
    char* full_domain_name;
    int8_t is_apex;
    size_t full_domain_name_size;
    ZoneList list;
    size_t child_count;
    struct zonefile_tree_node** children;
} ZoneFileListTree, *ZoneFileListTreePtr;


/**
 * @brief       Looks up node in children of zone file tree
 * 
 * @param node  Target node
 * @param val   Input value
 * @return      Found note or NULL
 */
ZoneFileListTreePtr zoneFileTreeFindNode(ZoneFileListTreePtr node, char* val);


/**
 * @brief       Creates node with value input
 * 
 * @param val   Input val
 * @return      Created ZoneFileListTree node
 */
ZoneFileListTreePtr zoneFileTreeCreateNode(char* val);


/**
 * @brief           Inserts child note into parend
 * 
 * @param parent    Parent node
 * @param child     Child node
 * @return ExitStatus code STATUS | MALLOC
 */
ExitStatus zoneFileTreeAddChild(ZoneFileListTreePtr parent, ZoneFileListTreePtr child);


/**
 * @brief       Recursively deletes whole tree
 * 
 * @param node  Starting root 
 */
void zoneFileTreeDelete(ZoneFileListTreePtr node);


/**
 * @brief       Checks whether the domain is stored in tree, returns the apex zone for SOA and name
 * 
 * @param root  Input entry
 * @param labels Input domain
 * @param zone  Output zone apex
 * @param name  Output zone name
 * @return uint8_t 1 if zone is null 0 if its inside 
 */
uint8_t isInZone(ZoneFileListTreePtr root, StringListPtr labels, ZoneFileListTreePtr* zone, ZoneFileListTreePtr* name);

#endif // ZONE_FILE_TREE_H