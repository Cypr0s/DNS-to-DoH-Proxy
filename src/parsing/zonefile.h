#include "data-structures/zone-file-tree.h"
#include "error.h"

#define ZONEFILE_COUNTER_MAX UINT32_MAX
#define ZONEFILE_MIN 0U
#define ZONEFILE_MINIMUM MAX ZONEFILECOUNTER_MAX / 2
#define ZONEFILE_NS_PREFERENCE_MAX UINT16_MAX