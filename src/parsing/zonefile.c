#include "parsing/zonefile.h"

ExitStatus parseZoneList(StringListPtr block_list, BlockListTreePtr root) {
    StringListIterator it;
    stringListIterInit(&it, block_list);
    char* filename = stringListIterNext(&it);
    FILE* fp;
    while(filename != NULL) {
        if(openFile(&fp, filename) != STATUS_SUCCESS) {
            // TODO
            return STATUS_EX_CONFIG;
        }


        fclose(fp);
        filename = stringListIterNext(&it);
    }
    return STATUS_SUCCESS;
}