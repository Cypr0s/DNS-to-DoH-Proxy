#include "parsing/zonelist.h"

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

        while((line_char_count = getdelim(&line_str, &line_str_capacity, '\n', fp)) != -1) {
            if(line_str[0] == '\n') {
                continue;
            }
        }

        fclose(fp);
        filename = stringListIterNext(&it);
    }
    return STATUS_SUCCESS;
}