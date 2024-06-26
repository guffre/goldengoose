#include "common.h"
#include "linkedlist.h"
#include "commandnode.h"

void FreeBlobs(DataBlobs* data)
{
    if (data)
    {
        for (unsigned int i = 0; i < data->count; ++i)
        {
            SAFE_FREE(data->buffers[i]);
        }
        SAFE_FREE(data->buffers);
        SAFE_FREE(data->sizes);
        SAFE_FREE(data);
    }
}

void BREAK_WITH_ERROR(char *err)
{
    debugf("\n%s\n", err);
    exit(3);
}