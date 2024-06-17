#include "common.h"

void FreeBlobs(DataBlobs* data)
{
    if (data)
    {
        for (int i = 0; i < data->count; ++i)
        {
            CHECK_FREE_NULL(data->buffers[i]);
        }
        CHECK_FREE_NULL(data->buffers);
        CHECK_FREE_NULL(data->sizes);
        CHECK_FREE_NULL(data);
    }
}

void BREAK_WITH_ERROR(char *err)
{
	printf("\n%s\n", err);
	exit(3);
}
