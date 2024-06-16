#include "common.h"

void FreeBlobs(DataBlobs* data)
{
    if (data) {
        for (int i = 0; i < data->count; ++i) {
            free(data->buffers[i]);
        }
        free(data->buffers);
        free(data->sizes);
        free(data);
    }
}

int Base64Encode(const unsigned char* buffer, int length, char* base64Buffer) {
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int base64Length = 0;

    while (length--) {
        char_array_3[i++] = *(buffer++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                base64Buffer[base64Length++] = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++) {
            base64Buffer[base64Length++] = base64_chars[char_array_4[j]];
        }

        while ((i++ < 3)) {
            base64Buffer[base64Length++] = '=';
        }
    }

    return base64Length;
}

void BREAK_WITH_ERROR(char *err) {
	printf("\n%s\n", err);
	exit(3);
}
