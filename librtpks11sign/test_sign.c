#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "sign.h"

void main() {
    char *data = "test";
    char *PIN = "12345678";
    char *key_pair_id = "00000000";

    size_t result_size = 0;
    uint8_t *result = perform_signing(data, arraysize(data), &result_size, PIN, arraysize(PIN), key_pair_id, arraysize(key_pair_id));
    if (result == NULL || result_size == 0){
        puts("perform_signing failed");
    }
    else
        free(result);
}
