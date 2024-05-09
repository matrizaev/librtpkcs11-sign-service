#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "sign.h"

void main() {
    TMemoryPointer input = {.data = "test", .length=arraysize("test")};
    char *user_pin = "12345678";
    char *key_pair_id = "00000000";

    TMemoryPointer result = perform_signing(input, user_pin, key_pair_id);
    if (result.data == NULL){
        puts("perform_signing failed");
    }
    else {
        puts("perform_signing succeeded");
        printf("result length: %zu\n", result.length);
        free(result.data);
    }
}
