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
        result.length = 0;
    }
    else {
        puts("perform_signing succeeded");
        printf("result length: %zu\n", result.length);
        free(result.data);
        result.data = NULL;
        result.length = 0;
    }

    result = hello_world(input);
    if (result.data == NULL){
        puts("hello_world failed");
        result.length = 0;
    } else {
        puts("hello_world succeeded");
        printf("result length: %zu\n", result.length);
        free(result.data);
        result.data = NULL;
        result.length = 0;
    }
}
