#include <stddef.h>
#include <stdint.h>

#define PKCS11_LIBRARY_NAME "librtpkcs11ecp.so"
#define arraysize(a) (sizeof(a) / sizeof(a[0]))

typedef struct {
    size_t length;
    uint8_t *data;
} TMemoryPointer;

extern TMemoryPointer perform_signing (const TMemoryPointer input, char *userPIN, char *keyPairId);
