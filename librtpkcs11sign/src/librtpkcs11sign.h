#ifndef _LIBRTPKCS11_H
#define _LIBRTPKCS11_H

#include <stdint.h>
#include <stddef.h>

#include <rutoken/rtpkcs11.h>

typedef struct
{
    size_t length;
    uint8_t *data;
} TMemoryBlock;

extern TMemoryBlock perform_signing(const TMemoryBlock input, char *userPIN, char *keyPairId, size_t slot);
extern size_t get_slot_count();
// extern CK_SLOT_INFO get_slot_info(size_t slot);

#endif // _LIBRTPKCS11_H
