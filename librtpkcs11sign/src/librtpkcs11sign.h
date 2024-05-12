#ifndef _LIBRTPKCS11_H
#define _LIBRTPKCS11_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <rutoken/rtpkcs11.h>

typedef struct
{
    size_t length; // the full length of the memory block in bytes
    uint8_t *data;
} TByteArray;

typedef struct
{
    CK_SLOT_INFO slot_info;
    CK_TOKEN_INFO token_info;
    bool valid;
    size_t slot_id;
} TSlotTokenInfo;

typedef struct
{
    size_t count;
    TSlotTokenInfo *slots_info;
} TSlotTokenInfoArray;

extern TByteArray perform_signing(const TByteArray input, const char *user_pin, const char *key_pair_id, size_t slot);
extern TSlotTokenInfoArray get_slots_info();
extern void release_slots_info(TSlotTokenInfoArray array);
extern void release_byte_array(TByteArray array);

#endif // _LIBRTPKCS11_H
