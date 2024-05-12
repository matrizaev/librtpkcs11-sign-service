#ifndef _LIBRTPKCS11_H
#define _LIBRTPKCS11_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <rutoken/rtpkcs11.h>

typedef struct
{
    void *pkcs11_handle;
    CK_FUNCTION_LIST_PTR function_list;
    CK_FUNCTION_LIST_EXTENDED_PTR function_list_ex;
} TPKCS11Handle;

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

#define PKCS11_LIBRARY_NAME "librtpkcs11ecp.so"
#define arraysize(a) (sizeof(a) / sizeof(a[0]))

extern CK_SESSION_HANDLE open_slot_session(size_t slot, const char *user_pin);
extern void close_slot_session(CK_SESSION_HANDLE session);

extern TByteArray perform_signing(const TByteArray input, const char *user_pin, const char *key_pair_id, size_t slot);
extern TSlotTokenInfoArray get_slots_info();
extern void release_slots_info(TSlotTokenInfoArray array);
extern void release_byte_array(TByteArray array);
extern void init_pkcs11();
extern void cleanup_pkcs11();
extern bool check_pkcs11();

#endif // _LIBRTPKCS11_H
