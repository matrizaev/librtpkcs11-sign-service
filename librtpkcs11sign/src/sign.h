#ifndef _SIGN_H
#define _SIGN_H

#include <stddef.h>

#include <rutoken/rtpkcs11.h>

#define PKCS11_LIBRARY_NAME "librtpkcs11ecp.so"
#define arraysize(a) (sizeof(a) / sizeof(a[0]))

typedef struct
{
    void *pkcs11_handle;
    CK_FUNCTION_LIST_PTR function_list;
    CK_FUNCTION_LIST_EXTENDED_PTR function_list_ex;
    CK_SLOT_ID_PTR slots;
    CK_ULONG slot_count;
} TPKCS11Handle;

extern TPKCS11Handle init_pkcs11(const char *library_file_name);
extern void cleanup_pkcs11(TPKCS11Handle handle);
extern CK_SESSION_HANDLE open_slot_session(TPKCS11Handle handle, size_t slot, const char *user_pin);
extern void close_slot_session(TPKCS11Handle handle, CK_SESSION_HANDLE session);

#endif // _SIGN_H
