#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <errno.h>

#include <rutoken/rtpkcs11.h>

#include "dbg.h"
#include "librtpkcs11sign.h"
#include "sign.h"
#include "errors.h"

TPKCS11Handle init_pkcs11(const char *library_file_name)
{
    TPKCS11Handle result = {0};
    CK_RV rv;

    check(library_file_name != NULL, "library_file_name is NULL");

    result.pkcs11_handle = dlopen(library_file_name, RTLD_NOW);
    check(result.pkcs11_handle != NULL, "%s", dlerror());

    dlerror();
    CK_C_GetFunctionList get_function_list = (CK_C_GetFunctionList)dlsym(result.pkcs11_handle, "C_GetFunctionList");
    const char *error_msg = dlerror();
    check((get_function_list != NULL) && (error_msg == NULL), "Couldn't find C_GetFunctionList: %s", error_msg);

    dlerror();
    CK_C_EX_GetFunctionListExtended get_function_list_ex = (CK_C_EX_GetFunctionListExtended)dlsym(result.pkcs11_handle, "C_EX_GetFunctionListExtended");
    error_msg = dlerror();
    check((get_function_list_ex != NULL) && (error_msg == NULL), "Couldn't find C_EX_GetFunctionListExtended: %s", error_msg);

    rv = get_function_list(&result.function_list);
    check((rv == CKR_OK) && (result.function_list != NULL), "Couldn't run C_GetFunctionList: %s", rv_to_str(rv));

    rv = get_function_list_ex(&result.function_list_ex);
    check((rv == CKR_OK) && (result.function_list_ex != NULL), "Couldn't run C_EX_GetFunctionListExtended: %s", rv_to_str(rv));

    rv = result.function_list->C_Initialize(NULL);
    check(rv == CKR_OK, "Couldn't run C_Initialize: %s", rv_to_str(rv));

    rv = result.function_list->C_GetSlotList(CK_TRUE, NULL, &result.slot_count);
    check((rv == CKR_OK) && (result.slot_count != 0), "There are no slots available: %s", rv_to_str(rv));

    result.slots = (CK_SLOT_ID_PTR)malloc(result.slot_count * sizeof(CK_SLOT_ID));
    check_mem(result.slots);

    rv = result.function_list->C_GetSlotList(CK_TRUE, result.slots, &result.slot_count);
    check((rv == CKR_OK) && (result.slot_count != 0), "There are no slots available: %s", rv_to_str(rv));

error:
    return result;
}

static bool check_pkcs11(TPKCS11Handle handle)
{
    return (handle.pkcs11_handle != NULL) && (handle.function_list != NULL) && (handle.function_list_ex != NULL) && (handle.slots != NULL) && (handle.slot_count > 0);
}

void cleanup_pkcs11(TPKCS11Handle handle)
{
    CK_RV rv;
    if (handle.slots != NULL)
        free(handle.slots);
    if (handle.function_list != NULL)
    {
        rv = handle.function_list->C_Finalize(NULL);
        if (rv != CKR_OK)
            log_err("%s", rv_to_str(rv));
    }
    if (handle.pkcs11_handle != NULL)
        dlclose(handle.pkcs11_handle);
}

CK_SESSION_HANDLE open_slot_session(TPKCS11Handle handle, size_t slot, const char *user_pin)
{
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV rv;

    check(check_pkcs11(handle), "pkcs11 handle is invalid");

    check(slot < handle.slot_count, "slot is out of bounds");
    check(user_pin != NULL, "user_pin is NULL");

    char *user_pin_mut = strdup(user_pin);
    check_mem(user_pin_mut);

    rv = handle.function_list->C_OpenSession(handle.slots[slot], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    check(rv == CKR_OK, "Couldn't run C_OpenSession: %s", rv_to_str(rv));

    rv = handle.function_list->C_Login(session, CKU_USER, user_pin_mut, strlen(user_pin_mut));
    if (rv != CKR_OK)
    {
        log_err("Couldn't run C_Login: %s", rv_to_str(rv));
        close_slot_session(handle, session);
        session = CK_INVALID_HANDLE;
    }

error:
    if (user_pin_mut != NULL)
        free(user_pin_mut);
    return session;
}

void close_slot_session(TPKCS11Handle handle, CK_SESSION_HANDLE session)
{
    CK_RV rv;
    if (session != CK_INVALID_HANDLE)
    {
        rv = handle.function_list->C_Logout(session);
        if (rv != CKR_OK)
            log_err("Couldn't run C_Logout: %s", rv_to_str(rv));

        rv = handle.function_list->C_CloseSession(session);
        if (rv != CKR_OK)
            log_err("Couldn't run C_CloseSession: %s", rv_to_str(rv));
    }
}

static int find_objects(CK_FUNCTION_LIST_PTR function_list,
                        CK_SESSION_HANDLE session,
                        CK_ATTRIBUTE_PTR attributes,
                        CK_ULONG attr_count,
                        CK_OBJECT_HANDLE_PTR *objects,
                        CK_ULONG *objects_count)
{
    CK_RV rv;
    CK_ULONG new_objects_count;
    CK_ULONG buffer_size;
    CK_OBJECT_HANDLE_PTR buffer = NULL;
    int error_code = 1;

    rv = function_list->C_FindObjectsInit(session, attributes, attr_count);
    check(rv == CKR_OK, "%s", rv_to_str(rv));
    error_code = 2;

    *objects = NULL;
    *objects_count = 0;

    for (buffer_size = 8;; buffer_size *= 2)
    {
        buffer = (CK_OBJECT_HANDLE_PTR)realloc(*objects, buffer_size * sizeof(CK_OBJECT_HANDLE));
        check_mem(buffer);
        *objects = buffer;

        rv = function_list->C_FindObjects(session, *objects + *objects_count, buffer_size - *objects_count, &new_objects_count);
        check(rv == CKR_OK, "%s", rv_to_str(rv));

        *objects_count += new_objects_count;

        if (*objects_count < buffer_size)
        {
            break;
        }
    }
    error_code = 3;

    if (*objects_count != 0)
    {
        buffer = (CK_OBJECT_HANDLE_PTR)realloc(*objects, *objects_count * sizeof(CK_OBJECT_HANDLE));
        check_mem(buffer);
        *objects = buffer;
    }
    error_code = 4;
error:

    if (error_code > 1)
    {
        rv = function_list->C_FindObjectsFinal(session);
        if (rv != CKR_OK)
            log_err("%s", rv_to_str(rv));
        if (error_code == 4)
            error_code = 0;
    }

    if (error_code != 0 || *objects_count == 0)
    {
        if (*objects != NULL)
        {
            free(*objects);
            *objects = NULL;
        }
    }
    return error_code;
}

TByteArray perform_signing(const TByteArray input, const char *user_pin, const char *key_pair_id, size_t slot)
{

    CK_OBJECT_CLASS privateKeyObject = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS certificateObject = CKO_CERTIFICATE;
    CK_BBOOL attributeTrue = CK_TRUE;
    CK_CERTIFICATE_TYPE certificateType = CKC_X_509;
    // CK_ULONG tokenUserCertificate = 1;

    CK_RV rv = 0;

    CK_OBJECT_HANDLE_PTR privateKeys = NULL;
    CK_ULONG keysCount = 0;

    CK_OBJECT_HANDLE_PTR certificates = NULL;
    CK_ULONG certificatesCount;

    CK_BYTE_PTR signature = NULL;
    CK_ULONG signatureSize = 0;
    TByteArray result = {.length = 0, .data = NULL};

    check(input.data != NULL && input.length > 0 && user_pin != NULL && key_pair_id != NULL, "Function input is invalid.");

    char *key_pair_id_mut = strdup(key_pair_id);
    check_mem(key_pair_id_mut);

    CK_ATTRIBUTE privateKeyTemplate[] =
        {
            {CKA_CLASS, &privateKeyObject, sizeof(privateKeyObject)},
            {CKA_TOKEN, &attributeTrue, sizeof(attributeTrue)},
            {CKA_ID, key_pair_id_mut, strlen(key_pair_id_mut)},
        };

    CK_ATTRIBUTE certificateTemplate[] =
        {
            {CKA_CLASS, &certificateObject, sizeof(certificateObject)},
            {CKA_TOKEN, &attributeTrue, sizeof(attributeTrue)},
            {CKA_ID, key_pair_id_mut, strlen(key_pair_id_mut)},
            {CKA_CERTIFICATE_TYPE, &certificateType, sizeof(certificateType)},
            // { CKA_CERTIFICATE_CATEGORY, &tokenUserCertificate, sizeof(tokenUserCertificate)},
        };

    TPKCS11Handle handle = init_pkcs11(PKCS11_LIBRARY_NAME);
    check(check_pkcs11(handle), "pkcs11 handle is invalid");

    CK_SESSION_HANDLE session = open_slot_session(handle, slot, user_pin);
    check(session != CK_INVALID_HANDLE, "open_slot_session failed");

    int r = find_objects(handle.function_list, session, privateKeyTemplate, arraysize(privateKeyTemplate),
                         &privateKeys, &keysCount);
    check((r == 0) && (keysCount > 0), "There are no private keys available.");

    r = find_objects(handle.function_list, session, certificateTemplate, arraysize(certificateTemplate),
                     &certificates, &certificatesCount);
    check(r == 0 && certificatesCount > 0, "There are no certificates available.");

    rv = handle.function_list_ex->C_EX_PKCS7Sign(session, input.data, input.length, certificates[0],
                                                 &signature, &signatureSize, privateKeys[0], NULL, 0, USE_HARDWARE_HASH | PKCS7_DETACHED_SIGNATURE);
    check(rv == CKR_OK && signatureSize != 0, "C_EX_PKCS7Sign: %s", rv_to_str(rv));

    result.data = malloc(signatureSize);
    check_mem(result.data);
    result.length = signatureSize;
    memmove(result.data, signature, signatureSize);

error:
    if (key_pair_id_mut != NULL)
        free(key_pair_id_mut);
    if (certificates != NULL)
        free(certificates);
    if (privateKeys != NULL)
        free(privateKeys);
    if (signature != NULL)
    {
        rv = handle.function_list_ex->C_EX_FreeBuffer(signature);
        if (rv != CKR_OK)
            log_err("C_EX_FreeBuffer: %s", rv_to_str(rv));
    }

    close_slot_session(handle, session);
    cleanup_pkcs11(handle);
    return result;
}

TSlotTokenInfoArray get_slots_info()
{
    TSlotTokenInfoArray result = {.count = 0, .slots_info = NULL};
    CK_RV rv;

    TPKCS11Handle handle = init_pkcs11(PKCS11_LIBRARY_NAME);
    check(check_pkcs11(handle), "pkcs11 handle is invalid");
    result.slots_info = (TSlotTokenInfo *)malloc(handle.slot_count * sizeof(TSlotTokenInfo));
    check_mem(result.slots_info);
    result.count = handle.slot_count;

    for (size_t i = 0; i < handle.slot_count; i++)
    {
        CK_SLOT_ID slot_id = handle.slots[i];
        result.slots_info[i].slot_id = slot_id;
        result.slots_info[i].valid = true;

        rv = handle.function_list->C_GetSlotInfo(slot_id, &result.slots_info[i].slot_info);
        if (rv != CKR_OK)
        {
            log_err("Couldn't run C_GetSlotInfo: %s for %ld", rv_to_str(rv), slot_id);
            result.slots_info[i].valid = false;
            continue;
        }
        rv = handle.function_list->C_GetTokenInfo(slot_id, &result.slots_info[i].token_info);
        if (rv != CKR_OK)
        {
            log_err("Couldn't run C_GetTokenInfo: %s for %ld", rv_to_str(rv), slot_id);
            result.slots_info[i].valid = false;
            continue;
        }
    }

error:
    cleanup_pkcs11(handle);
    return result;
}

void release_slots_info(TSlotTokenInfoArray array)
{
    if (array.slots_info != NULL)
        free(array.slots_info);
}

void release_byte_array(TByteArray array)
{
    if (array.data != NULL)
        free(array.data);
}
