#include "minunit.h"
#include "sign.h"
#include "librtpkcs11sign.h"

char *test_init_rtpkcs11()
{
    TPKCS11Handle handle = init_pkcs11(NULL);
    mu_assert(handle.pkcs11_handle == NULL, "init_pkcs11 should have failed with the library name NULL");

    handle = init_pkcs11(PKCS11_LIBRARY_NAME);
    mu_assert(handle.pkcs11_handle != NULL, "init_pkcs11 did not find librtpkcs11.so");
    mu_assert(handle.function_list != NULL, "init_pkcs11 did not get function list");
    mu_assert(handle.function_list_ex != NULL, "init_pkcs11 did not get extended function list");
    mu_assert(handle.slots != NULL && handle.slot_count > 0, "init_pkcs11 did not get extended function list");
    CK_SESSION_HANDLE session = open_slot_session(handle, 0, "12345678");
    mu_assert(session != CK_INVALID_HANDLE, "open_slot_session failed");

    close_slot_session(handle, session);
    cleanup_pkcs11(handle);

    return NULL;
}

char *test_get_slot_count()
{
    mu_assert(get_slot_count() > 0, "no slots available");

    return NULL;
}

char *all_tests()
{

    mu_suite_start();

    mu_run_test(test_init_rtpkcs11);
    mu_run_test(test_get_slot_count);

    return NULL;
}

RUN_TESTS(all_tests);