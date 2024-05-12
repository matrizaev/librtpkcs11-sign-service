#include "minunit.h"
#include "librtpkcs11sign.h"

char *test_init_rtpkcs11()
{
    init_pkcs11();

    mu_assert(check_pkcs11(), "init_pkcs11 did not initialized the library");

    CK_SESSION_HANDLE session = open_slot_session(0, "12345678");
    mu_assert(session != CK_INVALID_HANDLE, "open_slot_session failed");

    close_slot_session(session);
    cleanup_pkcs11();

    return NULL;
}

char *test_get_slots_info()
{
    init_pkcs11();

    TSlotTokenInfoArray slots = get_slots_info();
    mu_assert(slots.count > 0 && slots.slots_info != NULL, "get_slots_info failed");

    release_slots_info(slots);
    cleanup_pkcs11();
    return NULL;
}

char *test_perform_signing()
{
    TByteArray input_data = {
        .data = "Hello World!",
        .length = 12};
    init_pkcs11();
    TByteArray signature = perform_signing(input_data, "12345678", "12345678", 0);

    mu_assert(signature.data != NULL && signature.length > 0, "perform_signing failed");

    release_byte_array(signature);
    cleanup_pkcs11();
    return NULL;
}

char *all_tests()
{

    mu_suite_start();

    mu_run_test(test_init_rtpkcs11);
    mu_run_test(test_get_slots_info);
    mu_run_test(test_perform_signing);

    return NULL;
}

RUN_TESTS(all_tests);