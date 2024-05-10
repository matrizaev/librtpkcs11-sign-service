#include <string.h>

#include "minunit.h"
#include "errors.h"

char *test_rv_to_str()
{
    mu_assert(strcmp(rv_to_str(CKR_OK), "CKR_OK") == 0, "rv_to_str doesn't work properlys");

    return NULL;
}

char *all_tests()
{

    mu_suite_start();

    mu_run_test(test_rv_to_str);

    return NULL;
}

RUN_TESTS(all_tests);