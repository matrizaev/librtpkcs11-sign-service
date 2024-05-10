file(GLOB HEADER_LIST CONFIGURE_DEPENDS "${librtpkcs11sign_SOURCE_DIR}/src/*.h")

include_directories("${librtpkcs11sign_SOURCE_DIR}/src")

add_executable(errors_tests errors_tests.c ${HEADER_LIST})
add_executable(sign_tests sign_tests.c ${HEADER_LIST})

target_link_libraries(errors_tests rtpkcs11sign)
target_link_libraries(sign_tests rtpkcs11sign)

add_test(NAME errors_tests COMMAND errors_tests)
add_test(NAME sign_tests COMMAND sign_tests)
