file(GLOB HEADER_LIST CONFIGURE_DEPENDS "${rtpkcs11sign_SOURCE_DIR}/src/*.h")

add_library(rtpkcs11sign SHARED sign.c errors.c ${HEADER_LIST})

target_link_libraries(rtpkcs11sign PRIVATE ${CMAKE_DL_LIBS})
