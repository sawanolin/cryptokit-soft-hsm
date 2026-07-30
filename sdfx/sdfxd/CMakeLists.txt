# Daemon module

add_executable(sdfxd
    src/main.c
    src/daemon_core.c
    src/thread_pool.c
    src/protocol_handler.c
    src/session_manager.c
    src/object_manager.c
    src/internal_key_manager.c
    src/rsa_key_manager.c
    src/crypto_random.c
    src/crypto_hash.c
    src/crypto_symmetric.c
    src/crypto_asymmetric.c
)

target_include_directories(sdfxd PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../transport
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENHITLS_ROOT}/include
    ${OPENHITLS_ROOT}/include/hitls/bsl
)

target_link_libraries(sdfxd
    sdfx_transport
    sdfx_protocol
    sdfx_config
    sdfx_hitls_init
    ${COMMON_LIBS}
)

# Install executable file
install(TARGETS sdfxd
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
