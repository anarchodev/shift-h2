add_executable(h2c_echo h2c_echo.c)
target_link_libraries(h2c_echo PRIVATE shift_h2 pthread)

add_executable(h2c_client h2c_client.c)
target_link_libraries(h2c_client PRIVATE shift_h2 pthread)

add_executable(h2c_proxy h2c_proxy.c)
target_link_libraries(h2c_proxy PRIVATE shift_h2 pthread)

if(TARGET OpenSSL::SSL)
    add_executable(h2_echo h2_echo.c)
    target_link_libraries(h2_echo PRIVATE shift_h2 pthread)

    add_executable(h2_client h2_client.c)
    target_link_libraries(h2_client PRIVATE shift_h2 pthread)

    add_executable(h2_mtls_echo h2_mtls_echo.c)
    target_link_libraries(h2_mtls_echo PRIVATE shift_h2 pthread)
endif()
