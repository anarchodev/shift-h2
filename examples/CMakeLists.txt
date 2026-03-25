add_executable(h2c_echo h2c_echo.c)
target_link_libraries(h2c_echo PRIVATE shift_h2 pthread)

if(TARGET OpenSSL::SSL)
    add_executable(h2_echo h2_echo.c)
    target_link_libraries(h2_echo PRIVATE shift_h2 pthread)
endif()
