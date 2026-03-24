add_executable(h2c_echo h2c_echo.c)
target_link_libraries(h2c_echo PRIVATE shift_h2 pthread)
