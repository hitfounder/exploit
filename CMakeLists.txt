cmake_minimum_required(VERSION 3.13.0)
project(exploit VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

add_executable(stack_overflow stack_overflow.cpp)
target_compile_features(stack_overflow PRIVATE cxx_std_17)
target_compile_options(stack_overflow PRIVATE -fno-stack-protector)
target_link_options(stack_overflow PRIVATE -z execstack)

add_executable(stack_overflow_bypass_nx stack_overflow_bypass_nx.cpp)
target_compile_features(stack_overflow_bypass_nx PRIVATE cxx_std_17)
target_compile_options(stack_overflow_bypass_nx PRIVATE -fno-stack-protector)

add_executable(stack_overflow_bypass_aslr stack_overflow_bypass_aslr.cpp)
target_compile_features(stack_overflow_bypass_aslr PRIVATE cxx_std_17)
target_compile_options(stack_overflow_bypass_aslr PRIVATE -fno-stack-protector)
target_link_options(stack_overflow_bypass_aslr PRIVATE -no-pie)

add_executable(stack_overflow_bypass_canary stack_overflow_bypass_canary.cpp)
target_compile_features(stack_overflow_bypass_canary PRIVATE cxx_std_17)
target_link_options(stack_overflow_bypass_canary PRIVATE -no-pie)

add_executable(stack_overflow_bypass_pie stack_overflow_bypass_canary.cpp)
target_compile_options(stack_overflow_bypass_pie PRIVATE -fomit-frame-pointer)
target_compile_features(stack_overflow_bypass_pie PRIVATE cxx_std_17)

add_executable(getenvvar getenvvar.c)

add_executable(shellcode shellcode.c)
target_compile_options(shellcode PRIVATE -fno-stack-protector)
target_link_options(shellcode PRIVATE -z execstack)

add_executable(mysh mysh.c)
add_executable(server server.c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
