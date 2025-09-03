cmake_minimum_required(VERSION 3.10)

project(mqtt VERSION 0.0.1 LANGUAGES C)

include(CheckCCompilerFlag)
check_c_compiler_flag(-std=c11 HAS_C11)
if(HAS_C11)
    set(CMAKE_C_STANDARD 11)
    include(CheckSymbolExists)
    set(CMAKE_REQUIRED_FLAGS -std=c11)
    check_symbol_exists(thrd_create "threads.h" HAS_C11_THREADS)
    if(HAS_C11_THREADS)
        add_compile_definitions(HAVE_C11_THREADS=1)
    else()
        add_compile_definitions(HAVE_C11_THREADS=0)
    endif()
else()
    set(CMAKE_C_STANDARD 99)
    add_compile_definitions(HAVE_C11_THREADS=0)
endif()
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra -Wno-unused-parameter")
endif()

if(WIN32)
    find_package(OpenSSL)
else()
    find_package(OpenSSL)
endif()

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(mqtt_broker
    mqtt_broker.c
    rbtree.c
    http_parser.c
)

add_executable(mqtt_proxy
    mqtt_proxy.c
    http_parser.c
    rbtree.c
)

add_executable(mqtt_sn_gateway
    mqtt_sn_gateway.c
    rbtree.c
)

add_executable(mqtt_pub
    mqtt_pub.c
)

add_executable(mqtt_sub
    mqtt_sub.c
)

add_executable(mqtt_sn_pub
    mqtt_sn_pub.c
)

add_executable(mqtt_sn_sub
    mqtt_sn_sub.c
)

add_executable(mqtt_cli_test
    mqtt_cli_test.c
)

add_executable(mqtt_sn_cli_test
    mqtt_sn_cli_test.c
)

add_executable(mqtt_test
    mqtt_test.c
)

if(WIN32)
    target_link_libraries(mqtt_cli_test ${OPENSSL_LIBRARIES} ws2_32)
    target_link_libraries(mqtt_sn_cli_test ws2_32)
    target_link_libraries(mqtt_pub ws2_32)
    target_link_libraries(mqtt_sub ws2_32)
    target_link_libraries(mqtt_sn_pub ws2_32)
    target_link_libraries(mqtt_sn_sub ws2_32)
    target_link_libraries(mqtt_broker uv ws2_32)
    target_link_libraries(mqtt_proxy uv ${OPENSSL_LIBRARIES} ws2_32)
    target_link_libraries(mqtt_sn_gateway uv ws2_32)
else()
    target_link_libraries(mqtt_cli_test ${OPENSSL_LIBRARIES})
    target_link_libraries(mqtt_broker uv)
    target_link_libraries(mqtt_proxy uv ${OPENSSL_LIBRARIES} pthread)
    target_link_libraries(mqtt_sn_gateway uv)
endif()
