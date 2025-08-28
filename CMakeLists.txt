cmake_minimum_required(VERSION 3.10)

project(mqtt VERSION 0.0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra -Wno-unused-parameter")

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBUV REQUIRED libuv)
if(NOT LIBUV_FOUND)
    message(FATAL_ERROR "libuv library not found")
endif()

find_package(OpenSSL REQUIRED)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${LIBUV_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})

link_directories(${LIBUV_LIBRARY_DIRS})

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

target_link_libraries(mqtt_broker ${LIBUV_LIBRARIES})
target_link_libraries(mqtt_proxy ${LIBUV_LIBRARIES} ${OPENSSL_LIBRARIES} pthread)
target_link_libraries(mqtt_sn_gateway ${LIBUV_LIBRARIES})
