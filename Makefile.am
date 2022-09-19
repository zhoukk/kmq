ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = mqtt_broker mqtt_proxy mqtt_sn_gateway mqtt_pub mqtt_sub mqtt_sn_pub mqtt_sn_sub mqtt_cli_test mqtt_sn_cli_test mqtt_test

BROKER_SRCS = \
    mqtt.h \
    snowflake.h \
    rbtree.h rbtree.c \
    map.h \
    queue.h \
    http_parser.c \
    mqtt_broker.c

mqtt_broker_SOURCES = $(BROKER_SRCS)
mqtt_broker_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter
mqtt_broker_LDFLAGS =
mqtt_broker_LDADD = -luv

PROXY_SRCS = \
    websocket.h \
    tls.h \
    map.h \
    rbtree.h rbtree.c \
    http_parser.h \
    http_parser.c \
    mqtt_proxy.c

mqtt_proxy_SOURCES = $(PROXY_SRCS)
mqtt_proxy_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter -I/usr/local/opt/openssl/include
mqtt_proxy_LDFLAGS = -L/usr/local/opt/openssl/lib
mqtt_proxy_LDADD = -luv -lssl -lcrypto -lpthread

GATEWAY_SRCS = \
    mqtt.h \
    snowflake.h \
    rbtree.h rbtree.c \
    map.h \
    queue.h \
    mqtt_sn_gateway.c

mqtt_sn_gateway_SOURCES = $(GATEWAY_SRCS)
mqtt_sn_gateway_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter
mqtt_sn_gateway_LDFLAGS =
mqtt_sn_gateway_LDADD = -luv

mqtt_pub_SOURCE = mqtt_pub.c mqtt_cli.h mqtt.h
mqtt_pub_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter
mqtt_pub_LDFLAGS =
mqtt_pub_LDADD =

mqtt_sub_SOURCE = mqtt_sub.c mqtt_cli.h mqtt.h
mqtt_sub_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter
mqtt_sub_LDFLAGS =
mqtt_sub_LDADD =

mqtt_sn_pub_SOURCE = mqtt_sn_pub.c mqtt_sn_cli.h mqtt.h
mqtt_sn_pub_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter
mqtt_sn_pub_LDFLAGS =
mqtt_sn_pub_LDADD =

mqtt_sn_sub_SOURCE = mqtt_sn_sub.c mqtt_sn_cli.h mqtt.h
mqtt_sn_sub_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter
mqtt_sn_sub_LDFLAGS =
mqtt_sn_sub_LDADD =

mqtt_cli_test_SOURCE = mqtt_cli_test.c mqtt_cli.h mqtt.h
mqtt_cli_test_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter
mqtt_cli_test_LDFLAGS =
mqtt_cli_test_LDADD =

mqtt_sn_cli_test_SOURCE = mqtt_sn_cli_test.c mqtt_sn_cli.h mqtt.h
mqtt_sn_cli_test_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter
mqtt_sn_cli_test_LDFLAGS =
mqtt_sn_cli_test_LDADD =

mqtt_test_SOURCE = mqtt_test.c mqtt.h
mqtt_test_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter
mqtt_test_LDFLAGS =
mqtt_test_LDADD =