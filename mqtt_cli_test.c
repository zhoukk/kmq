#define MQTT_CLI_LINUX_PLATFORM
#define MQTT_CLI_IMPL
#include "mqtt_cli.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

static const char *topic = "mqtt/client/test";
static mqtt_qos_t qos = MQTT_QOS_2;
static mqtt_str_t message = MQTT_STR_INITIALIZER;

static void
_connack(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    uint16_t packet_id;

    if (pkt->v.connack.v4.return_code != MQTT_CRC_ACCEPTED) {
        printf("connect %s\n", mqtt_crc_name(pkt->v.connack.v4.return_code));
        return;
    }
    printf("connack sp:%" PRIu8 "\n", pkt->v.connack.v4.acknowledge_flags.bits.session_present);
    if (!mqtt_cli_subscribe(m, 1, &topic, &qos, &packet_id)) {
        printf("send subscribe (id:%" PRIu16 ") ok\n", packet_id);
    }
}

static void
_suback(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    uint16_t packet_id;

    printf("suback (id:%" PRIu16 ")\n", pkt->v.suback.packet_id);
    if (!mqtt_cli_publish(m, 0, topic, qos, &message, &packet_id)) {
        printf("send publish (id:%" PRIu16 ") ok\n", packet_id);
    }
}

static void
_unsuback(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    printf("unsuback (id:%" PRIu16 ")\n", pkt->v.unsuback.packet_id);
    if (!mqtt_cli_disconnect(m)) {
        printf("send disconnect ok\n");
    }
}

static void
_puback(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    uint16_t packet_id;

    printf("puback (id:%" PRIu16 ")\n", pkt->v.puback.packet_id);
    if (!mqtt_cli_unsubscribe(m, 1, &topic, &packet_id)) {
        printf("send unsubscribe (id:%" PRIu16 ") ok\n", packet_id);
    }
}

static void
_publish(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    printf("publish (id:%" PRIu16 ", topic:%.*s) %.*s\n", pkt->v.publish.packet_id,
           MQTT_STR_PRINT(pkt->v.publish.topic_name), MQTT_STR_PRINT(pkt->p.publish.message));
}

int
main(int argc, char *argv[]) {
    void *net;
    mqtt_cli_t *m;
    mqtt_cli_conf_t config = {
        .client_id = "mqtt_cli_test",
        .version = MQTT_VERSION_4,
        .keep_alive = 60,
        .clean_session = 1,
        .auth =
            {
                .username = "mqtt_cli",
                .password = "123456",
            },
        .lwt =
            {
                .retain = 0,
                .topic = "mqtt/client/exit",
                .qos = MQTT_QOS_1,
                .message = {.s = "byebye", .n = 6},
            },
        .cb =
            {
                .connack = _connack,
                .suback = _suback,
                .unsuback = _unsuback,
                .puback = _puback,
                .publish = _publish,
            },
        .ud = 0,
    };

    mqtt_str_from(&message, "hello world");

    net = linux_tcp_connect("127.0.0.1", MQTT_TCP_PORT);
    if (!net) {
        exit(EXIT_FAILURE);
    }

    m = mqtt_cli_create(&config);
    mqtt_cli_connect(m);
    while (1) {
        mqtt_str_t outgoing, incoming;
        uint64_t t1, t2;

        t1 = linux_time_now();
        mqtt_cli_outgoing(m, &outgoing);
        if (linux_tcp_transfer(net, &outgoing, &incoming)) {
            break;
        }
        if (mqtt_cli_incoming(m, &incoming)) {
            break;
        }
        t2 = linux_time_now();
        if (mqtt_cli_elapsed(m, t2 - t1)) {
            break;
        }
    }
    mqtt_cli_destroy(m);

    linux_tcp_close(net);
    return 0;
}
