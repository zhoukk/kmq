#define MQTT_SN_CLI_LINUX_PLATFORM
#define MQTT_SN_CLI_IMPL
#include "mqtt_sn_cli.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static const char *topic = "mqtt-sn/client/test";
static mqtt_sn_qos_t qos = MQTT_SN_QOS_2;
static mqtt_str_t message = MQTT_STR_INITIALIZER;
static mqtt_sn_topic_t t;

static void
_advertise(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    mqtt_sn_cli_state_t state;
    printf("advertise id: %d, duration: %d\n", pkt->v.advertise.gwid, pkt->v.advertise.duration);

    state = mqtt_sn_cli_state(m);
    if (MQTT_SN_STATE_DISCONNECTED == state || MQTT_SN_STATE_SEARCHGW == state) {
        linux_udp_set_unicast(ud, linux_udp_from_address(ud));
        mqtt_sn_cli_connect(m);
    }
}

static void
_searchgw(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    printf("searchgw radius: %d\n", pkt->v.searchgw.radius);
}

static void
_gwinfo(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    mqtt_sn_cli_state_t state;
    printf("gwinfo %d %.*s\n", pkt->v.gwinfo.gwid, MQTT_STR_PRINT(pkt->v.gwinfo.gwadd));

    state = mqtt_sn_cli_state(m);
    if (MQTT_SN_STATE_DISCONNECTED == state || MQTT_SN_STATE_SEARCHGW == state) {
        linux_udp_set_unicast(ud, linux_udp_from_address(ud));
        mqtt_sn_cli_connect(m);
    }
}

static void
_connack(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {

    if (pkt->v.connack.return_code != MQTT_SN_RC_ACCEPTED) {
        printf("connect %s\n", mqtt_sn_rc_name(pkt->v.connack.return_code));
        return;
    }
    printf("connack %s\n", mqtt_sn_rc_name(pkt->v.connack.return_code));

    mqtt_sn_cli_register(m, topic, 0);
}

static void
_regack(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    uint16_t packet_id;

    printf("regack %s %d %d\n", mqtt_sn_rc_name(pkt->v.regack.return_code), pkt->v.regack.msg_id,
           pkt->v.regack.topic_id);

    t.type = MQTT_SN_TOPIC_ID_TYPE_PREDEFINED;
    t.id = pkt->v.regack.topic_id;
    mqtt_sn_cli_subscribe(m, &t, qos, &packet_id);
}

static void
_suback(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    uint16_t packet_id;

    printf("suback (id:%" PRIu16 ") %s\n", pkt->v.suback.msg_id, mqtt_sn_rc_name(pkt->v.suback.return_code));

    mqtt_sn_cli_publish(m, 0, &t, qos, &message, &packet_id);
}

static void
_unsuback(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    printf("unsuback (id:%" PRIu16 ")\n", pkt->v.unsuback.msg_id);
    mqtt_sn_cli_disconnect(m, 0);
}

static void
_puback(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    uint16_t packet_id;

    printf("puback (id:%" PRIu16 ") %s\n", pkt->v.puback.msg_id, mqtt_sn_rc_name(pkt->v.puback.return_code));
    mqtt_sn_cli_unsubscribe(m, &t, &packet_id);
}

static void
_publish(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    printf("publish (id:%" PRIu16 ", topic:%d) %.*s\n", pkt->v.publish.msg_id, pkt->v.publish.topic.id,
           MQTT_STR_PRINT(pkt->v.publish.data));
}

static void
_disconnect(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    printf("disconnect duration: %d\n", pkt->v.disconnect.duration);
}

int
main(int argc, char *argv[]) {
    void *net;
    mqtt_sn_cli_t *m;
    mqtt_sn_cli_conf_t config = {
        .client_id = "mqtt_sn_cli_test",
        .duration = 60,
        .clean_session = 1,
        .lwt =
            {
                .retain = 0,
                .topic = "mqtt-sn/client/exit",
                .qos = MQTT_SN_QOS_1,
                .message = {.s = "byebye", .n = 6},
            },
        .cb =
            {
                .advertise = _advertise,
                .searchgw = _searchgw,
                .gwinfo = _gwinfo,
                .connack = _connack,
                .regack = _regack,
                .suback = _suback,
                .unsuback = _unsuback,
                .puback = _puback,
                .publish = _publish,
                .disconnect = _disconnect,
            },
        .ud = 0,
    };

    mqtt_str_from(&message, "hello world");

    net = linux_udp_open("0.0.0.0", MQTT_SN_UDP_PORT);
    if (!net) {
        return EXIT_FAILURE;
    }
    config.ud = net;

    linux_udp_set_broadcast(net, MQTT_SN_UDP_PORT);
    m = mqtt_sn_cli_create(&config);

    mqtt_sn_cli_searchgw(m, 1);

    while (1) {
        mqtt_str_t outgoing, incoming;
        uint64_t t1, t2;

        t1 = linux_time_now();
        mqtt_sn_cli_outgoing(m, &outgoing);
        if (linux_udp_transfer(net, &outgoing, &incoming)) {
            break;
        }
        if (mqtt_sn_cli_incoming(m, &incoming)) {
            break;
        }
        t2 = linux_time_now();
        if (mqtt_sn_cli_elapsed(m, t2 - t1)) {
            break;
        }
    }

    mqtt_sn_cli_destroy(m);

    linux_udp_close(net);
    return 0;
}
