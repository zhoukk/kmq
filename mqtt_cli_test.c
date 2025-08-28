#define MQTT_CLI_NETWORK_IMPL
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

#define MQTT_MEMPOOL_IMPL
#include "mqtt_mempool.h"

static mqtt_mempool_t *g_mempool = NULL;

static void *
mqtt_mempool_malloc_adapter(size_t size) {
    if (g_mempool) {
        return mqtt_mempool_alloc(g_mempool, size);
    }
    return malloc(size);
}

static void
mqtt_mempool_free_adapter(void *ptr) {
    if (g_mempool) {
        mqtt_mempool_free(g_mempool, ptr);
    } else {
        free(ptr);
    }
}

int
main(int argc, char *argv[]) {

    g_mempool = mqtt_mempool_create(0);

    mqtt_set_allocator(mqtt_mempool_malloc_adapter, mqtt_mempool_free_adapter);

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

    net = network_tcp_connect("127.0.0.1", MQTT_TCP_PORT);
    if (!net) {
        exit(EXIT_FAILURE);
    }

    m = mqtt_cli_create(&config);
    mqtt_cli_connect(m);
    while (1) {
        mqtt_str_t outgoing, incoming;
        uint64_t t1, t2;

        t1 = network_time_now();
        mqtt_cli_outgoing(m, &outgoing);
        if (network_tcp_transfer(net, &outgoing, &incoming)) {
            break;
        }
        if (mqtt_cli_incoming(m, &incoming)) {
            break;
        }
        t2 = network_time_now();
        if (mqtt_cli_elapsed(m, t2 - t1)) {
            break;
        }
    }
    mqtt_cli_destroy(m);

    network_tcp_close(net);

    size_t allocated_size = 0, used_size = 0, total_allocations = 0, total_frees = 0;
    double hit_rate = 0;
    mqtt_mempool_stats(g_mempool, &allocated_size, &used_size, &total_allocations, &total_frees, &hit_rate);

    printf("Memory pool stats:\n");
    printf("  Allocated size: %zu bytes\n", allocated_size);
    printf("  Used size: %zu bytes\n", used_size);
    printf("  Total allocations: %zu\n", total_allocations);
    printf("  Total frees: %zu\n", total_frees);
    printf("  Hit rate: %.2f\n", hit_rate);

    mqtt_mempool_destroy(g_mempool);
    g_mempool = NULL;

    printf("Memory pool destroyed\n");

    return 0;
}
