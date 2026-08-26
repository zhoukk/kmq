/*
 * mqtt_remote_test.c -- functional test suite for a remote MQTT broker.
 *
 * Connects to a broker at host:port (default 120.26.78.56:1883) and runs
 * scenario tests over the network, covering MQTT 3.1.1 and MQTT 5.0:
 * CONNACK and server capabilities, QoS 0/1/2 round trips, wildcards,
 * retained messages and retain-handling options, session persistence
 * and expiry, wills (immediate / cancelled / delayed), ping/keepalive,
 * shared subscriptions, topic aliases (both directions), subscription
 * identifiers, property pass-through, large payloads, and protocol
 * error handling.
 *
 * Usage:
 *   mqtt_remote_test [-h host] [-p port] [-u user] [-w pass] [-t timeout_ms] [test_prefix]
 *
 * test_prefix (optional) runs only the tests whose name starts with it.
 * Exit code: 0 = all tests passed, 1 = at least one failure.
 */

#define MQTT_CLI_NETWORK_IMPL
#define MQTT_CLI_IMPL
#include "mqtt_cli.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ================================================================== */
/* test harness                                                       */
/* ================================================================== */

static int g_checks;
static int g_checks_failed;
static int g_failed; /* per-test, reset in test_begin */
static int g_tests;
static int g_tests_failed;
static int g_tests_skipped;
static int g_skip;
static const char *g_test = "";

static void
test_begin(const char *name) {
    g_test = name;
    g_tests++;
    g_failed = 0;
    g_skip = 0;
    fprintf(stderr, "== %s\n", name);
}

static void
test_skip(const char *why) {
    g_skip = 1;
    fprintf(stderr, "  SKIP %s\n", why);
}

static void
test_end(void) {
    if (g_skip) {
        g_tests_skipped++;
        fprintf(stderr, "-- %s skipped\n\n", g_test);
    } else if (g_failed) {
        g_tests_failed++;
        fprintf(stderr, "-- %s FAILED\n\n", g_test);
    } else {
        fprintf(stderr, "-- %s ok\n\n", g_test);
    }
}

#define CHECK(cond, ...) \
    do { \
        g_checks++; \
        if (!(cond)) { \
            g_failed++; \
            g_checks_failed++; \
            fprintf(stderr, "  FAIL %s:%d ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, "\n"); \
        } \
    } while (0)

#define CHECK_EQ_INT(a, b, what) CHECK((a) == (b), "%s: got %" PRId64 " want %" PRId64, what, (int64_t)(a), (int64_t)(b))

static uint64_t
ms_now(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ================================================================== */
/* configuration                                                      */
/* ================================================================== */

static char g_host[128] = "120.26.78.56";
static int g_port = 1883;
static char g_user[128] = "";
static char g_pass[192] = "";
static int g_timeout_ms = 10000;
static const char *g_filter = "";

/* per-run unique names so parallel runs do not collide */
static char g_topic[96];
static char g_rt_topic[128]; /* <g_topic>/resp */
static int g_id_seq;

static const char *
next_client_id(char *buf, size_t n) {
    snprintf(buf, n, "kmqrt%d-%d", (int)getpid(), ++g_id_seq);
    return buf;
}

/* capability flags learned from the v5 CONNACK (0 = unknown/absent) */
static int g_cap_shared;
static int g_cap_subid;
static int g_cap_retain;
static int g_cap_wildcard;
static uint16_t g_cap_alias_max; /* server -> client topic alias maximum */
static uint32_t g_cap_max_packet;

/* ================================================================== */
/* raw mqtt client                                                    */
/* ================================================================== */

typedef struct {
    uint16_t alias;
    char topic[160];
} alias_entry_t;

typedef struct {
    void *net;
    mqtt_parser_t parser;
    uint16_t next_id;
    mqtt_version_t ver;
    int alive;
    int no_ack; /* when set, incoming QoS1/2 publications are not acked */
    alias_entry_t in_alias[16]; /* server -> client topic aliases */
    char topic_buf[256];        /* NUL-terminated topic of the last PUBLISH */
    mqtt_packet_t stashed;      /* first non-matching PUBLISH */
    char *rx;
    size_t rx_n;
    size_t rx_cap;
} cli_t;

static int
cli_open(cli_t *cli, mqtt_version_t ver) {
    int attempt;

    memset(cli, 0, sizeof *cli);
    /* the target may be across the internet: retry a few times on failure */
    for (attempt = 0; attempt < 3; attempt++) {
        cli->net = network_tcp_connect(g_host, g_port);
        if (cli->net) {
            break;
        }
        usleep(500 * 1000);
    }
    if (!cli->net) {
        return -1;
    }
    cli->ver = ver;
    cli->alive = 1;
    cli->rx_cap = 1024 * 1024;
    cli->rx = (char *)malloc(cli->rx_cap);
    if (!cli->rx) {
        network_tcp_close(cli->net);
        cli->net = 0;
        return -1;
    }
    mqtt_parser_init(&cli->parser);
    mqtt_parser_version(&cli->parser, ver);
    return 0;
}

static void
cli_close(cli_t *cli) {
    if (cli->stashed.f.flags) {
        mqtt_packet_cleanup(&cli->stashed);
    }
    free(cli->rx);
    cli->rx = 0;
    if (cli->net) {
        network_tcp_close(cli->net);
        cli->net = 0;
    }
    cli->alive = 0;
}

static int
cli_wait(cli_t *cli, mqtt_packet_type_t type, int timeout_ms, mqtt_packet_t *pkt);

/* next PUBLISH for this client: from the stash if one was kept, else wait */
static int
cli_next_publish(cli_t *cli, mqtt_packet_t *pkt, int timeout_ms) {
    if (cli->stashed.f.flags) {
        *pkt = cli->stashed;
        memset(&cli->stashed, 0, sizeof *pkt);
        return 0;
    }
    return cli_wait(cli, MQTT_PUBLISH, timeout_ms, pkt);
}

static uint16_t
cli_next_id(cli_t *cli) {
    cli->next_id++;
    if (cli->next_id == 0) {
        cli->next_id++;
    }
    return cli->next_id;
}

static int
cli_send_raw(cli_t *cli, const char *data, size_t n) {
    if (network_tcp_send(cli->net, data, n) < 0) {
        cli->alive = 0;
        return -1;
    }
    return 0;
}

static int
cli_send_pkt(cli_t *cli, mqtt_packet_t *pkt) {
    mqtt_str_t b = MQTT_STR_INITIALIZER;
    int rc;

    rc = mqtt_serialize(pkt, &b);
    if (rc) {
        mqtt_packet_cleanup(pkt);
        return -1;
    }
    rc = cli_send_raw(cli, b.s, b.n);
    mqtt_str_free(&b);
    mqtt_packet_cleanup(pkt);
    return rc;
}

/* answer incoming QoS1/2 publications so the broker's in-flight windows drain */
static int
cli_auto_ack(cli_t *cli, const mqtt_packet_t *pkt) {
    mqtt_packet_t ack;
    mqtt_qos_t qos;
    mqtt_packet_type_t type;

    if (cli->no_ack) {
        return 0;
    }
    type = (mqtt_packet_type_t)MQTT_FH_TYPE(pkt->f.flags);
    qos = (mqtt_qos_t)MQTT_FH_QOS(pkt->f.flags);

    if (type == MQTT_PUBLISH) {
        if (qos == MQTT_QOS_1) {
            mqtt_packet_init(&ack, cli->ver, MQTT_PUBACK);
            ack.v.puback.packet_id = pkt->v.publish.packet_id;
            return cli_send_pkt(cli, &ack);
        }
        if (qos == MQTT_QOS_2) {
            mqtt_packet_init(&ack, cli->ver, MQTT_PUBREC);
            ack.v.pubrec.packet_id = pkt->v.publish.packet_id;
            return cli_send_pkt(cli, &ack);
        }
        return 0;
    }
    if (type == MQTT_PUBREC) {
        mqtt_packet_init(&ack, cli->ver, MQTT_PUBREL);
        ack.v.pubrel.packet_id = pkt->v.pubrec.packet_id;
        return cli_send_pkt(cli, &ack);
    }
    if (type == MQTT_PUBREL) {
        mqtt_packet_init(&ack, cli->ver, MQTT_PUBCOMP);
        ack.v.pubcomp.packet_id = pkt->v.pubrel.packet_id;
        return cli_send_pkt(cli, &ack);
    }
    return 0;
}

/*
 * wait for one packet of the given type. Other packets are consumed
 * (and acked where required).
 * returns: 0 packet in *pkt, -1 timeout, -2 connection closed
 */
static int
cli_wait(cli_t *cli, mqtt_packet_type_t type, int timeout_ms, mqtt_packet_t *pkt) {
    uint64_t deadline;

    memset(pkt, 0, sizeof *pkt);
    deadline = ms_now() + (uint64_t)timeout_ms;
    for (;;) {
        if (cli->rx_n > 0) {
            mqtt_str_t incoming;
            int rc;

            mqtt_str_init(&incoming, cli->rx, cli->rx_n);
            while ((rc = mqtt_parse(&cli->parser, &incoming, pkt)) > 0) {
                if (MQTT_FH_TYPE(pkt->f.flags) == type) {
                    cli_auto_ack(cli, pkt);
                    memmove(cli->rx, cli->rx + incoming.i, cli->rx_n - incoming.i);
                    cli->rx_n -= incoming.i;
                    return 0;
                }
                cli_auto_ack(cli, pkt);
                if (MQTT_FH_TYPE(pkt->f.flags) == MQTT_PUBLISH && cli->stashed.f.flags == 0) {
                    cli->stashed = *pkt;
                    memset(pkt, 0, sizeof *pkt);
                } else {
                    mqtt_packet_cleanup(pkt);
                }
            }
            if (rc < 0) {
                cli->alive = 0;
                return -2;
            }
            memmove(cli->rx, cli->rx + incoming.i, cli->rx_n - incoming.i);
            cli->rx_n -= incoming.i;
        }
        if (ms_now() >= deadline) {
            return -1;
        }
        {
            ssize_t r = network_tcp_recv(cli->net, cli->rx + cli->rx_n, cli->rx_cap - cli->rx_n);
            if (r < 0) {
                cli->alive = 0;
                return -2;
            }
            if (r > 0) {
                cli->rx_n += (size_t)r;
            }
        }
    }
}

/*
 * resolve the (possibly aliased) topic name of a received PUBLISH.
 * the topic bytes are not NUL-terminated on the wire, so the result is
 * copied into a per-client buffer.
 */
static const char *
cli_publish_topic(cli_t *cli, mqtt_packet_t *pkt) {
    mqtt_property_t *prop;
    uint16_t alias;
    int i;

    if (pkt->v.publish.topic_name.n > 0) {
        prop = mqtt_properties_find(&pkt->v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS);
        if (prop) {
            alias = prop->b2;
            for (i = 0; i < 16; i++) {
                if (cli->in_alias[i].alias == 0 || cli->in_alias[i].alias == alias) {
                    cli->in_alias[i].alias = alias;
                    snprintf(cli->in_alias[i].topic, sizeof(cli->in_alias[i].topic), "%.*s",
                             (int)pkt->v.publish.topic_name.n, pkt->v.publish.topic_name.s);
                    break;
                }
            }
        }
        snprintf(cli->topic_buf, sizeof(cli->topic_buf), "%.*s", (int)pkt->v.publish.topic_name.n,
                 pkt->v.publish.topic_name.s);
        return cli->topic_buf;
    }
    prop = mqtt_properties_find(&pkt->v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS);
    if (!prop) {
        return "";
    }
    alias = prop->b2;
    for (i = 0; i < 16; i++) {
        if (cli->in_alias[i].alias == alias) {
            return cli->in_alias[i].topic;
        }
    }
    return "";
}

/* ------------------------------------------------------------------ */
/* packet builders                                                     */
/* ------------------------------------------------------------------ */

/*
 * CONNECT + wait for CONNACK.
 * returns 0 on CONNACK (in *connack), -1 timeout, -2 error.
 */
static int
cli_connect(cli_t *cli, const char *client_id, int clean, uint16_t keepalive, uint32_t session_expiry,
            uint16_t receive_max, uint16_t alias_max, const char *will_topic, const char *will_msg,
            mqtt_qos_t will_qos, uint32_t will_delay, mqtt_packet_t *connack) {
    mqtt_packet_t pkt;
    uint32_t v4;
    uint16_t v2;
    int rc;

    memset(connack, 0, sizeof *connack);
    mqtt_packet_init(&pkt, cli->ver, MQTT_CONNECT);
    if (clean) {
        pkt.v.connect.connect_flags |= MQTT_CF_CLEAN_SESSION;
    }
    pkt.v.connect.keep_alive = keepalive;
    if (client_id) {
        mqtt_str_from(&pkt.p.connect.client_id, client_id);
    }
    if (g_user[0]) {
        pkt.v.connect.connect_flags |= MQTT_CF_USERNAME;
        mqtt_str_from(&pkt.p.connect.username, g_user);
    }
    if (g_pass[0]) {
        pkt.v.connect.connect_flags |= MQTT_CF_PASSWORD;
        mqtt_str_from(&pkt.p.connect.password, g_pass);
    }
    if (cli->ver == MQTT_VERSION_5) {
        if (session_expiry) {
            v4 = session_expiry;
            mqtt_properties_add(&pkt.v.connect.v5.properties, MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL, &v4, NULL);
        }
        if (receive_max) {
            v2 = receive_max;
            mqtt_properties_add(&pkt.v.connect.v5.properties, MQTT_PROPERTY_RECEIVE_MAXIMUM, &v2, NULL);
        }
        if (alias_max) {
            v2 = alias_max;
            mqtt_properties_add(&pkt.v.connect.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM, &v2, NULL);
        }
        if (will_topic) {
            pkt.v.connect.connect_flags |= MQTT_CF_WILL_FLAG | ((uint8_t)will_qos << 3);
            mqtt_str_from(&pkt.p.connect.will_topic, will_topic);
            mqtt_str_from(&pkt.p.connect.will_message, will_msg);
            if (will_delay) {
                v4 = will_delay;
                mqtt_properties_add(&pkt.p.connect.v5.will_properties, MQTT_PROPERTY_WILL_DELAY_INTERVAL, &v4, NULL);
            }
        }
    } else if (will_topic) {
        pkt.v.connect.connect_flags |= MQTT_CF_WILL_FLAG | ((uint8_t)will_qos << 3);
        mqtt_str_from(&pkt.p.connect.will_topic, will_topic);
        mqtt_str_from(&pkt.p.connect.will_message, will_msg);
    }

    if (cli_send_pkt(cli, &pkt)) {
        return -2;
    }
    rc = cli_wait(cli, MQTT_CONNACK, g_timeout_ms, connack);
    if (rc != 0) {
        cli->alive = 0;
    }
    return rc;
}

static int
cli_publish(cli_t *cli, const char *topic, mqtt_qos_t qos, int retain, const char *payload, uint16_t *id) {
    mqtt_packet_t pkt;
    uint16_t pid = 0;

    mqtt_packet_init(&pkt, cli->ver, MQTT_PUBLISH);
    pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, qos, retain);
    if (qos > MQTT_QOS_0) {
        pid = cli_next_id(cli);
    }
    pkt.v.publish.packet_id = pid;
    mqtt_str_from(&pkt.v.publish.topic_name, topic);
    mqtt_str_from(&pkt.p.publish.message, payload);
    if (id) {
        *id = pid;
    }
    return cli_send_pkt(cli, &pkt);
}

/* v5 PUBLISH with properties (user property, content type, ...) */
static int
cli_publish5_props(cli_t *cli, const char *topic, mqtt_qos_t qos, const char *payload, uint16_t *id) {
    mqtt_packet_t pkt;
    uint16_t pid = 0;
    mqtt_str_t corr;
    uint32_t meqi = 120;

    mqtt_packet_init(&pkt, cli->ver, MQTT_PUBLISH);
    pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, qos, 0);
    if (qos > MQTT_QOS_0) {
        pid = cli_next_id(cli);
    }
    pkt.v.publish.packet_id = pid;
    mqtt_str_from(&pkt.v.publish.topic_name, topic);
    mqtt_str_from(&pkt.p.publish.message, payload);
    mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_USER_PROPERTY, "v1", "k1");
    mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_USER_PROPERTY, "v2", "k2");
    mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_CONTENT_TYPE, "text/plain", NULL);
    mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_RESPONSE_TOPIC, g_rt_topic, NULL);
    mqtt_str_init(&corr, (char *)"corr-123", strlen("corr-123"));
    mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_CORRELATION_DATA, &corr, NULL);
    mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL, &meqi, NULL);
    if (id) {
        *id = pid;
    }
    return cli_send_pkt(cli, &pkt);
}

/* v5 PUBLISH carrying a topic alias (empty topic when alias-only) */
static int
cli_publish_alias(cli_t *cli, const char *topic, uint16_t alias, const char *payload, uint16_t *id) {
    mqtt_packet_t pkt;
    uint16_t pid = 0;

    mqtt_packet_init(&pkt, cli->ver, MQTT_PUBLISH);
    pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_1, 0);
    pid = cli_next_id(cli);
    pkt.v.publish.packet_id = pid;
    if (topic) {
        mqtt_str_from(&pkt.v.publish.topic_name, topic);
    }
    mqtt_str_from(&pkt.p.publish.message, payload);
    mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS, &alias, NULL);
    if (id) {
        *id = pid;
    }
    return cli_send_pkt(cli, &pkt);
}

static int
cli_subscribe(cli_t *cli, int n, const char *filters[], const uint8_t options[], uint32_t sub_id, uint16_t *id) {
    mqtt_packet_t pkt;
    uint16_t pid;
    int i;

    mqtt_packet_init(&pkt, cli->ver, MQTT_SUBSCRIBE);
    pid = cli_next_id(cli);
    pkt.v.subscribe.packet_id = pid;
    if (mqtt_subscribe_generate(&pkt, n)) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        mqtt_str_from(&pkt.p.subscribe.topic_filters[i], filters[i]);
        pkt.p.subscribe.options[i].flags = options[i];
    }
    if (cli->ver == MQTT_VERSION_5 && sub_id) {
        uint32_t sid = sub_id;

        mqtt_properties_add(&pkt.v.subscribe.v5.properties, MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER, &sid, NULL);
    }
    if (id) {
        *id = pid;
    }
    return cli_send_pkt(cli, &pkt);
}

static int
cli_unsubscribe(cli_t *cli, int n, const char *filters[], uint16_t *id) {
    mqtt_packet_t pkt;
    uint16_t pid;
    int i;

    mqtt_packet_init(&pkt, cli->ver, MQTT_UNSUBSCRIBE);
    pid = cli_next_id(cli);
    pkt.v.unsubscribe.packet_id = pid;
    if (mqtt_unsubscribe_generate(&pkt, n)) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[i], filters[i]);
    }
    if (id) {
        *id = pid;
    }
    return cli_send_pkt(cli, &pkt);
}

static int
cli_ping(cli_t *cli) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, cli->ver, MQTT_PINGREQ);
    return cli_send_pkt(cli, &pkt);
}

static int
cli_disconnect(cli_t *cli) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, cli->ver, MQTT_DISCONNECT);
    return cli_send_pkt(cli, &pkt);
}

/* v5 DISCONNECT with reason code */
static int
cli_disconnect5(cli_t *cli, uint8_t reason) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_DISCONNECT);
    pkt.v.disconnect.v5.reason_code = (mqtt_rc_t)reason;
    return cli_send_pkt(cli, &pkt);
}

/* v5 AUTH packet */
static int
cli_auth5(cli_t *cli, const char *method, const char *data) {
    mqtt_packet_t pkt;
    mqtt_str_t d;

    mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_AUTH);
    pkt.v.auth.v5.reason_code = MQTT_RC_SUCCESS;
    if (method) {
        mqtt_properties_add(&pkt.v.auth.v5.properties, MQTT_PROPERTY_AUTHENTICATION_METHOD, method, NULL);
    }
    if (data) {
        mqtt_str_init(&d, (char *)data, strlen(data));
        mqtt_properties_add(&pkt.v.auth.v5.properties, MQTT_PROPERTY_AUTHENTICATION_DATA, &d, NULL);
    }
    return cli_send_pkt(cli, &pkt);
}

/* send a raw QoS1/2 ack-style packet with an explicit (possibly unknown) id */
static int
cli_send_ack(cli_t *cli, mqtt_packet_type_t type, uint16_t packet_id) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, cli->ver, type);
    switch (type) {
    case MQTT_PUBACK:
        pkt.v.puback.packet_id = packet_id;
        break;
    case MQTT_PUBREC:
        pkt.v.pubrec.packet_id = packet_id;
        break;
    case MQTT_PUBREL:
        pkt.v.pubrel.packet_id = packet_id;
        break;
    case MQTT_PUBCOMP:
        pkt.v.pubcomp.packet_id = packet_id;
        break;
    default:
        return -1;
    }
    if (cli->ver == MQTT_VERSION_5) {
        switch (type) {
        case MQTT_PUBACK:
            pkt.v.puback.v5.reason_code = MQTT_RC_SUCCESS;
            break;
        case MQTT_PUBREC:
            pkt.v.pubrec.v5.reason_code = MQTT_RC_SUCCESS;
            break;
        case MQTT_PUBREL:
            pkt.v.pubrel.v5.reason_code = MQTT_RC_SUCCESS;
            break;
        case MQTT_PUBCOMP:
            pkt.v.pubcomp.v5.reason_code = MQTT_RC_SUCCESS;
            break;
        default:
            break;
        }
    }
    return cli_send_pkt(cli, &pkt);
}

/* ------------------------------------------------------------------ */
/* property inspection helpers (valid until the next parse)            */
/* ------------------------------------------------------------------ */

static int
prop_b1(mqtt_properties_t *p, mqtt_property_code_t code) {
    mqtt_property_t *x = mqtt_properties_find(p, code);

    return x ? (int)x->b1 : -1;
}

static int
prop_b2(mqtt_properties_t *p, mqtt_property_code_t code) {
    mqtt_property_t *x = mqtt_properties_find(p, code);

    return x ? (int)x->b2 : -1;
}

static int
prop_b4(mqtt_properties_t *p, mqtt_property_code_t code) {
    mqtt_property_t *x = mqtt_properties_find(p, code);

    return x ? (int)x->b4 : -1;
}

static int
prop_str_eq(mqtt_properties_t *p, mqtt_property_code_t code, const char *s) {
    mqtt_property_t *x = mqtt_properties_find(p, code);

    return x && mqtt_str_strcmp(&x->str, s) == 0;
}

static int
prop_str_nonempty(mqtt_properties_t *p, mqtt_property_code_t code) {
    mqtt_property_t *x = mqtt_properties_find(p, code);

    return x && x->str.n > 0;
}

static int
prop_data_eq(mqtt_properties_t *p, mqtt_property_code_t code, const char *s) {
    mqtt_property_t *x = mqtt_properties_find(p, code);

    return x && x->data.n == strlen(s) && memcmp(x->data.s, s, x->data.n) == 0;
}

static int
prop_user_eq(mqtt_properties_t *p, const char *name, const char *value) {
    mqtt_property_t *x;

    for (x = p->head; x; x = x->next) {
        if (x->code == MQTT_PROPERTY_USER_PROPERTY && mqtt_str_strcmp(&x->pair.name, name) == 0 &&
            mqtt_str_strcmp(&x->pair.value, value) == 0) {
            return 1;
        }
    }
    return 0;
}

static int
suback_rc5(mqtt_packet_t *pkt, int i) {
    return (pkt->p.suback.v5.reason_codes && i < pkt->p.suback.n) ? (int)pkt->p.suback.v5.reason_codes[i] : -1;
}

static int
payload_eq(mqtt_packet_t *pkt, const char *s) {
    return pkt->p.publish.message.n == strlen(s) && memcmp(pkt->p.publish.message.s, s, pkt->p.publish.message.n) == 0;
}

/* ------------------------------------------------------------------ */
/* message collection                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    char topic[192];
    char payload[2048];
    size_t payload_n;
    uint8_t qos;
    uint8_t retain;
    uint32_t sub_id; /* 0 = absent */
    uint16_t alias;  /* 0 = absent */
    int user_kv1;
    int user_kv2;
    int ct;
    int rt;
    int corr;
    int meqi;
} rmsg_t;

static int
payload_eq_str(rmsg_t *m, const char *s) {
    return m->payload_n == strlen(s) && memcmp(m->payload, s, m->payload_n) == 0;
}

static void
rmsg_fill(cli_t *cli, rmsg_t *m, mqtt_packet_t *pkt) {
    mqtt_properties_t *p;

    memset(m, 0, sizeof *m);
    snprintf(m->topic, sizeof(m->topic), "%s", cli_publish_topic(cli, (mqtt_packet_t *)pkt));
    m->payload_n = pkt->p.publish.message.n < sizeof(m->payload) ? pkt->p.publish.message.n : sizeof(m->payload);
    memcpy(m->payload, pkt->p.publish.message.s, m->payload_n);
    m->qos = (uint8_t)MQTT_FH_QOS(pkt->f.flags);
    m->retain = (uint8_t)MQTT_FH_RETAIN(pkt->f.flags);
    if (pkt->ver == MQTT_VERSION_5) {
        p = &pkt->v.publish.v5.properties;
        m->sub_id = (uint32_t)prop_b4(p, MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER);
        m->alias = (uint16_t)prop_b2(p, MQTT_PROPERTY_TOPIC_ALIAS);
        m->user_kv1 = prop_user_eq(p, "k1", "v1");
        m->user_kv2 = prop_user_eq(p, "k2", "v2");
        m->ct = prop_str_eq(p, MQTT_PROPERTY_CONTENT_TYPE, "text/plain");
        m->rt = prop_str_eq(p, MQTT_PROPERTY_RESPONSE_TOPIC, g_rt_topic);
        m->corr = prop_data_eq(p, MQTT_PROPERTY_CORRELATION_DATA, "corr-123");
        m->meqi = prop_b4(p, MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL);
    }
}

/*
 * collect up to n PUBLISHes (blocking until timeout).
 * returns the number collected.
 */
static int
cli_collect(cli_t *cli, int n, int timeout_ms, rmsg_t *msgs) {
    int i;
    uint64_t deadline;
    mqtt_packet_t pkt;

    i = 0;
    deadline = ms_now() + (uint64_t)timeout_ms;
    while (i < n) {
        int rc;
        uint64_t left;

        left = deadline > ms_now() ? deadline - ms_now() : 0;
        if (left == 0) {
            break;
        }
        rc = cli_next_publish(cli, &pkt, (int)left);
        if (rc != 0) {
            break;
        }
        rmsg_fill(cli, &msgs[i], &pkt);
        mqtt_packet_cleanup(&pkt);
        i++;
    }
    return i;
}

/* wait until the connection is closed; returns 0 when closed, -1 on timeout */
static int
cli_wait_closed(cli_t *cli, int timeout_ms) {
    uint64_t deadline;

    deadline = ms_now() + (uint64_t)timeout_ms;
    while (ms_now() < deadline) {
        ssize_t r = network_tcp_recv(cli->net, cli->rx + cli->rx_n, cli->rx_cap - cli->rx_n);
        if (r < 0) {
            return 0;
        }
        if (r > 0) {
            cli->rx_n += (size_t)r;
        }
    }
    return -1;
}

/* ================================================================== */
/* tests: connection and handshake                                     */
/* ================================================================== */

static void
test_tcp_reachability(void) {
    void *net;

    test_begin("tcp reachability");
    net = network_tcp_connect(g_host, g_port);
    CHECK(net != 0, "TCP connect to %s:%d", g_host, g_port);
    if (net) {
        network_tcp_close(net);
    }
    test_end();
}

static void
test_v4_connect_clean(void) {
    cli_t cli;
    mqtt_packet_t ca;
    char cid[64];

    test_begin("v3.1.1 connect (clean session)");
    CHECK(cli_open(&cli, MQTT_VERSION_4) == 0, "tcp connect");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack (if the broker requires auth, pass -u/-w)");
    CHECK_EQ_INT(ca.v.connack.v4.return_code, MQTT_CRC_ACCEPTED, "v4 return code");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_v5_connect_caps(void) {
    cli_t cli;
    mqtt_packet_t ca;
    mqtt_properties_t *p;
    char cid[64];

    test_begin("v5 connect + CONNACK capabilities");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "tcp connect");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack (if the broker requires auth, pass -u/-w)");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "v5 reason code");
    p = &ca.v.connack.v5.properties;
    CHECK(prop_b2(p, MQTT_PROPERTY_RECEIVE_MAXIMUM) > 0, "receive maximum advertised");
    {
        /* optional per spec; 0xFFFFFFFF means "no limit" */
        mqtt_property_t *mps = mqtt_properties_find(p, MQTT_PROPERTY_MAXIMUM_PACKET_SIZE);

        CHECK(!mps || mps->bv > 0, "maximum packet size (if advertised) is non-zero");
        g_cap_max_packet = mps ? mps->bv : 0;
    }
    CHECK_EQ_INT(prop_b1(p, MQTT_PROPERTY_RETAIN_AVAILABLE), 1, "retain available");
    CHECK_EQ_INT(prop_b1(p, MQTT_PROPERTY_WILDCARD_SUBSCRIPTION_AVAILABLE), 1, "wildcard available");
    g_cap_shared = prop_b1(p, MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE);
    g_cap_subid = prop_b1(p, MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIERS_AVAILABLE);
    g_cap_retain = prop_b1(p, MQTT_PROPERTY_RETAIN_AVAILABLE);
    g_cap_wildcard = prop_b1(p, MQTT_PROPERTY_WILDCARD_SUBSCRIPTION_AVAILABLE);
    g_cap_alias_max = (uint16_t)prop_b2(p, MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM);
    fprintf(stderr, "  caps: alias_max=%" PRIu16 " max_packet=%" PRIu32 " shared=%d subid=%d\n", g_cap_alias_max,
            g_cap_max_packet, g_cap_shared, g_cap_subid);
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_v4_persistent_session(void) {
    cli_t a, b;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    char cid[64], topic[128];

    test_begin("v3.1.1 persistent session: subscriptions survive reconnect");
    snprintf(topic, sizeof(topic), "%s/sess4", g_topic);
    f[0] = topic;
    CHECK(cli_open(&a, MQTT_VERSION_4) == 0, "a open");
    CHECK(cli_connect(&a, next_client_id(cid, sizeof(cid)), 0, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "a connack");
    CHECK_EQ_INT(ca.v.connack.v4.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 0, "a: no previous session");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&a, 1, f, &o, 0, 0) == 0, "a subscribe sent");
    CHECK(cli_wait(&a, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "a suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_disconnect(&a) == 0, "a clean disconnect");
    cli_wait_closed(&a, g_timeout_ms);
    cli_close(&a);

    CHECK(cli_open(&b, MQTT_VERSION_4) == 0, "b open");
    CHECK(cli_connect(&b, cid, 0, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v4.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "b: session present");
    mqtt_packet_cleanup(&ca);
    /* the subscription survived: publishing to the topic reaches this client */
    CHECK(cli_publish(&b, topic, MQTT_QOS_1, 0, "resumed", 0) == 0, "b publish");
    CHECK(cli_wait(&b, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "b puback");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_wait(&b, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "b receives its own message");
    CHECK(payload_eq(&pk, "resumed"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&b);
    test_end();
}

static void
test_v5_session_expiry_resume(void) {
    cli_t a, b;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    char cid[64], topic[128];

    test_begin("v5 session expiry: session resumes after DISCONNECT");
    snprintf(topic, sizeof(topic), "%s/sess5", g_topic);
    f[0] = topic;
    CHECK(cli_open(&a, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, next_client_id(cid, sizeof(cid)), 0, 60, 300, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "a connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "a reason");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&a, 1, f, &o, 0, 0) == 0, "a subscribe sent");
    CHECK(cli_wait(&a, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "a suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_disconnect5(&a, MQTT_RC_NORMAL_DISCONNECTION) == 0, "a v5 disconnect");
    cli_wait_closed(&a, g_timeout_ms);
    cli_close(&a);

    CHECK(cli_open(&b, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, cid, 0, 60, 300, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "b: session present");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&b, topic, MQTT_QOS_1, 0, "resumed5", 0) == 0, "b publish");
    CHECK(cli_wait(&b, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "b puback");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_wait(&b, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "b receives its own message");
    CHECK(payload_eq(&pk, "resumed5"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&b);
    test_end();
}

static void
test_v4_empty_id(void) {
    cli_t cli;
    mqtt_packet_t ca;

    test_begin("v3.1.1 empty client id: clean ok, persistent rejected");
    /* clean session + empty id: allowed, server may assign an id */
    CHECK(cli_open(&cli, MQTT_VERSION_4) == 0, "open (clean)");
    CHECK(cli_connect(&cli, "", 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack (clean)");
    CHECK_EQ_INT(ca.v.connack.v4.return_code, MQTT_CRC_ACCEPTED, "clean: accepted");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);

    /* persistent session + empty id: must be rejected */
    CHECK(cli_open(&cli, MQTT_VERSION_4) == 0, "open (persistent)");
    CHECK(cli_connect(&cli, "", 0, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack (persistent)");
    CHECK_EQ_INT(ca.v.connack.v4.return_code, MQTT_CRC_REFUSED_IDENTIFIER_REJECTED, "persistent: 0x02");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_v5_client_id_too_long(void) {
    cli_t cli;
    mqtt_packet_t ca;
    char long_id[32];

    test_begin("v5 client id longer than 23 chars is rejected");
    memset(long_id, 'a', sizeof(long_id) - 1);
    long_id[sizeof(long_id) - 1] = '\0';
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, long_id, 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_CLIENT_IDENTIFIER_NOT_VALID, "reason 0x85");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_v5_assigned_client_id(void) {
    cli_t cli;
    mqtt_packet_t ca;

    test_begin("v5 empty client id: server assigns one");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "", 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "reason");
    CHECK(prop_str_nonempty(&ca.v.connack.v5.properties, MQTT_PROPERTY_ASSIGNED_CLIENT_IDENTIFIER),
          "ASSIGNED_CLIENT_IDENTIFIER property present");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_bad_protocol_name(void) {
    cli_t cli;
    /* CONNECT with protocol name "FOO" (level 4): malformed, server must close */
    static const unsigned char pkt[] = {
        0x10, 0x0C, 0x00, 0x03, 'F', 'O', 'O', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x01, 'x'};

    test_begin("CONNECT with bad protocol name closes the connection");
    CHECK(cli_open(&cli, MQTT_VERSION_4) == 0, "open");
    CHECK(cli_send_raw(&cli, (const char *)pkt, sizeof(pkt)) == 0, "raw connect sent");
    CHECK(cli_wait_closed(&cli, 5000) == 0, "broker closed the connection");
    cli_close(&cli);
    test_end();
}

static void
test_unsupported_protocol_level(void) {
    cli_t cli;
    mqtt_packet_t ca;
    /* CONNECT with protocol level 6 (unsupported) */
    static const unsigned char pkt[] = {
        0x10, 0x0D, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x06, 0x02, 0x00, 0x3C, 0x00, 0x01, 'x'};
    int rc;

    test_begin("CONNECT with unsupported protocol level");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_send_raw(&cli, (const char *)pkt, sizeof(pkt)) == 0, "raw connect sent");
    rc = cli_wait(&cli, MQTT_CONNACK, 5000, &ca);
    if (rc == 0) {
        /* spec: CONNACK 0x84 (unsupported protocol version) before closing */
        CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION, "reason 0x84");
        mqtt_packet_cleanup(&ca);
        fprintf(stderr, "  (broker answered CONNACK 0x84)\n");
    } else {
        /* spec also allows closing without CONNACK */
        CHECK(rc == -2, "broker closed the connection (rc=%d)", rc);
        fprintf(stderr, "  (broker closed without CONNACK)\n");
    }
    cli_close(&cli);
    test_end();
}

/* ================================================================== */
/* tests: publish / subscribe                                          */
/* ================================================================== */

static void
test_qos0_roundtrip(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    char cid1[64], cid2[64], topic[128];

    test_begin("qos0 publish/subscribe round trip");
    snprintf(topic, sizeof(topic), "%s/q0", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_0, 0, "hello-q0", 0) == 0, "pub publish sent");

    CHECK(cli_wait(&sub, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "sub received");
    CHECK(payload_eq(&pk, "hello-q0"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_qos1_roundtrip(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    char cid1[64], cid2[64], topic[128];

    test_begin("qos1 publish/subscribe round trip");
    snprintf(topic, sizeof(topic), "%s/q1", g_topic);
    f[0] = topic;
    o = MQTT_QOS_1;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 0, "hello-q1", &pid) == 0, "pub publish sent");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    CHECK_EQ_INT(pk.v.puback.packet_id, pid, "puback id");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_wait(&sub, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "sub received");
    CHECK_EQ_INT(MQTT_FH_QOS(pk.f.flags), MQTT_QOS_1, "delivery qos");
    CHECK(payload_eq(&pk, "hello-q1"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_qos2_roundtrip(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    char cid1[64], cid2[64], topic[128];

    test_begin("qos2 publish/subscribe round trip (PUBREC/PUBREL/PUBCOMP)");
    snprintf(topic, sizeof(topic), "%s/q2", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    o = MQTT_QOS_2;
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_2, 0, "hello-q2", &pid) == 0, "pub publish sent");
    CHECK(cli_wait(&pub, MQTT_PUBREC, g_timeout_ms, &pk) == 0, "pub pubrec");
    CHECK_EQ_INT(pk.v.pubrec.packet_id, pid, "pubrec id");
    mqtt_packet_cleanup(&pk);
    /* auto-ack already sent PUBREL; expect PUBCOMP */
    CHECK(cli_wait(&pub, MQTT_PUBCOMP, g_timeout_ms, &pk) == 0, "pub pubcomp");
    CHECK_EQ_INT(pk.v.pubcomp.packet_id, pid, "pubcomp id");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_wait(&sub, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "sub received");
    CHECK_EQ_INT(MQTT_FH_QOS(pk.f.flags), MQTT_QOS_2, "delivery qos");
    CHECK(payload_eq(&pk, "hello-q2"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_multi_filter_subscribe(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa;
    const char *f[3];
    uint8_t o[3] = {0, 0, 0};
    rmsg_t msgs[3];
    char cid1[64], cid2[64], t0[128], t1[128], t2[128];

    test_begin("single SUBSCRIBE with three topic filters");
    snprintf(t0, sizeof(t0), "%s/mf/a", g_topic);
    snprintf(t1, sizeof(t1), "%s/mf/b", g_topic);
    snprintf(t2, sizeof(t2), "%s/mf/c", g_topic);
    f[0] = t0;
    f[1] = t1;
    f[2] = t2;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 3, f, o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    CHECK_EQ_INT(sa.p.suback.n, 3, "suback count");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_GRANTED_QOS_0, "granted[0]");
    CHECK_EQ_INT(suback_rc5(&sa, 1), MQTT_RC_GRANTED_QOS_0, "granted[1]");
    CHECK_EQ_INT(suback_rc5(&sa, 2), MQTT_RC_GRANTED_QOS_0, "granted[2]");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, t0, MQTT_QOS_0, 0, "ma", 0) == 0, "pub a");
    CHECK(cli_publish(&pub, t1, MQTT_QOS_0, 0, "mb", 0) == 0, "pub b");
    CHECK(cli_publish(&pub, t2, MQTT_QOS_0, 0, "mc", 0) == 0, "pub c");

    CHECK_EQ_INT(cli_collect(&sub, 3, g_timeout_ms, msgs), 3, "collected 3");
    CHECK(strcmp(msgs[0].topic, t0) == 0 && payload_eq_str(&msgs[0], "ma"), "msg a");
    CHECK(strcmp(msgs[1].topic, t1) == 0 && payload_eq_str(&msgs[1], "mb"), "msg b");
    CHECK(strcmp(msgs[2].topic, t2) == 0 && payload_eq_str(&msgs[2], "mc"), "msg c");
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_wildcard_plus(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    rmsg_t msgs[2];
    char cid1[64], cid2[64], filter[128], ta[128], tb[128], ty[128];

    test_begin("single-level wildcard +");
    snprintf(filter, sizeof(filter), "%s/wc/+/x", g_topic);
    snprintf(ta, sizeof(ta), "%s/wc/a/x", g_topic);
    snprintf(tb, sizeof(tb), "%s/wc/b/x", g_topic);
    snprintf(ty, sizeof(ty), "%s/wc/a/y", g_topic);
    f[0] = filter;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, ta, MQTT_QOS_0, 0, "wa", 0) == 0, "pub ta");
    CHECK(cli_publish(&pub, tb, MQTT_QOS_0, 0, "wb", 0) == 0, "pub tb");
    CHECK(cli_publish(&pub, ty, MQTT_QOS_0, 0, "nope", 0) == 0, "pub ty (must not match)");

    CHECK_EQ_INT(cli_collect(&sub, 2, g_timeout_ms, msgs), 2, "collected 2");
    CHECK(strcmp(msgs[0].topic, ta) == 0 && payload_eq_str(&msgs[0], "wa"), "msg ta");
    CHECK(strcmp(msgs[1].topic, tb) == 0 && payload_eq_str(&msgs[1], "wb"), "msg tb");
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 2000, &pk) == -1, "no delivery for non-matching topic");
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_wildcard_hash(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa;
    const char *f[1];
    uint8_t o = 0;
    rmsg_t msg;
    char cid1[64], cid2[64], filter[128], t[128];

    test_begin("multi-level wildcard #");
    snprintf(filter, sizeof(filter), "%s/hash/#", g_topic);
    snprintf(t, sizeof(t), "%s/hash/a/b/c", g_topic);
    f[0] = filter;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, t, MQTT_QOS_0, 0, "deep", 0) == 0, "pub deep topic");

    CHECK_EQ_INT(cli_collect(&sub, 1, g_timeout_ms, &msg), 1, "collected 1");
    CHECK(strcmp(msg.topic, t) == 0, "topic");
    CHECK(payload_eq_str(&msg, "deep"), "payload");
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_unsubscribe_stops_delivery(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, ua, pk;
    const char *f[1];
    uint8_t o = 0;
    rmsg_t msg;
    char cid1[64], cid2[64], topic[128];

    test_begin("UNSUBSCRIBE stops further delivery");
    snprintf(topic, sizeof(topic), "%s/unsub", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_0, 0, "before", 0) == 0, "pub before");
    CHECK_EQ_INT(cli_collect(&sub, 1, g_timeout_ms, &msg), 1, "received before");
    CHECK(payload_eq_str(&msg, "before"), "payload before");

    CHECK(cli_unsubscribe(&sub, 1, f, 0) == 0, "sub unsubscribe sent");
    CHECK(cli_wait(&sub, MQTT_UNSUBACK, g_timeout_ms, &ua) == 0, "sub unsuback");
    mqtt_packet_cleanup(&ua);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_0, 0, "after", 0) == 0, "pub after");
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 2000, &pk) == -1, "no delivery after unsubscribe");
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_qos_downgrade_delivery(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    char cid1[64], cid2[64], topic[128];

    test_begin("qos2 publish to a qos0 subscription is delivered at qos0");
    snprintf(topic, sizeof(topic), "%s/down", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe qos0");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_GRANTED_QOS_0, "granted qos0");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_2, 0, "downgraded", &pid) == 0, "pub qos2");
    CHECK(cli_wait(&pub, MQTT_PUBREC, g_timeout_ms, &pk) == 0, "pub pubrec");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_wait(&pub, MQTT_PUBCOMP, g_timeout_ms, &pk) == 0, "pub pubcomp");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_wait(&sub, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "sub received");
    CHECK_EQ_INT(MQTT_FH_QOS(pk.f.flags), MQTT_QOS_0, "delivered at qos0");
    CHECK(payload_eq(&pk, "downgraded"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_empty_payload(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    char cid1[64], cid2[64], topic[128];

    test_begin("empty payload round trip");
    snprintf(topic, sizeof(topic), "%s/empty", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 0, "", &pid) == 0, "pub empty");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_wait(&sub, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "sub received");
    CHECK_EQ_INT((int)pk.p.publish.message.n, 0, "empty message");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_large_payload(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    char cid1[64], cid2[64], topic[128];
    static char payload[256 * 1024];
    size_t size = 200 * 1024;
    size_t i;

    test_begin("large payload round trip");
    if (g_cap_max_packet > 0 && size + 512 > g_cap_max_packet) {
        size = g_cap_max_packet - 512;
    }
    if (size < 16 * 1024) {
        test_skip("broker maximum packet size too small");
        test_end();
        return;
    }
    for (i = 0; i < size; i++) {
        payload[i] = (char)(i % 251);
    }
    fprintf(stderr, "  payload size: %zu bytes\n", size);
    snprintf(topic, sizeof(topic), "%s/large", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    {
        mqtt_packet_t p;
        mqtt_str_t msg;

        mqtt_packet_init(&p, MQTT_VERSION_5, MQTT_PUBLISH);
        p.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_1, 0);
        p.v.publish.packet_id = cli_next_id(&pub);
        pid = p.v.publish.packet_id;
        mqtt_str_from(&p.v.publish.topic_name, topic);
        mqtt_str_init(&msg, payload, size);
        mqtt_str_set(&p.p.publish.message, &msg);
        CHECK(cli_send_pkt(&pub, &p) == 0, "pub large publish sent");
    }
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    CHECK_EQ_INT(pk.v.puback.packet_id, pid, "puback id");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_wait(&sub, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "sub received");
    CHECK_EQ_INT((int)pk.p.publish.message.n, (int)size, "message size");
    CHECK(memcmp(pk.p.publish.message.s, payload, size) == 0, "payload content");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_two_clients_fanout(void) {
    cli_t a, b, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    char cid1[64], cid2[64], cid3[64], topic[128];

    test_begin("one qos1 publish is delivered to two subscribers");
    snprintf(topic, sizeof(topic), "%s/fanout", g_topic);
    f[0] = topic;
    CHECK(cli_open(&a, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "a connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&a, 1, f, &o, 0, 0) == 0, "a subscribe sent");
    CHECK(cli_wait(&a, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "a suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&b, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "b connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&b, 1, f, &o, 0, 0) == 0, "b subscribe sent");
    CHECK(cli_wait(&b, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "b suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid3, sizeof(cid3)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 0, "fanout", &pid) == 0, "pub publish sent");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_wait(&a, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "a received");
    CHECK(payload_eq(&pk, "fanout"), "a payload");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_wait(&b, MQTT_PUBLISH, g_timeout_ms, &pk) == 0, "b received");
    CHECK(payload_eq(&pk, "fanout"), "b payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&a);
    cli_close(&b);
    cli_close(&pub);
    test_end();
}

static void
test_burst_qos0_order(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa;
    const char *f[1];
    uint8_t o = 0;
    rmsg_t msgs[100];
    char cid1[64], cid2[64], topic[128];
    char payload[16];
    int i;

    test_begin("burst of 100 qos0 messages arrives in order");
    snprintf(topic, sizeof(topic), "%s/burst", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    for (i = 0; i < 100; i++) {
        snprintf(payload, sizeof(payload), "m%03d", i);
        CHECK(cli_publish(&pub, topic, MQTT_QOS_0, 0, payload, 0) == 0, "pub %d", i);
    }

    CHECK_EQ_INT(cli_collect(&sub, 100, 2 * g_timeout_ms, msgs), 100, "collected 100");
    for (i = 0; i < 100; i++) {
        snprintf(payload, sizeof(payload), "m%03d", i);
        if (!payload_eq_str(&msgs[i], payload)) {
            CHECK(0, "message %d out of order: got %s want %s", i, msgs[i].payload, payload);
            break;
        }
    }
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

/* ================================================================== */
/* tests: retained messages                                            */
/* ================================================================== */

static void
test_retained_set_get_clear(void) {
    cli_t pub, s1, s2;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    rmsg_t msg;
    char cid1[64], cid2[64], cid3[64], topic[128];

    test_begin("retained message: set, delivered to new subscriber, cleared");
    snprintf(topic, sizeof(topic), "%s/retain", g_topic);
    f[0] = topic;
    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 1, "retained-hello", &pid) == 0, "pub retained");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_open(&s1, MQTT_VERSION_5) == 0, "s1 open");
    CHECK(cli_connect(&s1, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "s1 connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&s1, 1, f, &o, 0, 0) == 0, "s1 subscribe sent");
    CHECK(cli_wait(&s1, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "s1 suback");
    mqtt_packet_cleanup(&sa);
    CHECK_EQ_INT(cli_collect(&s1, 1, g_timeout_ms, &msg), 1, "s1 got retained");
    CHECK(payload_eq_str(&msg, "retained-hello"), "s1 payload");

    /* clear the retained message with an empty retained publish */
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 1, "", &pid) == 0, "pub clear");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_open(&s2, MQTT_VERSION_5) == 0, "s2 open");
    CHECK(cli_connect(&s2, next_client_id(cid3, sizeof(cid3)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "s2 connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&s2, 1, f, &o, 0, 0) == 0, "s2 subscribe sent");
    CHECK(cli_wait(&s2, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "s2 suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_wait(&s2, MQTT_PUBLISH, 2000, &pk) == -1, "s2 got nothing after clear");
    cli_close(&pub);
    cli_close(&s1);
    cli_close(&s2);
    test_end();
}

static void
test_retained_flag_on_delivery(void) {
    cli_t pub, sub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    char cid1[64], cid2[64], topic[128];

    test_begin("retained delivery carries the retain flag");
    snprintf(topic, sizeof(topic), "%s/retainflag", g_topic);
    f[0] = topic;
    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 1, "flag", &pid) == 0, "pub retained");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_next_publish(&sub, &pk, g_timeout_ms) == 0, "sub received");
    CHECK_EQ_INT(MQTT_FH_RETAIN(pk.f.flags), 1, "retain flag set");
    CHECK(payload_eq(&pk, "flag"), "payload");
    mqtt_packet_cleanup(&pk);
    /* clean up: clear the retained message */
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 1, "", &pid) == 0, "pub clear");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);
    cli_close(&pub);
    cli_close(&sub);
    test_end();
}

static void
test_v5_retain_handling(void) {
    cli_t pub, s1, s2, s3, s4;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o;
    uint16_t pid;
    rmsg_t msg;
    char cid1[64], cid2[64], cid3[64], cid4[64], cid5[64], topic[128];

    test_begin("v5 retain handling options (RH=1 keep, RH=2 delete)");
    if (!g_cap_retain) {
        test_skip("broker does not advertise retain support");
        test_end();
        return;
    }
    snprintf(topic, sizeof(topic), "%s/rh", g_topic);
    f[0] = topic;
    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 1, "kept", &pid) == 0, "pub retained");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);

    /* RH=1: do not send the retained message, but keep it stored */
    o = MQTT_SUBOPT_RH_MASK & (1 << 4);
    CHECK(cli_open(&s1, MQTT_VERSION_5) == 0, "s1 open");
    CHECK(cli_connect(&s1, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "s1 connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&s1, 1, f, &o, 0, 0) == 0, "s1 subscribe RH=1");
    CHECK(cli_wait(&s1, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "s1 suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_wait(&s1, MQTT_PUBLISH, 2000, &pk) == -1, "s1: no retained delivery (RH=1)");

    /* normal subscribe: the retained message is still there */
    o = 0;
    CHECK(cli_open(&s2, MQTT_VERSION_5) == 0, "s2 open");
    CHECK(cli_connect(&s2, next_client_id(cid3, sizeof(cid3)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "s2 connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&s2, 1, f, &o, 0, 0) == 0, "s2 subscribe normal");
    CHECK(cli_wait(&s2, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "s2 suback");
    mqtt_packet_cleanup(&sa);
    CHECK_EQ_INT(cli_collect(&s2, 1, g_timeout_ms, &msg), 1, "s2 got retained");
    CHECK(payload_eq_str(&msg, "kept"), "s2 payload");

    /* RH=2: do not send, and delete the stored message */
    o = MQTT_SUBOPT_RH_MASK & (2 << 4);
    CHECK(cli_open(&s3, MQTT_VERSION_5) == 0, "s3 open");
    CHECK(cli_connect(&s3, next_client_id(cid4, sizeof(cid4)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "s3 connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&s3, 1, f, &o, 0, 0) == 0, "s3 subscribe RH=2");
    CHECK(cli_wait(&s3, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "s3 suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_wait(&s3, MQTT_PUBLISH, 2000, &pk) == -1, "s3: no retained delivery (RH=2)");

    /* normal subscribe: nothing stored anymore */
    o = 0;
    CHECK(cli_open(&s4, MQTT_VERSION_5) == 0, "s4 open");
    CHECK(cli_connect(&s4, next_client_id(cid5, sizeof(cid5)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "s4 connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&s4, 1, f, &o, 0, 0) == 0, "s4 subscribe normal");
    CHECK(cli_wait(&s4, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "s4 suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_wait(&s4, MQTT_PUBLISH, 2000, &pk) == -1, "s4: retained message was deleted");
    cli_close(&pub);
    cli_close(&s1);
    cli_close(&s2);
    cli_close(&s3);
    cli_close(&s4);
    test_end();
}

/* ================================================================== */
/* tests: keepalive                                                    */
/* ================================================================== */

static void
test_pingreq_pingresp(void) {
    cli_t cli;
    mqtt_packet_t ca, pr;
    char cid[64];

    test_begin("PINGREQ -> PINGRESP");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_ping(&cli) == 0, "pingreq sent");
    CHECK(cli_wait(&cli, MQTT_PINGRESP, g_timeout_ms, &pr) == 0, "pingresp");
    mqtt_packet_cleanup(&pr);
    cli_close(&cli);
    test_end();
}

static void
test_keepalive_timeout(void) {
    cli_t cli;
    mqtt_packet_t ca, pk;
    char cid[64];

    test_begin("keep alive timeout drops the connection");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 2, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack keepalive=2");
    mqtt_packet_cleanup(&ca);
    /* no PINGREQ: the server must drop us after 1.5x keep alive */
    CHECK(cli_wait(&cli, MQTT_PINGRESP, 15000, &pk) == -2, "connection closed by the broker");
    cli_close(&cli);
    test_end();
}

/* ================================================================== */
/* tests: wills                                                        */
/* ================================================================== */

static void
test_will_delivery(void) {
    cli_t sub, willer;
    mqtt_packet_t ca, sa;
    const char *f[1];
    uint8_t o = 0;
    rmsg_t msg;
    char cid1[64], cid2[64], topic[128];

    test_begin("will message is published on abrupt disconnect");
    snprintf(topic, sizeof(topic), "%s/will", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&willer, MQTT_VERSION_4) == 0, "willer open");
    CHECK(cli_connect(&willer, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, topic, "willmsg", MQTT_QOS_1, 0,
                      &ca) == 0, "willer connack");
    mqtt_packet_cleanup(&ca);
    /* abrupt close: no DISCONNECT packet */
    cli_close(&willer);

    CHECK_EQ_INT(cli_collect(&sub, 1, 15000, &msg), 1, "sub received the will");
    CHECK(payload_eq_str(&msg, "willmsg"), "will payload");
    cli_close(&sub);
    test_end();
}

static void
test_will_cancelled(void) {
    cli_t sub, willer;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    char cid1[64], cid2[64], topic[128];

    test_begin("clean DISCONNECT cancels the will message");
    snprintf(topic, sizeof(topic), "%s/willcancel", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&willer, MQTT_VERSION_4) == 0, "willer open");
    CHECK(cli_connect(&willer, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, topic, "willmsg2", MQTT_QOS_1, 0,
                      &ca) == 0, "willer connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_disconnect(&willer) == 0, "willer clean disconnect");
    cli_wait_closed(&willer, g_timeout_ms);
    cli_close(&willer);

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == -1, "no will delivered");
    cli_close(&sub);
    test_end();
}

static void
test_v5_will_delay(void) {
    cli_t sub, willer;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    rmsg_t msg;
    char cid1[64], cid2[64], topic[128];

    test_begin("v5 will delay: will arrives only after the delay");
    snprintf(topic, sizeof(topic), "%s/willdelay", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    /* will delay only applies to persistent sessions */
    CHECK(cli_open(&willer, MQTT_VERSION_5) == 0, "willer open");
    CHECK(cli_connect(&willer, next_client_id(cid2, sizeof(cid2)), 0, 60, 300, 0, 0, topic, "delayed-will",
                      MQTT_QOS_1, 3, &ca) == 0, "willer connack (persistent, will delay 3s)");
    mqtt_packet_cleanup(&ca);
    cli_close(&willer); /* abrupt close starts the delay timer */

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 1500, &pk) == -1, "no will before the delay elapses");
    CHECK_EQ_INT(cli_collect(&sub, 1, 20000, &msg), 1, "will arrived after the delay");
    CHECK(payload_eq_str(&msg, "delayed-will"), "will payload");
    cli_close(&sub);
    test_end();
}

/* ================================================================== */
/* tests: mqtt 5 features                                              */
/* ================================================================== */

static void
test_v5_props_passthrough(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    rmsg_t msg;
    char cid1[64], cid2[64], topic[128];

    test_begin("v5 publish properties pass through to the subscriber");
    snprintf(topic, sizeof(topic), "%s/props", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish5_props(&pub, topic, MQTT_QOS_1, "with-props", &pid) == 0, "pub publish sent");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);

    CHECK_EQ_INT(cli_collect(&sub, 1, g_timeout_ms, &msg), 1, "sub received");
    CHECK(payload_eq_str(&msg, "with-props"), "payload");
    CHECK(msg.user_kv1, "user property k1=v1");
    CHECK(msg.user_kv2, "user property k2=v2");
    CHECK(msg.ct, "content type");
    CHECK(msg.rt, "response topic");
    CHECK(msg.corr, "correlation data");
    CHECK_EQ_INT(msg.meqi, 120, "message expiry interval");
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_topic_alias_in(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    rmsg_t msgs[2];
    char cid1[64], cid2[64], topic[128];

    test_begin("v5 topic alias: bind then publish with alias only");
    if (g_cap_alias_max == 0) {
        test_skip("broker does not accept topic aliases");
        test_end();
        return;
    }
    snprintf(topic, sizeof(topic), "%s/aliasin", g_topic);
    f[0] = topic;
    CHECK(cli_open(&sub, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, &o, 0, 0) == 0, "sub subscribe sent");
    CHECK(cli_wait(&sub, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "sub suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    /* bind alias 1 -> topic */
    CHECK(cli_publish_alias(&pub, topic, 1, "bind", &pid) == 0, "pub bind publish sent");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);
    /* publish with the alias only (empty topic name) */
    CHECK(cli_publish_alias(&pub, 0, 1, "aliased", &pid) == 0, "pub alias publish sent");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback");
    mqtt_packet_cleanup(&pk);

    CHECK_EQ_INT(cli_collect(&sub, 2, g_timeout_ms, msgs), 2, "sub received 2");
    CHECK(strcmp(msgs[0].topic, topic) == 0, "msg1 topic");
    CHECK(payload_eq_str(&msgs[0], "bind"), "msg1 payload");
    CHECK(strcmp(msgs[1].topic, topic) == 0, "msg2 topic (alias resolved)");
    CHECK(payload_eq_str(&msgs[1], "aliased"), "msg2 payload");
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_topic_alias_out(void) {
    cli_t cli;
    mqtt_packet_t ca, sa;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    rmsg_t msgs[3];
    char cid[64], topic[128];

    test_begin("v5 topic alias: broker sends alias-only publishes");
    snprintf(topic, sizeof(topic), "%s/aliasout", g_topic);
    f[0] = topic;
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    /* advertise that we accept topic aliases from the server */
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 10, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&cli, 1, f, &o, 0, 0) == 0, "subscribe sent");
    CHECK(cli_wait(&cli, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_publish(&cli, topic, MQTT_QOS_0, 0, "o1", &pid) == 0, "pub 1");
    CHECK(cli_publish(&cli, topic, MQTT_QOS_0, 0, "o2", &pid) == 0, "pub 2");
    CHECK(cli_publish(&cli, topic, MQTT_QOS_0, 0, "o3", &pid) == 0, "pub 3");

    CHECK_EQ_INT(cli_collect(&cli, 3, g_timeout_ms, msgs), 3, "received 3");
    CHECK(strcmp(msgs[0].topic, topic) == 0, "msg1 full topic");
    CHECK(msgs[0].alias != 0, "msg1 binds an alias");
    CHECK((msgs[1].alias != 0) || (msgs[2].alias != 0), "a later message uses the alias");
    cli_close(&cli);
    test_end();
}

static void
test_v5_bad_topic_alias(void) {
    cli_t cli;
    mqtt_packet_t ca, pk;
    uint16_t pid;
    char cid[64], topic[128];

    test_begin("v5 topic alias above the server maximum is rejected");
    if (g_cap_alias_max == 0) {
        test_skip("broker does not accept topic aliases");
        test_end();
        return;
    }
    snprintf(topic, sizeof(topic), "%s/aliasbad", g_topic);
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    /* alias above the advertised maximum: expect PUBACK 0x94 (qos>0) */
    CHECK(cli_publish_alias(&cli, topic, (uint16_t)(g_cap_alias_max + 1), "bad", &pid) == 0, "pub sent");
    CHECK(cli_wait(&cli, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "puback");
    CHECK_EQ_INT(pk.v.puback.v5.reason_code, MQTT_RC_TOPIC_ALIAS_INVALID, "puback 0x94");
    mqtt_packet_cleanup(&pk);
    cli_close(&cli);
    test_end();
}

static void
test_v5_subscription_identifier(void) {
    cli_t cli;
    mqtt_packet_t ca, sa;
    const char *f[1];
    uint8_t o = 0;
    uint16_t pid;
    rmsg_t msg;
    char cid[64], topic[128];

    test_begin("v5 subscription identifier is echoed on delivery");
    if (!g_cap_subid) {
        test_skip("broker does not advertise subscription identifiers");
        test_end();
        return;
    }
    snprintf(topic, sizeof(topic), "%s/subid", g_topic);
    f[0] = topic;
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&cli, 1, f, &o, 7, 0) == 0, "subscribe sent (sub id 7)");
    CHECK(cli_wait(&cli, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_publish(&cli, topic, MQTT_QOS_0, 0, "subid-msg", &pid) == 0, "pub");
    CHECK_EQ_INT(cli_collect(&cli, 1, g_timeout_ms, &msg), 1, "received");
    CHECK_EQ_INT((int)msg.sub_id, 7, "subscription identifier");
    cli_close(&cli);
    test_end();
}

static void
test_v5_shared_subscription(void) {
    cli_t a, b, pub;
    mqtt_packet_t ca, sa, pk;
    const char *fa[1];
    uint8_t o = 0;
    uint16_t pid;
    rmsg_t ma[2], mb[2];
    int na, nb;
    char cid1[64], cid2[64], cid3[64], share[160], topic[128];

    test_begin("v5 shared subscription: each message goes to one group member");
    if (!g_cap_shared) {
        test_skip("broker does not advertise shared subscriptions");
        test_end();
        return;
    }
    snprintf(topic, sizeof(topic), "%s/shared", g_topic);
    snprintf(share, sizeof(share), "$share/kmqrt/%s", topic);
    fa[0] = share;
    CHECK(cli_open(&a, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, next_client_id(cid1, sizeof(cid1)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "a connack");
    mqtt_packet_cleanup(&ca);
    o = MQTT_QOS_1;
    CHECK(cli_subscribe(&a, 1, fa, &o, 0, 0) == 0, "a shared subscribe");
    CHECK(cli_wait(&a, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "a suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_GRANTED_QOS_1, "a granted qos1");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&b, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, next_client_id(cid2, sizeof(cid2)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "b connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&b, 1, fa, &o, 0, 0) == 0, "b shared subscribe");
    CHECK(cli_wait(&b, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "b suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, next_client_id(cid3, sizeof(cid3)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 0, "s1", &pid) == 0, "pub 1");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback 1");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_publish(&pub, topic, MQTT_QOS_1, 0, "s2", &pid) == 0, "pub 2");
    CHECK(cli_wait(&pub, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "pub puback 2");
    mqtt_packet_cleanup(&pk);

    na = cli_collect(&a, 2, g_timeout_ms, ma);
    nb = cli_collect(&b, 2, g_timeout_ms, mb);
    fprintf(stderr, "  a got %d, b got %d\n", na, nb);
    CHECK_EQ_INT(na + nb, 2, "both messages delivered exactly once");
    CHECK(na <= 1 && nb <= 1, "load balanced across the group");
    cli_close(&a);
    cli_close(&b);
    cli_close(&pub);
    test_end();
}

static void
test_v5_suback_granted_qos(void) {
    cli_t cli;
    mqtt_packet_t ca, sa;
    const char *f[3];
    uint8_t o[3] = {MQTT_QOS_2, MQTT_QOS_1, MQTT_QOS_0};
    char cid[64], t0[128], t1[128], t2[128];

    test_begin("v5 SUBACK grants the requested qos per filter");
    snprintf(t0, sizeof(t0), "%s/grant/a", g_topic);
    snprintf(t1, sizeof(t1), "%s/grant/b", g_topic);
    snprintf(t2, sizeof(t2), "%s/grant/c", g_topic);
    f[0] = t0;
    f[1] = t1;
    f[2] = t2;
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&cli, 3, f, o, 0, 0) == 0, "subscribe sent");
    CHECK(cli_wait(&cli, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "suback");
    CHECK_EQ_INT(sa.p.suback.n, 3, "suback count");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_GRANTED_QOS_2, "granted qos2");
    CHECK_EQ_INT(suback_rc5(&sa, 1), MQTT_RC_GRANTED_QOS_1, "granted qos1");
    CHECK_EQ_INT(suback_rc5(&sa, 2), MQTT_RC_GRANTED_QOS_0, "granted qos0");
    mqtt_packet_cleanup(&sa);
    cli_close(&cli);
    test_end();
}

static void
test_v5_invalid_topic_filter(void) {
    cli_t cli;
    mqtt_packet_t ca, sa;
    char cid[64];
    /* SUBSCRIBE with filter "a/#/b" ('#' must be the last character).
     * sent raw because the local serializer refuses to build it. */
    static const unsigned char pkt[] = {0x82, 0x0B, 0x00, 0x01, 0x00, 0x00, 0x05, 'a', '/', '#', '/', 'b', 0x00};

    test_begin("v5 invalid topic filter is rejected (SUBACK 0x8F)");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_send_raw(&cli, (const char *)pkt, sizeof(pkt)) == 0, "subscribe sent");
    CHECK(cli_wait(&cli, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_TOPIC_FILTER_INVALID, "suback 0x8F");
    mqtt_packet_cleanup(&sa);
    cli_close(&cli);
    test_end();
}

static void
test_v5_publish_wildcard_topic(void) {
    cli_t cli;
    mqtt_packet_t ca, pk;
    char cid[64];
    /* PUBLISH (qos1, id 1) to topic "a/+/b".
     * sent raw because the local serializer refuses to build it. */
    static const unsigned char pkt[] = {0x32, 0x13, 0x00, 0x05, 'a', '/', '+', '/', 'b', 0x00, 0x01, 0x00,
                                        'b',  'a',  'd',  '-',  't',  'o',  'p',  'i',  'c'};

    test_begin("v5 publish to a topic name with a wildcard is rejected (0x90)");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_send_raw(&cli, (const char *)pkt, sizeof(pkt)) == 0, "pub sent");
    CHECK(cli_wait(&cli, MQTT_PUBACK, g_timeout_ms, &pk) == 0, "puback");
    CHECK_EQ_INT(pk.v.puback.v5.reason_code, MQTT_RC_TOPIC_NAME_INVALID, "puback 0x90");
    mqtt_packet_cleanup(&pk);
    cli_close(&cli);
    test_end();
}

static void
test_v5_auth_packet(void) {
    cli_t cli;
    mqtt_packet_t ca, au, pr;
    char cid[64];

    test_begin("v5 AUTH packet is answered with AUTH 0x00");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_auth5(&cli, "test-method", "c2FtcGxlZGF0YQ==") == 0, "auth sent");
    CHECK(cli_wait(&cli, MQTT_AUTH, g_timeout_ms, &au) == 0, "auth reply");
    CHECK_EQ_INT(au.v.auth.v5.reason_code, MQTT_RC_SUCCESS, "auth rc 0x00");
    mqtt_packet_cleanup(&au);
    CHECK(cli_ping(&cli) == 0, "pingreq");
    CHECK(cli_wait(&cli, MQTT_PINGRESP, g_timeout_ms, &pr) == 0, "still connected");
    mqtt_packet_cleanup(&pr);
    cli_close(&cli);
    test_end();
}

static void
test_v5_disconnect(void) {
    cli_t cli;
    mqtt_packet_t ca, pk;
    char cid[64];

    test_begin("v5 DISCONNECT ends the session cleanly");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_disconnect5(&cli, MQTT_RC_NORMAL_DISCONNECTION) == 0, "disconnect sent");
    CHECK(cli_wait(&cli, MQTT_PUBLISH, 5000, &pk) == -2, "broker closed the connection");
    cli_close(&cli);
    test_end();
}

/* ================================================================== */
/* tests: protocol edge cases                                          */
/* ================================================================== */

static void
test_qos2_duplicate_publish(void) {
    cli_t cli;
    mqtt_packet_t ca, sa, pk, dup;
    const char *f[1];
    uint8_t o = MQTT_QOS_2;
    uint16_t pid;
    char cid[64], topic[128];

    test_begin("qos2 duplicate PUBLISH (same id, in flight) is re-acked, not re-delivered");
    snprintf(topic, sizeof(topic), "%s/q2dup", g_topic);
    f[0] = topic;
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&cli, 1, f, &o, 0, 0) == 0, "subscribe sent");
    CHECK(cli_wait(&cli, MQTT_SUBACK, g_timeout_ms, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_publish(&cli, topic, MQTT_QOS_2, 0, "once", &pid) == 0, "pub sent");
    /* hold the publication in the REL state: do not answer the PUBREC
     * (as if the PUBREC was lost) */
    cli.no_ack = 1;
    CHECK(cli_wait(&cli, MQTT_PUBREC, g_timeout_ms, &pk) == 0, "pubrec");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_next_publish(&cli, &pk, g_timeout_ms) == 0, "delivered once");
    CHECK(payload_eq(&pk, "once"), "payload");
    mqtt_packet_cleanup(&pk);

    /* retransmit the same PUBLISH (same id, dup=1): the broker must not
     * re-dispatch it, only re-send the PUBREC */
    mqtt_packet_init(&dup, MQTT_VERSION_5, MQTT_PUBLISH);
    dup.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, MQTT_QOS_2, 0);
    dup.v.publish.packet_id = pid;
    mqtt_str_from(&dup.v.publish.topic_name, topic);
    mqtt_str_from(&dup.p.publish.message, "once");
    CHECK(cli_send_pkt(&cli, &dup) == 0, "duplicate pub sent");
    CHECK(cli_wait(&cli, MQTT_PUBREC, g_timeout_ms, &pk) == 0, "re-acked (pubrec again)");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_wait(&cli, MQTT_PUBLISH, 3000, &pk) == -1, "not re-delivered");

    /* complete the QoS2 flow */
    cli.no_ack = 0;
    CHECK(cli_send_ack(&cli, MQTT_PUBREL, pid) == 0, "pubrel sent");
    CHECK(cli_wait(&cli, MQTT_PUBCOMP, g_timeout_ms, &pk) == 0, "pubcomp");
    mqtt_packet_cleanup(&pk);
    cli_close(&cli);
    test_end();
}

static void
test_puback_unknown_id(void) {
    cli_t cli;
    mqtt_packet_t ca, pr;
    char cid[64];

    test_begin("PUBACK with an unknown packet id is ignored");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_send_ack(&cli, MQTT_PUBACK, 0xBEEF) == 0, "puback sent");
    CHECK(cli_ping(&cli) == 0, "pingreq");
    CHECK(cli_wait(&cli, MQTT_PINGRESP, g_timeout_ms, &pr) == 0, "still connected");
    mqtt_packet_cleanup(&pr);
    cli_close(&cli);
    test_end();
}

static void
test_pubrel_unknown_id(void) {
    cli_t cli;
    mqtt_packet_t ca, pk;
    char cid[64];

    test_begin("PUBREL with an unknown packet id answers PUBCOMP 0x92");
    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_send_ack(&cli, MQTT_PUBREL, 0xBEEF) == 0, "pubrel sent");
    CHECK(cli_wait(&cli, MQTT_PUBCOMP, g_timeout_ms, &pk) == 0, "pubcomp");
    CHECK_EQ_INT(pk.v.pubcomp.v5.reason_code, MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND, "pubcomp 0x92");
    mqtt_packet_cleanup(&pk);
    cli_close(&cli);
    test_end();
}

static void
test_v5_session_takeover(void) {
    cli_t a, b;
    mqtt_packet_t ca, dc;
    char cid[64];

    test_begin("v5 session takeover: old connection gets DISCONNECT 0x8E");
    CHECK(cli_open(&a, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, next_client_id(cid, sizeof(cid)), 0, 60, 300, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "a connack");
    mqtt_packet_cleanup(&ca);

    CHECK(cli_open(&b, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, cid, 0, 60, 300, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "b accepted");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "b session present");
    mqtt_packet_cleanup(&ca);

    CHECK(cli_wait(&a, MQTT_DISCONNECT, g_timeout_ms, &dc) == 0, "a receives DISCONNECT");
    CHECK_EQ_INT(dc.v.disconnect.v5.reason_code, MQTT_RC_SESSION_TAKEN_OVER, "a reason 0x8E");
    mqtt_packet_cleanup(&dc);
    cli_close(&a);
    cli_close(&b);
    test_end();
}

static void
test_auth_bad_password(void) {
    cli_t cli;
    mqtt_packet_t ca;
    char cid[64];
    char saved_pass[192];
    char wrong_pass[192];

    test_begin("auth: bad password is rejected (0x86 / 0x04)");
    if (!g_user[0]) {
        test_skip("no -u user given");
        test_end();
        return;
    }
    /* keep the working credentials, try a wrong password */
    snprintf(saved_pass, sizeof(saved_pass), "%.*s", (int)sizeof(saved_pass) - 1, g_pass);
    snprintf(wrong_pass, sizeof(wrong_pass), "%.*s-wrong", (int)(sizeof(wrong_pass) - 8), g_pass);
    snprintf(g_pass, sizeof(g_pass), "%.*s", (int)sizeof(g_pass) - 1, wrong_pass);

    CHECK(cli_open(&cli, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, next_client_id(cid, sizeof(cid)), 1, 60, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0,
          "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_BAD_USERNAME_OR_PASSWORD, "v5 0x86");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);

    snprintf(g_pass, sizeof(g_pass), "%s", saved_pass);
    test_end();
}

/* ================================================================== */
/* main                                                                */
/* ================================================================== */

static void
usage(void) {
    fprintf(stderr,
            "Usage: mqtt_remote_test [-h host] [-p port] [-u user] [-w pass] [-t timeout_ms] [test_prefix]\n"
            "  -h : broker host (default 120.26.78.56)\n"
            "  -p : broker port (default 1883)\n"
            "  -u : username (if the broker requires auth)\n"
            "  -w : password\n"
            "  -t : per-step timeout in ms (default 10000)\n"
            "  test_prefix : run only tests whose name starts with this string\n");
}

static void
run_test(const char *name, void (*fn)(void)) {
    if (g_filter[0] && strncmp(name, g_filter, strlen(g_filter)) != 0) {
        return;
    }
    fn();
}

int
main(int argc, char *argv[]) {
    int i;

    for (i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-h") || !strcmp(argv[i], "--host")) && i + 1 < argc) {
            snprintf(g_host, sizeof(g_host), "%s", argv[++i]);
        } else if ((!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) && i + 1 < argc) {
            g_port = atoi(argv[++i]);
        } else if ((!strcmp(argv[i], "-u") || !strcmp(argv[i], "--user")) && i + 1 < argc) {
            snprintf(g_user, sizeof(g_user), "%s", argv[++i]);
        } else if ((!strcmp(argv[i], "-w") || !strcmp(argv[i], "--pass")) && i + 1 < argc) {
            snprintf(g_pass, sizeof(g_pass), "%s", argv[++i]);
        } else if ((!strcmp(argv[i], "-t") || !strcmp(argv[i], "--timeout")) && i + 1 < argc) {
            g_timeout_ms = atoi(argv[++i]);
            if (g_timeout_ms < 100) {
                g_timeout_ms = 1000;
            }
        } else if (!strcmp(argv[i], "--help")) {
            usage();
            return 0;
        } else if (argv[i][0] != '-') {
            g_filter = argv[i];
        } else {
            usage();
            return 1;
        }
    }

    snprintf(g_topic, sizeof(g_topic), "kmq/remote/%d", (int)getpid());
    snprintf(g_rt_topic, sizeof(g_rt_topic), "%s/resp", g_topic);
    fprintf(stderr, "mqtt_remote_test: target %s:%d (timeout %d ms, topic prefix %s)\n", g_host, g_port,
            g_timeout_ms, g_topic);

    /* connection and handshake */
    run_test("tcp reachability", test_tcp_reachability);
    run_test("v3.1.1 connect (clean session)", test_v4_connect_clean);
    run_test("v5 connect + CONNACK capabilities", test_v5_connect_caps);
    run_test("v3.1.1 persistent session: subscriptions survive reconnect", test_v4_persistent_session);
    run_test("v5 session expiry: session resumes after DISCONNECT", test_v5_session_expiry_resume);
    run_test("v3.1.1 empty client id: clean ok, persistent rejected", test_v4_empty_id);
    run_test("v5 client id longer than 23 chars is rejected", test_v5_client_id_too_long);
    run_test("v5 empty client id: server assigns one", test_v5_assigned_client_id);
    run_test("CONNECT with bad protocol name closes the connection", test_bad_protocol_name);
    run_test("CONNECT with unsupported protocol level", test_unsupported_protocol_level);

    /* publish / subscribe */
    run_test("qos0 publish/subscribe round trip", test_qos0_roundtrip);
    run_test("qos1 publish/subscribe round trip", test_qos1_roundtrip);
    run_test("qos2 publish/subscribe round trip (PUBREC/PUBREL/PUBCOMP)", test_qos2_roundtrip);
    run_test("single SUBSCRIBE with three topic filters", test_multi_filter_subscribe);
    run_test("single-level wildcard +", test_wildcard_plus);
    run_test("multi-level wildcard #", test_wildcard_hash);
    run_test("UNSUBSCRIBE stops further delivery", test_unsubscribe_stops_delivery);
    run_test("qos2 publish to a qos0 subscription is delivered at qos0", test_qos_downgrade_delivery);
    run_test("empty payload round trip", test_empty_payload);
    run_test("large payload round trip", test_large_payload);
    run_test("one qos1 publish is delivered to two subscribers", test_two_clients_fanout);
    run_test("burst of 100 qos0 messages arrives in order", test_burst_qos0_order);

    /* retained messages */
    run_test("retained message: set, delivered to new subscriber, cleared", test_retained_set_get_clear);
    run_test("retained delivery carries the retain flag", test_retained_flag_on_delivery);
    run_test("v5 retain handling options (RH=1 keep, RH=2 delete)", test_v5_retain_handling);

    /* keepalive */
    run_test("PINGREQ -> PINGRESP", test_pingreq_pingresp);
    run_test("keep alive timeout drops the connection", test_keepalive_timeout);

    /* wills */
    run_test("will message is published on abrupt disconnect", test_will_delivery);
    run_test("clean DISCONNECT cancels the will message", test_will_cancelled);
    run_test("v5 will delay: will arrives only after the delay", test_v5_will_delay);

    /* mqtt 5 features */
    run_test("v5 publish properties pass through to the subscriber", test_v5_props_passthrough);
    run_test("v5 topic alias: bind then publish with alias only", test_v5_topic_alias_in);
    run_test("v5 topic alias: broker sends alias-only publishes", test_v5_topic_alias_out);
    run_test("v5 topic alias above the server maximum is rejected", test_v5_bad_topic_alias);
    run_test("v5 subscription identifier is echoed on delivery", test_v5_subscription_identifier);
    run_test("v5 shared subscription: each message goes to one group member", test_v5_shared_subscription);
    run_test("v5 SUBACK grants the requested qos per filter", test_v5_suback_granted_qos);
    run_test("v5 invalid topic filter is rejected (SUBACK 0x8F)", test_v5_invalid_topic_filter);
    run_test("v5 publish to a topic name with a wildcard is rejected (0x90)", test_v5_publish_wildcard_topic);
    run_test("v5 AUTH packet is answered with AUTH 0x00", test_v5_auth_packet);
    run_test("v5 DISCONNECT ends the session cleanly", test_v5_disconnect);

    /* protocol edge cases */
    run_test("qos2 duplicate PUBLISH (same packet id) is not re-delivered", test_qos2_duplicate_publish);
    run_test("PUBACK with an unknown packet id is ignored", test_puback_unknown_id);
    run_test("PUBREL with an unknown packet id answers PUBCOMP 0x92", test_pubrel_unknown_id);
    run_test("v5 session takeover: old connection gets DISCONNECT 0x8E", test_v5_session_takeover);

    /* auth (only when credentials are given) */
    run_test("auth: bad password is rejected (0x86 / 0x04)", test_auth_bad_password);

    fprintf(stderr,
            "\n==============================\n"
            "tests:   %d (%d failed, %d skipped)\n"
            "checks:  %d (%d failed)\n",
            g_tests, g_tests_failed, g_tests_skipped, g_checks, g_checks_failed);
    if (g_tests_failed) {
        fprintf(stderr, "RESULT: FAIL\n");
        return 1;
    }
    fprintf(stderr, "RESULT: PASS\n");
    return 0;
}
