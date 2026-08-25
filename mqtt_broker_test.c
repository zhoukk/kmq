/*
 * mqtt_broker_test.c -- end-to-end tests for mqtt_broker.
 *
 * Spawns the mqtt_broker binary on local ports and drives it with a
 * raw-socket MQTT client built on the mqtt.h serializer/parser. Covers
 * MQTT 3.1.1 basics and the MQTT 5.0 feature set: CONNACK capabilities,
 * properties pass-through, session expiry, will delay, topic alias
 * (both directions), shared subscriptions, subscription identifiers,
 * retain options (NL/RAP/RH), AUTH, rate limiting, $SYS, the WS
 * listener and disk persistence.
 *
 * Usage: mqtt_broker_test [base_port]   (default 18831)
 * Exit code: 0 = all tests passed, 1 = at least one failure.
 */

#define MQTT_CLI_NETWORK_IMPL
#define MQTT_CLI_IMPL
#include "mqtt_cli.h"

#define BASE64_IMPL
#include "base64.h"

#include <openssl/sha.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ================================================================== */
/* test harness                                                       */
/* ================================================================== */

static int g_checks;
static int g_checks_failed; /* cumulative across all tests */
static int g_failed;        /* per-test, reset in test_begin */
static int g_tests;
static int g_tests_failed;
static const char *g_test = "";

static void
test_begin(const char *name) {
    g_test = name;
    g_tests++;
    g_failed = 0;
    fprintf(stderr, "== %s\n", name);
}

static void
test_end(void) {
    if (g_failed) {
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

static void
msleep(uint64_t ms) {
    usleep((useconds_t)(ms * 1000));
}

/* ================================================================== */
/* broker process management                                          */
/* ================================================================== */

static char g_broker_path[512];
static char g_tmpdir[128];
static pid_t g_broker_pids[16];
static int g_broker_pid_n;

static void
init_paths(int base_port) {
    ssize_t n;

    (void)base_port;
    n = readlink("/proc/self/exe", g_broker_path, sizeof(g_broker_path) - 16);
    if (n > 0) {
        g_broker_path[n] = '\0';
        char *slash = strrchr(g_broker_path, '/');
        if (slash) {
            *slash = '\0';
        }
    } else {
        snprintf(g_broker_path, sizeof(g_broker_path), ".");
    }
    snprintf(g_broker_path + strlen(g_broker_path), sizeof(g_broker_path) - strlen(g_broker_path), "/mqtt_broker");

    snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/mqtt_broker_test.%d", (int)getpid());
    if (mkdir(g_tmpdir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", g_tmpdir, strerror(errno));
        exit(1);
    }
}

static void
write_file(const char *path, const char *content) {
    FILE *f;

    f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "cannot write %s\n", path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

/* spawn the broker with the given ini body; wait until the port accepts */
static pid_t
broker_start(int port, const char *ini_body) {
    char ini_path[256], log_path[256];
    pid_t pid;
    uint64_t deadline;

    /* fail fast if something else already owns the port */
    {
        void *probe = network_tcp_connect("127.0.0.1", port);
        if (probe) {
            fprintf(stderr, "port %d is already in use\n", port);
            network_tcp_close(probe);
            exit(1);
        }
    }

    snprintf(ini_path, sizeof(ini_path), "%s/broker_%d.ini", g_tmpdir, port);
    snprintf(log_path, sizeof(log_path), "%s/broker_%d.log", g_tmpdir, port);
    write_file(ini_path, ini_body);

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        exit(1);
    }
    if (pid == 0) {
        int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, 1);
            dup2(fd, 2);
            close(fd);
        }
        execl(g_broker_path, "mqtt_broker", ini_path, (char *)0);
        fprintf(stderr, "exec %s: %s\n", g_broker_path, strerror(errno));
        _exit(127);
    }

    if (g_broker_pid_n < (int)(sizeof(g_broker_pids) / sizeof(g_broker_pids[0]))) {
        g_broker_pids[g_broker_pid_n++] = pid;
    }

    /* wait for the listener */
    deadline = ms_now() + 5000;
    while (ms_now() < deadline) {
        int st;
        void *net;

        if (waitpid(pid, &st, WNOHANG) != 0) {
            fprintf(stderr, "broker on port %d exited prematurely (see %s)\n", port, log_path);
            exit(1);
        }
        net = network_tcp_connect("127.0.0.1", port);
        if (net) {
            network_tcp_close(net);
            return pid;
        }
        msleep(50);
    }
    fprintf(stderr, "broker on port %d did not come up (see %s)\n", port, log_path);
    kill(pid, SIGKILL);
    waitpid(pid, 0, 0);
    exit(1);
}

static void
broker_stop(pid_t pid) {
    int waited;

    if (pid <= 0) {
        return;
    }
    kill(pid, SIGTERM);
    waited = 0;
    while (waitpid(pid, 0, WNOHANG) == 0) {
        if (waited++ > 50) {
            kill(pid, SIGKILL);
            waitpid(pid, 0, 0);
            return;
        }
        msleep(100);
    }
}

static void
broker_stop_all(void) {
    int i;

    for (i = g_broker_pid_n - 1; i >= 0; i--) {
        broker_stop(g_broker_pids[i]);
    }
}

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
    mqtt_packet_t stashed;      /* first non-matching PUBLISH (retained-before-SUBACK) */
    char rx[65536];
    size_t rx_n;
} cli_t;

static int
cli_open(cli_t *cli, int port, mqtt_version_t ver) {
    memset(cli, 0, sizeof *cli);
    cli->net = network_tcp_connect("127.0.0.1", port);
    if (!cli->net) {
        return -1;
    }
    cli->ver = ver;
    cli->alive = 1;
    mqtt_parser_init(&cli->parser);
    mqtt_parser_version(&cli->parser, ver);
    return 0;
}

static void
cli_close(cli_t *cli) {
    if (cli->stashed.f.flags) {
        mqtt_packet_cleanup(&cli->stashed);
    }
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
        return -1;
    }
    rc = cli_send_raw(cli, b.s, b.n);
    mqtt_str_free(&b);
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
        /* we are the publisher: continue the QoS2 flow */
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
                    /* ack the QoS1/2 publication before handing it to the test */
                    cli_auto_ack(cli, pkt);
                    /* drop the consumed prefix before returning the packet */
                    memmove(cli->rx, cli->rx + incoming.i, cli->rx_n - incoming.i);
                    cli->rx_n -= incoming.i;
                    return 0;
                }
                cli_auto_ack(cli, pkt);
                /* keep the first PUBLISH: retained messages may arrive before
                 * the SUBACK the test is waiting for. the stash takes
                 * ownership of the packet's buffers, so skip the cleanup. */
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
            /* drop the consumed prefix, keep the unconsumed tail */
            memmove(cli->rx, cli->rx + incoming.i, cli->rx_n - incoming.i);
            cli->rx_n -= incoming.i;
        }
        if (ms_now() >= deadline) {
            return -1;
        }
        {
            ssize_t r = network_tcp_recv(cli->net, cli->rx + cli->rx_n, sizeof(cli->rx) - cli->rx_n);
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
            /* alias + full topic: (re)bind the alias */
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
cli_connect(cli_t *cli, const char *client_id, int clean, uint16_t keepalive, const char *user, const char *pass,
            uint32_t session_expiry, uint16_t receive_max, uint16_t alias_max, const char *will_topic,
            const char *will_msg, mqtt_qos_t will_qos, uint32_t will_delay, mqtt_packet_t *connack) {
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
    if (user) {
        pkt.v.connect.connect_flags |= MQTT_CF_USERNAME;
        mqtt_str_from(&pkt.p.connect.username, user);
    }
    if (pass) {
        pkt.v.connect.connect_flags |= MQTT_CF_PASSWORD;
        mqtt_str_from(&pkt.p.connect.password, pass);
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
    rc = cli_wait(cli, MQTT_CONNACK, 3000, connack);
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

/* v5 DISCONNECT with reason code (and optional user property) */
static int
cli_disconnect5(cli_t *cli, uint8_t reason, const char *user_prop, const char *user_val) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_DISCONNECT);
    pkt.v.disconnect.v5.reason_code = (mqtt_rc_t)reason;
    if (user_prop) {
        mqtt_properties_add(&pkt.v.disconnect.v5.properties, MQTT_PROPERTY_USER_PROPERTY, user_val, user_prop);
    }
    return cli_send_pkt(cli, &pkt);
}

/* v5 AUTH packet (no callback on the broker: expect AUTH 0x00 back) */
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

/* ================================================================== */
/* property inspection helpers (valid until the next parse)            */
/* ================================================================== */

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
prop_bv(mqtt_properties_t *p, mqtt_property_code_t code) {
    mqtt_property_t *x = mqtt_properties_find(p, code);

    return x ? (int)x->bv : -1;
}

static int
prop_str_eq(mqtt_properties_t *p, mqtt_property_code_t code, const char *s) {
    mqtt_property_t *x = mqtt_properties_find(p, code);

    return x && mqtt_str_strcmp(&x->str, s) == 0;
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

/* safe accessors: return -1 when the packet is not what we expect */
static int
suback_rc5(mqtt_packet_t *pkt, int i) {
    return (pkt->p.suback.v5.reason_codes && i < pkt->p.suback.n) ? (int)pkt->p.suback.v5.reason_codes[i] : -1;
}

static int
unsuback_rc5(mqtt_packet_t *pkt, int i) {
    return (pkt->p.unsuback.v5.reason_codes && i < pkt->p.unsuback.v5.n) ? (int)pkt->p.unsuback.v5.reason_codes[i]
                                                                          : -1;
}

static int
payload_eq(mqtt_packet_t *pkt, const char *s) {
    return pkt->p.publish.message.n == strlen(s) && memcmp(pkt->p.publish.message.s, s, pkt->p.publish.message.n) == 0;
}

/* ================================================================== */
/* websocket client (minimal RFC6455)                                 */
/* ================================================================== */

typedef struct {
    void *net;
    char buf[65536];
    size_t buf_len;
    char payload[65536];
} wscli_t;

static int
find_bytes(const char *hay, size_t n, const char *needle, size_t m) {
    size_t i;

    if (m == 0 || n < m) {
        return 0;
    }
    for (i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) {
            return 1;
        }
    }
    return 0;
}

static int
ws_connect(wscli_t *ws, int port) {
    unsigned char key[16];
    char keyb64[32];
    char req[512];
    char resp[2048];
    size_t resp_len = 0;
    unsigned char sha[20];
    char concat[96];
    char accept[32];
    int i;
    int len;

    memset(ws, 0, sizeof *ws);
    ws->net = network_tcp_connect("127.0.0.1", port);
    if (!ws->net) {
        return -1;
    }

    for (i = 0; i < 16; i++) {
        key[i] = (unsigned char)('a' + ((int)ms_now() + i * 7 + (int)(port + i)) % 26);
    }
    base64_encode((const char *)key, 16, keyb64);

    len = snprintf(req, sizeof(req),
                   "GET /mqtt HTTP/1.1\r\n"
                   "Host: 127.0.0.1:%d\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "\r\n",
                   port, keyb64);
    if (network_tcp_send(ws->net, req, (size_t)len) < 0) {
        goto fail;
    }

    /* read until end of headers */
    while (!find_bytes(resp, resp_len, "\r\n\r\n", 4)) {
        ssize_t r;

        r = network_tcp_recv(ws->net, resp + resp_len, sizeof(resp) - resp_len - 1);
        if (r <= 0) {
            goto fail;
        }
        resp_len += (size_t)r;
    }
    resp[resp_len] = '\0';
    if (strncmp(resp, "HTTP/1.1 101", 12) != 0) {
        fprintf(stderr, "  ws handshake failed: %.80s\n", resp);
        goto fail;
    }

    /* verify Sec-WebSocket-Accept */
    snprintf(concat, sizeof(concat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", keyb64);
    SHA1((const unsigned char *)concat, strlen(concat), sha);
    base64_encode((const char *)sha, 20, accept);
    if (strstr(resp, accept) == NULL) {
        fprintf(stderr, "  ws accept key mismatch\n");
        goto fail;
    }
    return 0;

fail:
    if (ws->net) {
        network_tcp_close(ws->net);
        ws->net = 0;
    }
    return -1;
}

static int
ws_send_frame(wscli_t *ws, int opcode, const char *data, size_t n) {
    unsigned char hdr[14];
    size_t hl = 0;
    unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};
    char masked[65536];
    size_t i;

    hdr[hl++] = (unsigned char)(0x80 | (opcode & 0x0f));
    if (n < 126) {
        hdr[hl++] = (unsigned char)(0x80 | n);
    } else if (n < 65536) {
        hdr[hl++] = 0x80 | 126;
        hdr[hl++] = (unsigned char)(n >> 8);
        hdr[hl++] = (unsigned char)(n & 0xff);
    } else {
        return -1;
    }
    memcpy(hdr + hl, mask, 4);
    hl += 4;
    for (i = 0; i < n; i++) {
        masked[i] = data[i] ^ (char)mask[i % 4];
    }
    if (network_tcp_send(ws->net, (const char *)hdr, hl) < 0) {
        return -1;
    }
    if (n && network_tcp_send(ws->net, masked, n) < 0) {
        return -1;
    }
    return 0;
}

/*
 * wait for the next frame.
 * returns: opcode (0x2 binary, 0xa pong), -1 closed, -2 timeout/error;
 * payload in ws->payload, *plen its length.
 */
static int
ws_wait_frame(wscli_t *ws, size_t *plen, int timeout_ms) {
    uint64_t deadline;

    *plen = 0;
    deadline = ms_now() + (uint64_t)timeout_ms;
    for (;;) {
        unsigned char b0, b1;
        size_t len, off, need;
        int masked;
        int complete;
        unsigned char mask[4];

        if (ws->buf_len >= 2) {
            b0 = (unsigned char)ws->buf[0];
            b1 = (unsigned char)ws->buf[1];
            len = b1 & 0x7f;
            off = 2;
            masked = (b1 & 0x80) != 0;
            complete = 1;
            if (len == 126) {
                if (ws->buf_len < 4) {
                    complete = 0;
                } else {
                    len = ((size_t)ws->buf[2] << 8) | ws->buf[3];
                    off = 4;
                }
            } else if (len == 127) {
                return -1; /* 64-bit lengths unsupported in tests */
            }
            if (complete) {
                need = off + (masked ? 4 : 0) + len;
                if (ws->buf_len >= need) {
                    size_t i;

                    if (masked) {
                        memcpy(mask, ws->buf + off, 4);
                    }
                    if (len > sizeof(ws->payload)) {
                        return -1;
                    }
                    for (i = 0; i < len; i++) {
                        ws->payload[i] = ws->buf[off + (masked ? 4 : 0) + i] ^ (masked ? (char)mask[i % 4] : 0);
                    }
                    memmove(ws->buf, ws->buf + need, ws->buf_len - need);
                    ws->buf_len -= need;
                    *plen = len;
                    return b0 & 0x0f;
                }
            }
        }
        if (ms_now() >= deadline) {
            return -2;
        }
        {
            ssize_t r = network_tcp_recv(ws->net, ws->buf + ws->buf_len, sizeof(ws->buf) - ws->buf_len);
            if (r <= 0) {
                return -1;
            }
            ws->buf_len += (size_t)r;
        }
    }
}

/* ================================================================== */
/* tests                                                              */
/* ================================================================== */

static int g_port_main, g_port_auth, g_port_rate, g_port_sys, g_port_ws, g_port_persist;

static pid_t g_pid_main, g_pid_auth, g_pid_rate, g_pid_sys, g_pid_ws, g_pid_persist;

static char *
sha256_hex(const char *s) {
    static char out[65];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t i;

    SHA256((const unsigned char *)s, strlen(s), digest);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    }
    out[SHA256_DIGEST_LENGTH * 2] = '\0';
    return out;
}

static void
start_all_brokers(void) {
    char ini[1024];
    const char *log_level = getenv("BT_LOG");

    if (!log_level || !*log_level) {
        log_level = "warn";
    }

    snprintf(ini, sizeof(ini),
             "[log]\nlevel=%s\n[net]\nhost=127.0.0.1\nport=%d\n",
             log_level, g_port_main);
    g_pid_main = broker_start(g_port_main, ini);

    snprintf(ini, sizeof(ini),
             "[log]\nlevel=warn\n[net]\nhost=127.0.0.1\nport=%d\n"
             "[auth]\ntype=config\n"
             "[user]\n"
             "alice=secret123,*\n"
             "bob=pwd456,bobclient\n"
             "carol=sha256:%s,*\n",
             g_port_auth, sha256_hex("carolpass"));
    g_pid_auth = broker_start(g_port_auth, ini);

    snprintf(ini, sizeof(ini),
             "[log]\nlevel=warn\n[net]\nhost=127.0.0.1\nport=%d\n"
             "[limit]\nrate_limit=2\n",
             g_port_rate);
    g_pid_rate = broker_start(g_port_rate, ini);

    snprintf(ini, sizeof(ini),
             "[log]\nlevel=%s\n[net]\nhost=127.0.0.1\nport=%d\n"
             "[sys]\ninterval=1\n",
             log_level, g_port_sys);
    g_pid_sys = broker_start(g_port_sys, ini);

    snprintf(ini, sizeof(ini),
             "[log]\nlevel=%s\n[listener-ws]\nmode=ws\nhost=127.0.0.1\nport=%d\n",
             log_level, g_port_ws);
    g_pid_ws = broker_start(g_port_ws, ini);

    snprintf(ini, sizeof(ini),
             "[log]\nlevel=warn\n[net]\nhost=127.0.0.1\nport=%d\n"
             "[persist]\nfile=%s/persist.txt\n",
             g_port_persist, g_tmpdir);
    g_pid_persist = broker_start(g_port_persist, ini);
}

/* ---------------- A. connection ---------------- */

static void
test_v5_connack_caps(void) {
    cli_t cli;
    mqtt_packet_t ca;

    test_begin("v5 connack advertises server capabilities");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "connect");
    CHECK(cli_connect(&cli, "cap-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "reason");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 0, "session present");
    CHECK_EQ_INT(prop_b2(&ca.v.connack.v5.properties, MQTT_PROPERTY_RECEIVE_MAXIMUM), 10, "receive maximum");
    CHECK_EQ_INT(prop_b1(&ca.v.connack.v5.properties, MQTT_PROPERTY_MAXIMUM_QOS), 2, "max qos");
    CHECK_EQ_INT(prop_b1(&ca.v.connack.v5.properties, MQTT_PROPERTY_RETAIN_AVAILABLE), 1, "retain available");
    CHECK_EQ_INT(prop_b2(&ca.v.connack.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM), 10, "topic alias max");
    CHECK_EQ_INT(prop_b1(&ca.v.connack.v5.properties, MQTT_PROPERTY_WILDCARD_SUBSCRIPTION_AVAILABLE), 1, "wildcard");
    CHECK_EQ_INT(prop_b1(&ca.v.connack.v5.properties, MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIERS_AVAILABLE), 1, "sub ids");
    CHECK_EQ_INT(prop_b1(&ca.v.connack.v5.properties, MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE), 1, "shared");
    CHECK(mqtt_properties_find(&ca.v.connack.v5.properties, MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL) != 0,
          "session expiry present");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_v5_empty_client_id(void) {
    cli_t cli;
    mqtt_packet_t ca;

    test_begin("v5 connect with empty client id");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "connect");
    CHECK(cli_connect(&cli, "", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "reason");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_v5_session_present(void) {
    cli_t a, b;
    mqtt_packet_t ca;

    test_begin("v5 persistent session: session present on reconnect");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a connect");
    CHECK(cli_connect(&a, "sess-a", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 0, "first: no session");
    mqtt_packet_cleanup(&ca);
    cli_close(&a); /* abnormal close, session kept */

    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b connect");
    CHECK(cli_connect(&b, "sess-a", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "reconnect: session present");
    mqtt_packet_cleanup(&ca);
    cli_close(&b);
    test_end();
}

static void
test_v5_clean_session(void) {
    cli_t a, b;
    mqtt_packet_t ca;

    test_begin("v5 clean session drops the previous session");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a connect");
    CHECK(cli_connect(&a, "sess-b", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    mqtt_packet_cleanup(&ca);
    cli_close(&a);

    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b connect");
    CHECK(cli_connect(&b, "sess-b", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 0, "clean: no session");
    mqtt_packet_cleanup(&ca);
    cli_close(&b);
    test_end();
}

static void
test_v4_connack(void) {
    cli_t a, b;
    mqtt_packet_t ca;

    test_begin("v3.1.1 connect + session present");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_4) == 0, "a connect");
    CHECK(cli_connect(&a, "v4-cli", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    CHECK_EQ_INT(ca.v.connack.v4.return_code, MQTT_CRC_ACCEPTED, "a rc");
    mqtt_packet_cleanup(&ca);
    cli_close(&a);

    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_4) == 0, "b connect");
    CHECK(cli_connect(&b, "v4-cli", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v4.return_code, MQTT_CRC_ACCEPTED, "b rc");
    CHECK_EQ_INT(ca.v.connack.v4.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "session present");
    mqtt_packet_cleanup(&ca);
    cli_close(&b);
    test_end();
}

static void
test_auth(void) {
    cli_t cli;
    mqtt_packet_t ca;

    test_begin("auth: config users (plain + sha256) and client id binding");
    /* good plain password */
    CHECK(cli_open(&cli, g_port_auth, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "auth-1", 1, 60, "alice", "secret123", 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "alice ok");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);

    /* good sha256 password */
    CHECK(cli_open(&cli, g_port_auth, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "auth-2", 1, 60, "carol", "carolpass", 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "carol ok");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);

    /* bad password -> 0x86 */
    CHECK(cli_open(&cli, g_port_auth, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "auth-3", 1, 60, "alice", "wrong", 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_BAD_USERNAME_OR_PASSWORD, "bad password 0x86");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);

    /* client id binding: bob may only use "bobclient" */
    CHECK(cli_open(&cli, g_port_auth, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "other-id", 1, 60, "bob", "pwd456", 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_BAD_USERNAME_OR_PASSWORD, "client id binding 0x86");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);

    CHECK(cli_open(&cli, g_port_auth, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "bobclient", 1, 60, "bob", "pwd456", 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "bob with bound id ok");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);

    /* v4 rejection code */
    CHECK(cli_open(&cli, g_port_auth, MQTT_VERSION_4) == 0, "open");
    CHECK(cli_connect(&cli, "auth-4", 1, 60, "alice", "wrong", 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v4.return_code, MQTT_CRC_REFUSED_BAD_USERNAME_PASSWORD, "v4 bad password 0x04");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_session_takeover(void) {
    cli_t a, b;
    mqtt_packet_t ca, dc;

    test_begin("v5 session takeover: old connection gets DISCONNECT 0x8E");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, "take-1", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    mqtt_packet_cleanup(&ca);

    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, "take-1", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "b accepted");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "b session present");
    mqtt_packet_cleanup(&ca);

    CHECK(cli_wait(&a, MQTT_DISCONNECT, 3000, &dc) == 0, "a receives DISCONNECT");
    CHECK_EQ_INT(dc.v.disconnect.v5.reason_code, MQTT_RC_SESSION_TAKEN_OVER, "a reason 0x8E");
    mqtt_packet_cleanup(&dc);
    cli_close(&a);
    cli_close(&b);
    test_end();
}

static void
test_v5_ping(void) {
    cli_t cli;
    mqtt_packet_t ca, pr;

    test_begin("v5 PINGREQ -> PINGRESP");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "ping-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_ping(&cli) == 0, "pingreq sent");
    CHECK(cli_wait(&cli, MQTT_PINGRESP, 3000, &pr) == 0, "pingresp");
    mqtt_packet_cleanup(&pr);
    cli_close(&cli);
    test_end();
}

static void
test_v5_auth_packet(void) {
    cli_t cli;
    mqtt_packet_t ca, au, pr;

    test_begin("v5 AUTH packet is answered with AUTH 0x00");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "auth-pkt", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_auth5(&cli, "scram", "c2FtcGxlZGF0YQ==") == 0, "auth sent");
    CHECK(cli_wait(&cli, MQTT_AUTH, 3000, &au) == 0, "auth reply");
    CHECK_EQ_INT(au.v.auth.v5.reason_code, MQTT_RC_SUCCESS, "auth rc 0x00");
    mqtt_packet_cleanup(&au);
    CHECK(cli_ping(&cli) == 0, "pingreq");
    CHECK(cli_wait(&cli, MQTT_PINGRESP, 3000, &pr) == 0, "still connected");
    mqtt_packet_cleanup(&pr);
    cli_close(&cli);
    test_end();
}

static void
test_v5_disconnect_props(void) {
    cli_t cli;
    mqtt_packet_t ca;

    test_begin("v5 DISCONNECT with reason + user property");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "disc-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_disconnect5(&cli, MQTT_RC_NORMAL_DISCONNECTION, "reason", "test-client") == 0, "disconnect sent");
    CHECK(cli_wait(&cli, MQTT_PUBLISH, 1500, &ca) == -2, "broker closes the connection");
    cli_close(&cli);
    test_end();
}

static void
test_non_connect_first(void) {
    cli_t cli;
    mqtt_packet_t pub;

    test_begin("PUBLISH before CONNECT is rejected");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    mqtt_packet_init(&pub, MQTT_VERSION_5, MQTT_PUBLISH);
    pub.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_0, 0);
    mqtt_str_from(&pub.v.publish.topic_name, "x/y");
    mqtt_str_from(&pub.p.publish.message, "hi");
    CHECK(cli_send_pkt(&cli, &pub) == 0, "publish sent");
    CHECK(cli_wait(&cli, MQTT_CONNACK, 2000, &pub) == -2, "broker closes the connection");
    cli_close(&cli);
    test_end();
}

static void
test_keepalive_timeout(void) {
    cli_t cli;
    mqtt_packet_t ca, pkt;

    test_begin("keep alive timeout drops the connection");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "ka-cli", 1, 1, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack ka=1");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_wait(&cli, MQTT_PINGRESP, 6000, &pkt) == -2, "connection closed after 1.5x keep alive");
    cli_close(&cli);
    test_end();
}

/* ---------------- B. pub/sub ---------------- */

static void
test_v5_qos0(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"q0/t"};
    uint8_t o[] = {0};

    test_begin("v5 qos0 publish/subscribe");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "q0-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_GRANTED_QOS_0, "granted qos0");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "q0-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "q0/t", MQTT_QOS_0, 0, "hello-q0", 0) == 0, "publish");

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received");
    {
        mqtt_property_t *pp;
        fprintf(stderr, "  [dbg] topic=[%.*s] n=%zu payload=[%.*s]\n",
                (int)pk.v.publish.topic_name.n, pk.v.publish.topic_name.s ? pk.v.publish.topic_name.s : "",
                pk.v.publish.topic_name.n, (int)pk.p.publish.message.n,
                pk.p.publish.message.s ? pk.p.publish.message.s : "");
        for (pp = pk.v.publish.v5.properties.head; pp; pp = pp->next) {
            fprintf(stderr, "  [dbg] prop code=%d b2=%u\n", (int)pp->code, pp->b2);
        }
    }
    CHECK(strcmp(cli_publish_topic(&sub, &pk), "q0/t") == 0, "topic");
    CHECK_EQ_INT(pk.p.publish.message.n, strlen("hello-q0"), "payload len");
    CHECK(payload_eq(&pk, "hello-q0"), "payload");
    CHECK_EQ_INT(MQTT_FH_QOS(pk.f.flags), 0, "qos");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_qos1(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk, ack;
    uint16_t id = 0;
    const char *f[] = {"q1/t"};
    uint8_t o[] = {MQTT_QOS_1};

    test_begin("v5 qos1 publish/subscribe with PUBACK");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "q1-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_GRANTED_QOS_1, "granted qos1");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "q1-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "q1/t", MQTT_QOS_1, 0, "hello-q1", &id) == 0, "publish");
    CHECK(cli_wait(&pub, MQTT_PUBACK, 3000, &ack) == 0, "puback");
    CHECK_EQ_INT(ack.v.puback.packet_id, id, "puback id");
    CHECK_EQ_INT(ack.v.puback.v5.reason_code, MQTT_RC_SUCCESS, "puback rc");
    mqtt_packet_cleanup(&ack);

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received");
    CHECK(strcmp(cli_publish_topic(&sub, &pk), "q1/t") == 0, "topic");
    CHECK(payload_eq(&pk, "hello-q1"), "payload");
    CHECK_EQ_INT(MQTT_FH_QOS(pk.f.flags), 1, "qos");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_qos2(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk, rec, rel, comp;
    uint16_t id = 0;
    const char *f[] = {"q2/t"};
    uint8_t o[] = {MQTT_QOS_2};

    test_begin("v5 qos2 publish/subscribe (PUBREC/PUBREL/PUBCOMP)");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "q2-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_GRANTED_QOS_2, "granted qos2");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "q2-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "q2/t", MQTT_QOS_2, 0, "hello-q2", &id) == 0, "publish");
    /* receiving the PUBREC auto-answers with PUBREL */
    CHECK(cli_wait(&pub, MQTT_PUBREC, 3000, &rec) == 0, "pubrec");
    CHECK_EQ_INT(rec.v.pubrec.packet_id, id, "pubrec id");
    mqtt_packet_cleanup(&rec);
    CHECK(cli_wait(&pub, MQTT_PUBCOMP, 3000, &comp) == 0, "pubcomp");
    CHECK_EQ_INT(comp.v.pubcomp.packet_id, id, "pubcomp id");
    mqtt_packet_cleanup(&comp);

    /* the QoS2 PUBLISH is auto-answered with PUBREC */
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received");
    CHECK(strcmp(cli_publish_topic(&sub, &pk), "q2/t") == 0, "topic");
    CHECK(payload_eq(&pk, "hello-q2"), "payload");
    CHECK_EQ_INT(MQTT_FH_QOS(pk.f.flags), 2, "qos");
    /* the broker's PUBREL is auto-answered with PUBCOMP (the subscriber never
     * receives a PUBCOMP itself) */
    CHECK(cli_wait(&sub, MQTT_PUBREL, 3000, &rel) == 0, "pubrel from broker");
    CHECK_EQ_INT(rel.v.pubrel.packet_id, pk.v.publish.packet_id, "pubrel id matches publish");
    mqtt_packet_cleanup(&rel);
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_qos_downgrade(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"qd/t"};
    uint8_t o[] = {MQTT_QOS_0};

    test_begin("v5 qos downgrade: qos2 publish to qos0 subscription");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "qd-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe qos0");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "qd-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "qd/t", MQTT_QOS_2, 0, "down", 0) == 0, "publish qos2");

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received");
    CHECK_EQ_INT(MQTT_FH_QOS(pk.f.flags), 0, "delivered at qos0");
    CHECK(payload_eq(&pk, "down"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_props_passthrough(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk, pubpkt;
    mqtt_str_t corr;
    const char *f[] = {"pp/t"};
    uint8_t o[] = {0};
    uint8_t pfi = 1;
    uint32_t expiry = 120;

    test_begin("v5 publish properties are passed through to subscribers");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "pp-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "pp-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);

    mqtt_packet_init(&pubpkt, MQTT_VERSION_5, MQTT_PUBLISH);
    pubpkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_0, 0);
    mqtt_str_from(&pubpkt.v.publish.topic_name, "pp/t");
    mqtt_str_from(&pubpkt.p.publish.message, "{\"k\":1}");
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR, &pfi, NULL);
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL, &expiry, NULL);
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_CONTENT_TYPE, "application/json", NULL);
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_RESPONSE_TOPIC, "pp/resp", NULL);
    mqtt_str_init(&corr, (char *)"corr-123", 8);
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_CORRELATION_DATA, &corr, NULL);
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_USER_PROPERTY, "v1", "k1");
    CHECK(cli_send_pkt(&pub, &pubpkt) == 0, "publish with props");

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received");
    CHECK_EQ_INT(prop_b1(&pk.v.publish.v5.properties, MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR), 1, "payload format");
    CHECK_EQ_INT(prop_b4(&pk.v.publish.v5.properties, MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL), 120, "message expiry");
    CHECK(prop_str_eq(&pk.v.publish.v5.properties, MQTT_PROPERTY_CONTENT_TYPE, "application/json"), "content type");
    CHECK(prop_str_eq(&pk.v.publish.v5.properties, MQTT_PROPERTY_RESPONSE_TOPIC, "pp/resp"), "response topic");
    CHECK(prop_data_eq(&pk.v.publish.v5.properties, MQTT_PROPERTY_CORRELATION_DATA, "corr-123"), "correlation data");
    CHECK(prop_user_eq(&pk.v.publish.v5.properties, "k1", "v1"), "user property");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_retained(void) {
    cli_t sub, pub, sub2;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"rt/t"};
    uint8_t o[] = {0};

    test_begin("v5 retained messages: store, deliver, clear");
    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "rt-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "rt/t", MQTT_QOS_0, 1, "retained-hello", 0) == 0, "publish retained");

    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "rt-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);
    /* the retained message may have arrived before the SUBACK */
    CHECK(cli_next_publish(&sub, &pk, 3000) == 0, "retained delivered");
    CHECK_EQ_INT(MQTT_FH_RETAIN(pk.f.flags), 1, "retain flag set");
    CHECK(payload_eq(&pk, "retained-hello"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);

    /* clear with empty payload */
    CHECK(cli_publish(&pub, "rt/t", MQTT_QOS_0, 1, "", 0) == 0, "publish empty retained");
    msleep(200);

    CHECK(cli_open(&sub2, g_port_main, MQTT_VERSION_5) == 0, "sub2 open");
    CHECK(cli_connect(&sub2, "rt-sub2", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub2 connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub2, 1, f, o, 0, 0) == 0, "subscribe again");
    CHECK(cli_wait(&sub2, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_wait(&sub2, MQTT_PUBLISH, 1500, &pk) == -1, "no retained after clear");
    cli_close(&sub2);
    cli_close(&pub);
    test_end();
}

static void
test_v5_rap(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"rap/t"};
    uint8_t o[] = {MQTT_SUBOPT_RAP};

    test_begin("v5 retain-as-published: retained delivered with retain=0");
    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "rap-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "rap/t", MQTT_QOS_0, 1, "rap-hello", 0) == 0, "publish retained");

    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "rap-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe RAP");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);
    /* the retained message may have arrived before the SUBACK */
    CHECK(cli_next_publish(&sub, &pk, 3000) == 0, "retained delivered");
    CHECK_EQ_INT(MQTT_FH_RETAIN(pk.f.flags), 0, "retain flag cleared (RAP)");
    CHECK(payload_eq(&pk, "rap-hello"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_retain_handling(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"rh/t"};
    uint8_t o[] = {(uint8_t)(2 << 4)}; /* retain handling = 2: never send */

    test_begin("v5 retain handling 2: no retained on new subscription");
    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "rh-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "rh/t", MQTT_QOS_0, 1, "rh-hello", 0) == 0, "publish retained");

    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "rh-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe RH=2");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 1500, &pk) == -1, "no retained message");
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_no_local(void) {
    cli_t a, b;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"nl/t"};
    uint8_t o[] = {MQTT_SUBOPT_NL};

    test_begin("v5 no-local: own messages not echoed, others delivered");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, "nl-a", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&a, 1, f, o, 0, 0) == 0, "a subscribe NL");
    CHECK(cli_wait(&a, MQTT_SUBACK, 3000, &sa) == 0, "a suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_publish(&a, "nl/t", MQTT_QOS_0, 0, "own", 0) == 0, "a publishes own");
    CHECK(cli_wait(&a, MQTT_PUBLISH, 1500, &pk) == -1, "own message not delivered");

    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, "nl-b", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&b, "nl/t", MQTT_QOS_0, 0, "other", 0) == 0, "b publishes");
    CHECK(cli_wait(&a, MQTT_PUBLISH, 3000, &pk) == 0, "other message delivered");
    CHECK(payload_eq(&pk, "other"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&a);
    cli_close(&b);
    test_end();
}

static void
test_v5_wildcards(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"w/+/c", "w/#"};
    uint8_t o[] = {0, 0};

    test_begin("v5 wildcard subscriptions (+ and #)");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "wc-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 2, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_GRANTED_QOS_0, "rc0");
    CHECK_EQ_INT(suback_rc5(&sa, 1), MQTT_RC_GRANTED_QOS_0, "rc1");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "wc-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);

    /* matches both filters -> 2 deliveries */
    CHECK(cli_publish(&pub, "w/x/c", MQTT_QOS_0, 0, "m1", 0) == 0, "pub w/x/c");
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "m1 #1");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "m1 #2");
    mqtt_packet_cleanup(&pk);

    /* matches only w/# -> 1 delivery */
    CHECK(cli_publish(&pub, "w/x/d/e", MQTT_QOS_0, 0, "m2", 0) == 0, "pub w/x/d/e");
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "m2");
    CHECK(strcmp(cli_publish_topic(&sub, &pk), "w/x/d/e") == 0, "topic");
    mqtt_packet_cleanup(&pk);

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 1000, &pk) == -1, "no extra deliveries");
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_sub_id(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"sid/t"};
    uint8_t o[] = {0};

    test_begin("v5 subscription identifier is added to publications");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "sid-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 7, 0) == 0, "subscribe with sub id 7");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "sid-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "sid/t", MQTT_QOS_0, 0, "sid-msg", 0) == 0, "publish");

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received");
    CHECK_EQ_INT(prop_bv(&pk.v.publish.v5.properties, MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER), 7, "sub id 7");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_shared(void) {
    cli_t a, b, pub;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"$share/grp/sh/t"};
    uint8_t o[] = {0};
    int got_a = 0, got_b = 0, i;

    test_begin("v5 shared subscription: round robin, exactly one member per message");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, "sh-a", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&a, 1, f, o, 0, 0) == 0, "a subscribe");
    CHECK(cli_wait(&a, MQTT_SUBACK, 3000, &sa) == 0, "a suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_GRANTED_QOS_0, "a granted");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, "sh-b", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&b, 1, f, o, 0, 0) == 0, "b subscribe");
    CHECK(cli_wait(&b, MQTT_SUBACK, 3000, &sa) == 0, "b suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "sh-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);

    /* 4 messages: each member must get some, total must be 4 */
    for (i = 0; i < 4; i++) {
        char msg[16];

        snprintf(msg, sizeof(msg), "shared-%d", i);
        CHECK(cli_publish(&pub, "sh/t", MQTT_QOS_0, 0, msg, 0) == 0, "publish");
    }
    for (i = 0; i < 64; i++) {
        int ra, rb;

        ra = cli_wait(&a, MQTT_PUBLISH, 1500, &pk);
        if (ra == 0) {
            got_a++;
            mqtt_packet_cleanup(&pk);
            continue;
        }
        rb = cli_wait(&b, MQTT_PUBLISH, 1500, &pk);
        if (rb == 0) {
            got_b++;
            mqtt_packet_cleanup(&pk);
            continue;
        }
        break;
    }
    CHECK_EQ_INT(got_a + got_b, 4, "total delivered");
    CHECK(got_a >= 1, "a got at least one");
    CHECK(got_b >= 1, "b got at least one");

    cli_close(&a);
    cli_close(&b);
    cli_close(&pub);
    test_end();
}

static void
test_v5_shared_malformed(void) {
    cli_t cli;
    mqtt_packet_t ca, sa;
    const char *f[] = {"$share/nofilter"};
    uint8_t o[] = {0};

    test_begin("v5 malformed shared subscription -> SUBACK 0x9E");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "sh-bad", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&cli, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&cli, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED, "rc 0x9E");
    mqtt_packet_cleanup(&sa);
    cli_close(&cli);
    test_end();
}

static void
test_v5_invalid_filter(void) {
    cli_t cli;
    mqtt_packet_t ca, sa;

    test_begin("v5 invalid topic filter -> SUBACK 0x8F");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "badf-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    /* the client serializer rejects invalid filters, so send the SUBSCRIBE raw:
     * SUBSCRIBE id=1, no props, filter "sport/#/volley", options 0 */
    {
        const unsigned char raw[] = {0x82, 0x14, 0x00, 0x01, 0x00, 0x00, 0x0E,
                                     's',  'p',  'o',  'r',  't', '/', '#', '/',
                                     'v',  'o',  'l',  'l',  'e', 'y', 0x00};

        CHECK(cli_send_raw(&cli, (const char *)raw, sizeof(raw)) == 0, "subscribe (raw)");
    }
    CHECK(cli_wait(&cli, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_TOPIC_FILTER_INVALID, "rc 0x8F");
    mqtt_packet_cleanup(&sa);
    cli_close(&cli);
    test_end();
}

static void
test_v5_unsub_reasons(void) {
    cli_t cli;
    mqtt_packet_t ca, sa, ua;
    const char *f[] = {"us/t"};
    uint8_t o[] = {0};

    test_begin("v5 UNSUBACK reason codes (0x00 existed, 0x11 not)");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "us-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&cli, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&cli, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_unsubscribe(&cli, 1, f, 0) == 0, "unsubscribe");
    CHECK(cli_wait(&cli, MQTT_UNSUBACK, 3000, &ua) == 0, "unsuback");
    CHECK_EQ_INT(unsuback_rc5(&ua, 0), MQTT_RC_SUCCESS, "first unsub 0x00");
    mqtt_packet_cleanup(&ua);

    CHECK(cli_unsubscribe(&cli, 1, f, 0) == 0, "unsubscribe again");
    CHECK(cli_wait(&cli, MQTT_UNSUBACK, 3000, &ua) == 0, "unsuback");
    CHECK_EQ_INT(unsuback_rc5(&ua, 0), MQTT_RC_NO_SUBSCRIPTION_EXISTED, "second unsub 0x11");
    mqtt_packet_cleanup(&ua);
    cli_close(&cli);
    test_end();
}

static void
test_v5_unsub_invalid_filter(void) {
    cli_t cli;
    mqtt_packet_t ca, ua;
    const char *f[] = {"us/t"};
    uint8_t o[] = {0};

    test_begin("v5 invalid unsubscribe filter -> UNSUBACK 0x8F");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "us-bad-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    /* the client serializer rejects invalid filters, so send the UNSUBSCRIBE
     * raw: UNSUBSCRIBE id=1, no props, filter "sport/#/volley" */
    {
        const unsigned char raw[] = {0xA2, 0x13, 0x00, 0x01, 0x00, 0x00, 0x0E,
                                     's',  'p',  'o',  'r',  't', '/', '#', '/',
                                     'v',  'o',  'l',  'l',  'e', 'y'};

        CHECK(cli_send_raw(&cli, (const char *)raw, sizeof(raw)) == 0, "unsubscribe (raw)");
    }
    CHECK(cli_wait(&cli, MQTT_UNSUBACK, 3000, &ua) == 0, "unsuback");
    CHECK_EQ_INT(unsuback_rc5(&ua, 0), MQTT_RC_TOPIC_FILTER_INVALID, "rc 0x8F");
    mqtt_packet_cleanup(&ua);

    /* the connection survives: a follow-up valid unsubscribe still answers */
    CHECK(cli_subscribe(&cli, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&cli, MQTT_SUBACK, 3000, &ua) == 0, "suback");
    mqtt_packet_cleanup(&ua);
    CHECK(cli_unsubscribe(&cli, 1, f, 0) == 0, "unsubscribe");
    CHECK(cli_wait(&cli, MQTT_UNSUBACK, 3000, &ua) == 0, "unsuback");
    CHECK_EQ_INT(unsuback_rc5(&ua, 0), MQTT_RC_SUCCESS, "valid unsub 0x00");
    mqtt_packet_cleanup(&ua);
    cli_close(&cli);
    test_end();
}

static void
test_v5_alias_in(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk, pubpkt;
    uint16_t alias = 1;
    const char *f[] = {"al/t"};
    uint8_t o[] = {0};

    test_begin("v5 incoming topic alias: store then reuse with empty topic");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "al-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    /* publisher advertises Topic Alias Maximum = 5 */
    CHECK(cli_connect(&pub, "al-pub", 1, 60, 0, 0, 0, 0, 5, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);

    /* first use: alias + full topic */
    mqtt_packet_init(&pubpkt, MQTT_VERSION_5, MQTT_PUBLISH);
    pubpkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_0, 0);
    mqtt_str_from(&pubpkt.v.publish.topic_name, "al/t");
    mqtt_str_from(&pubpkt.p.publish.message, "alias-1");
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS, &alias, NULL);
    CHECK(cli_send_pkt(&pub, &pubpkt) == 0, "publish alias+topic");
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received 1");
    CHECK(strcmp(cli_publish_topic(&sub, &pk), "al/t") == 0, "topic 1");
    mqtt_packet_cleanup(&pk);

    /* second use: alias only, empty topic */
    mqtt_packet_init(&pubpkt, MQTT_VERSION_5, MQTT_PUBLISH);
    pubpkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_0, 0);
    mqtt_str_from(&pubpkt.p.publish.message, "alias-2");
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS, &alias, NULL);
    CHECK(cli_send_pkt(&pub, &pubpkt) == 0, "publish alias only");
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received 2");
    CHECK(strcmp(cli_publish_topic(&sub, &pk), "al/t") == 0, "topic resolved from alias");
    CHECK(payload_eq(&pk, "alias-2"), "payload 2");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_alias_out(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk1, pk2;
    const char *f[] = {"ao/t"};
    uint8_t o[] = {0};

    test_begin("v5 outgoing topic alias: broker aliases repeated topics");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "ao-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "ao-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "ao/t", MQTT_QOS_0, 0, "ao-1", 0) == 0, "publish 1");
    CHECK(cli_publish(&pub, "ao/t", MQTT_QOS_0, 0, "ao-2", 0) == 0, "publish 2");

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk1) == 0, "received 1");
    CHECK_EQ_INT(pk1.v.publish.topic_name.n, (size_t)strlen("ao/t"), "first has full topic");
    {
        mqtt_property_t *a1 = mqtt_properties_find(&pk1.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS);

        CHECK(a1 != 0, "first has topic alias property");
    }
    CHECK(strcmp(cli_publish_topic(&sub, &pk1), "ao/t") == 0, "topic 1");

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk2) == 0, "received 2");
    CHECK_EQ_INT(pk2.v.publish.topic_name.n, 0, "second uses empty topic");
    {
        mqtt_property_t *a2 = mqtt_properties_find(&pk2.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS);
        mqtt_property_t *a1 = mqtt_properties_find(&pk1.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS);

        CHECK(a2 != 0, "second has topic alias property");
        CHECK(a1 && a2 && a1->b2 == a2->b2, "same alias as first");
    }
    CHECK(strcmp(cli_publish_topic(&sub, &pk2), "ao/t") == 0, "topic 2 resolved");
    mqtt_packet_cleanup(&pk1);
    mqtt_packet_cleanup(&pk2);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_alias_range(void) {
    cli_t pub, sub;
    mqtt_packet_t ca, sa, pk, ack;
    uint16_t alias = 2;
    uint16_t id = 0;
    const char *f[] = {"ar/t"};
    uint8_t o[] = {0};

    test_begin("v5 topic alias above maximum -> PUBACK 0x94 + disconnect");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "ar-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    /* publisher advertises Topic Alias Maximum = 1, then uses alias 2 */
    CHECK(cli_connect(&pub, "ar-pub", 1, 60, 0, 0, 0, 0, 1, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);

    {
        mqtt_packet_t pubpkt;

        mqtt_packet_init(&pubpkt, MQTT_VERSION_5, MQTT_PUBLISH);
        pubpkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_1, 0);
        pubpkt.v.publish.packet_id = cli_next_id(&pub);
        mqtt_str_from(&pubpkt.v.publish.topic_name, "ar/t");
        mqtt_str_from(&pubpkt.p.publish.message, "bad-alias");
        mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS, &alias, NULL);
        id = pubpkt.v.publish.packet_id;
        CHECK(cli_send_pkt(&pub, &pubpkt) == 0, "publish out-of-range alias");
    }
    CHECK(cli_wait(&pub, MQTT_PUBACK, 3000, &ack) == 0, "puback");
    CHECK_EQ_INT(ack.v.puback.packet_id, id, "puback id");
    CHECK_EQ_INT(ack.v.puback.v5.reason_code, MQTT_RC_TOPIC_ALIAS_INVALID, "puback 0x94");
    mqtt_packet_cleanup(&ack);
    CHECK(cli_wait(&pub, MQTT_PUBLISH, 2000, &pk) == -2, "broker closes the connection");
    cli_close(&pub);
    cli_close(&sub);
    test_end();
}

static void
test_v5_alias_unknown(void) {
    cli_t pub, sub;
    mqtt_packet_t ca, sa, pk, ack;
    uint16_t alias = 9;
    uint16_t id = 0;
    const char *f[] = {"au/t"};
    uint8_t o[] = {0};

    test_begin("v5 unknown topic alias (empty topic) -> PUBACK 0x94 + disconnect");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "au-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "au-pub", 1, 60, 0, 0, 0, 0, 10, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);

    {
        mqtt_packet_t pubpkt;

        mqtt_packet_init(&pubpkt, MQTT_VERSION_5, MQTT_PUBLISH);
        pubpkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_1, 0);
        pubpkt.v.publish.packet_id = cli_next_id(&pub);
        mqtt_str_from(&pubpkt.p.publish.message, "unknown-alias");
        mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS, &alias, NULL);
        id = pubpkt.v.publish.packet_id;
        CHECK(cli_send_pkt(&pub, &pubpkt) == 0, "publish unknown alias");
    }
    CHECK(cli_wait(&pub, MQTT_PUBACK, 3000, &ack) == 0, "puback");
    CHECK_EQ_INT(ack.v.puback.packet_id, id, "puback id");
    CHECK_EQ_INT(ack.v.puback.v5.reason_code, MQTT_RC_TOPIC_ALIAS_INVALID, "puback 0x94");
    mqtt_packet_cleanup(&ack);
    CHECK(cli_wait(&pub, MQTT_PUBLISH, 2000, &pk) == -2, "broker closes the connection");
    cli_close(&pub);
    cli_close(&sub);
    test_end();
}

/* ---------------- C. will & sessions ---------------- */

static void
test_will_immediate(void) {
    cli_t sub, dead;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"will/t"};
    uint8_t o[] = {0};

    test_begin("v5 will published on abnormal close (no delay)");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "will-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&dead, g_port_main, MQTT_VERSION_5) == 0, "dead open");
    CHECK(cli_connect(&dead, "will-dead", 1, 60, 0, 0, 0, 0, 0, "will/t", "i-am-dead", MQTT_QOS_1, 0, &ca) == 0,
          "dead connack");
    mqtt_packet_cleanup(&ca);
    cli_close(&dead); /* abnormal close -> will */

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 4000, &pk) == 0, "will delivered");
    CHECK(strcmp(cli_publish_topic(&sub, &pk), "will/t") == 0, "will topic");
    CHECK(payload_eq(&pk, "i-am-dead"), "will payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    test_end();
}

static void
test_will_delayed(void) {
    cli_t sub, dead;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"wd/t"};
    uint8_t o[] = {0};

    test_begin("v5 will delay: held back, then published");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "wd-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&dead, g_port_main, MQTT_VERSION_5) == 0, "dead open");
    /* persistent session + will delay 2s */
    CHECK(cli_connect(&dead, "wd-dead", 0, 60, 0, 0, 0, 0, 0, "wd/t", "delayed-will", MQTT_QOS_1, 2, &ca) == 0,
          "dead connack");
    mqtt_packet_cleanup(&ca);
    cli_close(&dead); /* abnormal close -> delayed will */

    /* the blocking recv times out after 1s, so a "1200ms" wait can actually
     * run ~2.2s; keep the negative window below (delay - recv slack) */
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 800, &pk) == -1, "will not published before delay");
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 4000, &pk) == 0, "will published after delay");
    CHECK(payload_eq(&pk, "delayed-will"), "will payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    test_end();
}

static void
test_will_cancelled(void) {
    cli_t sub, c;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"wc/t"};
    uint8_t o[] = {0};

    test_begin("v5 clean DISCONNECT cancels the will");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "wc-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&c, g_port_main, MQTT_VERSION_5) == 0, "c open");
    CHECK(cli_connect(&c, "wc-cli", 1, 60, 0, 0, 0, 0, 0, "wc/t", "should-not-appear", MQTT_QOS_1, 0, &ca) == 0,
          "c connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_disconnect5(&c, MQTT_RC_NORMAL_DISCONNECTION, 0, 0) == 0, "clean disconnect");
    msleep(300);
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 1500, &pk) == -1, "no will after clean disconnect");
    cli_close(&sub);
    cli_close(&c);
    test_end();
}

static void
test_offline_queue(void) {
    cli_t a, b;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"off/t"};
    uint8_t o[] = {MQTT_QOS_1};
    int got = 0;

    test_begin("v5 persistent session: offline queue delivered on reconnect");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, "off-a", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&a, 1, f, o, 0, 0) == 0, "a subscribe");
    CHECK(cli_wait(&a, MQTT_SUBACK, 3000, &sa) == 0, "a suback");
    mqtt_packet_cleanup(&sa);
    cli_close(&a); /* abnormal close, session kept */

    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, "off-b", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    mqtt_packet_cleanup(&ca);
    for (int i = 0; i < 3; i++) {
        char msg[16];
        uint16_t id = 0;
        mqtt_packet_t ack;

        snprintf(msg, sizeof(msg), "offline-%d", i);
        CHECK(cli_publish(&b, "off/t", MQTT_QOS_1, 0, msg, &id) == 0, "publish");
        CHECK(cli_wait(&b, MQTT_PUBACK, 3000, &ack) == 0, "puback");
        mqtt_packet_cleanup(&ack);
    }
    cli_close(&b);

    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a reopen");
    CHECK(cli_connect(&a, "off-a", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "session present");
    mqtt_packet_cleanup(&ca);
    for (;;) {
        int rc = cli_wait(&a, MQTT_PUBLISH, 1500, &pk);

        if (rc != 0) {
            break;
        }
        got++;
        mqtt_packet_cleanup(&pk);
    }
    CHECK_EQ_INT(got, 3, "all queued messages delivered");
    cli_close(&a);
    test_end();
}

static void
test_session_expiry(void) {
    cli_t a, b;
    mqtt_packet_t ca;

    test_begin("v5 session expiry: session gone after the interval");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, "exp-a", 0, 60, 0, 0, 2, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack (expiry 2s)");
    mqtt_packet_cleanup(&ca);
    cli_close(&a);

    msleep(3500); /* let the session expire */

    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, "exp-a", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 0, "session expired");
    mqtt_packet_cleanup(&ca);
    cli_close(&b);
    test_end();
}

static void
test_session_expiry_keep(void) {
    cli_t a, b;
    mqtt_packet_t ca;

    test_begin("v5 session expiry: reconnect within the interval keeps the session");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, "exp-b", 0, 60, 0, 0, 5, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack (expiry 5s)");
    mqtt_packet_cleanup(&ca);
    cli_close(&a);

    msleep(1000);
    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, "exp-b", 0, 60, 0, 0, 5, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "session kept");
    mqtt_packet_cleanup(&ca);
    cli_close(&b);
    test_end();
}

/* ---------------- D. limits, $SYS, WS, persistence ---------------- */

static void
test_rate_limit(void) {
    cli_t cli;
    mqtt_packet_t ca, dc;

    test_begin("rate limit: v5 client disconnected with 0x97");
    CHECK(cli_open(&cli, g_port_rate, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "rate-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    /* limit is 2 msg/s: the 3rd publish in the same window trips it */
    CHECK(cli_publish(&cli, "rl/t", MQTT_QOS_0, 0, "1", 0) == 0, "pub 1");
    CHECK(cli_publish(&cli, "rl/t", MQTT_QOS_0, 0, "2", 0) == 0, "pub 2");
    CHECK(cli_publish(&cli, "rl/t", MQTT_QOS_0, 0, "3", 0) == 0, "pub 3");
    CHECK(cli_wait(&cli, MQTT_DISCONNECT, 3000, &dc) == 0, "disconnect");
    CHECK_EQ_INT(dc.v.disconnect.v5.reason_code, MQTT_RC_QUOTA_EXCEEDED, "reason 0x97");
    mqtt_packet_cleanup(&dc);
    cli_close(&cli);
    test_end();
}

static void
test_sys_topics(void) {
    cli_t cli;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"$SYS/#"};
    uint8_t o[] = {0};

    test_begin("$SYS topics published on interval");
    CHECK(cli_open(&cli, g_port_sys, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "sys-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&cli, 1, f, o, 0, 0) == 0, "subscribe $SYS/#");
    CHECK(cli_wait(&cli, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_wait(&cli, MQTT_PUBLISH, 4000, &pk) == 0, "sys message");
    CHECK(pk.v.publish.topic_name.n > 12 &&
              strncmp(pk.v.publish.topic_name.s, "$SYS/broker/", 12) == 0,
          "topic prefix");
    CHECK(pk.p.publish.message.n > 0, "non-empty payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&cli);
    test_end();
}

static void
test_ws(void) {
    wscli_t wsa, wsb;
    int rc;

    test_begin("websocket listener: mqtt over ws (handshake + pub/sub)");
    CHECK(ws_connect(&wsa, g_port_ws) == 0, "ws handshake a");
    CHECK(ws_connect(&wsb, g_port_ws) == 0, "ws handshake b");

    /* CONNECT through the ws frames */
    {
        mqtt_packet_t pkt;
        mqtt_str_t b = MQTT_STR_INITIALIZER;

        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_CONNECT);
        pkt.v.connect.connect_flags |= MQTT_CF_CLEAN_SESSION;
        pkt.v.connect.keep_alive = 60;
        mqtt_str_from(&pkt.p.connect.client_id, "ws-a");
        CHECK(mqtt_serialize(&pkt, &b) == 0, "serialize connect a");
        CHECK(ws_send_frame(&wsa, 0x2, b.s, b.n) == 0, "send connect a");
        mqtt_str_free(&b);
        mqtt_packet_cleanup(&pkt);

        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_CONNECT);
        pkt.v.connect.connect_flags |= MQTT_CF_CLEAN_SESSION;
        pkt.v.connect.keep_alive = 60;
        mqtt_str_from(&pkt.p.connect.client_id, "ws-b");
        CHECK(mqtt_serialize(&pkt, &b) == 0, "serialize connect b");
        CHECK(ws_send_frame(&wsb, 0x2, b.s, b.n) == 0, "send connect b");
        mqtt_str_free(&b);
        mqtt_packet_cleanup(&pkt);
    }

    /* CONNACKs */
    {
        size_t plen;
        mqtt_parser_t pa, pb;
        mqtt_packet_t pka, pkb;

        mqtt_parser_init(&pa);
        mqtt_parser_version(&pa, MQTT_VERSION_5);
        mqtt_parser_init(&pb);
        mqtt_parser_version(&pb, MQTT_VERSION_5);

        CHECK(ws_wait_frame(&wsa, &plen, 3000) == 0x2, "connack frame a");
        {
            mqtt_str_t in = {.s = wsa.payload, .n = plen};

            CHECK(mqtt_parse(&pa, &in, &pka) == 1, "parse connack a");
            CHECK_EQ_INT(pka.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "connack a");
            mqtt_packet_cleanup(&pka);
        }
        CHECK(ws_wait_frame(&wsb, &plen, 3000) == 0x2, "connack frame b");
        {
            mqtt_str_t in = {.s = wsb.payload, .n = plen};

            CHECK(mqtt_parse(&pb, &in, &pkb) == 1, "parse connack b");
            CHECK_EQ_INT(pkb.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "connack b");
            mqtt_packet_cleanup(&pkb);
        }
    }

    /* a subscribes over ws, b publishes over ws */
    {
        mqtt_packet_t pkt;
        mqtt_str_t b = MQTT_STR_INITIALIZER;
        size_t plen;
        uint16_t pid;

        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_SUBSCRIBE);
        pid = 1;
        pkt.v.subscribe.packet_id = pid;
        CHECK(mqtt_subscribe_generate(&pkt, 1) == 0, "gen subscribe");
        mqtt_str_from(&pkt.p.subscribe.topic_filters[0], "ws/t");
        pkt.p.subscribe.options[0].flags = 0;
        CHECK(mqtt_serialize(&pkt, &b) == 0, "serialize subscribe");
        CHECK(ws_send_frame(&wsa, 0x2, b.s, b.n) == 0, "send subscribe");
        mqtt_str_free(&b);
        mqtt_packet_cleanup(&pkt);

        CHECK(ws_wait_frame(&wsa, &plen, 3000) == 0x2, "suback frame");
        {
            mqtt_parser_t pa;
            mqtt_packet_t pka;
            mqtt_str_t in;

            mqtt_parser_init(&pa);
            mqtt_parser_version(&pa, MQTT_VERSION_5);
            mqtt_str_init(&in, wsa.payload, plen);
            CHECK(mqtt_parse(&pa, &in, &pka) == 1, "parse suback");
            CHECK_EQ_INT(pka.v.suback.packet_id, pid, "suback id");
            mqtt_packet_cleanup(&pka);
        }

        /* b publishes */
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBLISH);
        pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_0, 0);
        mqtt_str_from(&pkt.v.publish.topic_name, "ws/t");
        mqtt_str_from(&pkt.p.publish.message, "over-ws");
        CHECK(mqtt_serialize(&pkt, &b) == 0, "serialize publish");
        CHECK(ws_send_frame(&wsb, 0x2, b.s, b.n) == 0, "send publish");
        mqtt_str_free(&b);
        mqtt_packet_cleanup(&pkt);

        CHECK(ws_wait_frame(&wsa, &plen, 3000) == 0x2, "publish frame");
        {
            mqtt_parser_t pa;
            mqtt_packet_t pka;
            mqtt_str_t in;

            mqtt_parser_init(&pa);
            mqtt_parser_version(&pa, MQTT_VERSION_5);
            mqtt_str_init(&in, wsa.payload, plen);
            CHECK(mqtt_parse(&pa, &in, &pka) == 1, "parse publish");
            CHECK_EQ_INT(MQTT_FH_TYPE(pka.f.flags), MQTT_PUBLISH, "is publish");
            CHECK(payload_eq(&pka, "over-ws"), "payload");
            mqtt_packet_cleanup(&pka);
        }
    }

    /* ws ping -> pong */
    {
        size_t plen;

        CHECK(ws_send_frame(&wsa, 0x9, "hb", 2) == 0, "ws ping");
        rc = ws_wait_frame(&wsa, &plen, 3000);
        CHECK(rc == 0xa, "ws pong");
    }
    if (wsa.net) {
        network_tcp_close(wsa.net);
    }
    if (wsb.net) {
        network_tcp_close(wsb.net);
    }
    test_end();
}

static void
test_persistence(void) {
    cli_t a, b, c;
    mqtt_packet_t ca, sa, pk;
    const char *f[] = {"p/t"};
    uint8_t o[] = {MQTT_QOS_1};
    int got = 0;

    test_begin("persistence: retained + offline queue survive a restart");
    /* a subscribes, then goes offline */
    CHECK(cli_open(&a, g_port_persist, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, "p-a", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&a, 1, f, o, 0, 0) == 0, "a subscribe");
    CHECK(cli_wait(&a, MQTT_SUBACK, 3000, &sa) == 0, "a suback");
    mqtt_packet_cleanup(&sa);
    cli_close(&a);

    /* b publishes one offline message + one retained */
    CHECK(cli_open(&b, g_port_persist, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, "p-b", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    mqtt_packet_cleanup(&ca);
    {
        uint16_t id = 0;
        mqtt_packet_t ack;

        CHECK(cli_publish(&b, "p/t", MQTT_QOS_1, 0, "offline-kept", &id) == 0, "publish offline");
        CHECK(cli_wait(&b, MQTT_PUBACK, 3000, &ack) == 0, "puback");
        mqtt_packet_cleanup(&ack);
    }
    CHECK(cli_publish(&b, "p/t", MQTT_QOS_0, 1, "retained-kept", 0) == 0, "publish retained");
    cli_close(&b);

    msleep(1500); /* let the 1s persist tick fire */
    broker_stop(g_pid_persist);
    g_pid_persist = 0;

    /* restart with the same persist file */
    {
        char ini[1024];

        snprintf(ini, sizeof(ini),
                 "[log]\nlevel=warn\n[net]\nhost=127.0.0.1\nport=%d\n"
                 "[persist]\nfile=%s/persist.txt\n",
                 g_port_persist, g_tmpdir);
        g_pid_persist = broker_start(g_port_persist, ini);
    }

    /* a reconnects: offline message is redelivered */
    CHECK(cli_open(&a, g_port_persist, MQTT_VERSION_5) == 0, "a reopen");
    CHECK(cli_connect(&a, "p-a", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "session present");
    mqtt_packet_cleanup(&ca);
    for (;;) {
        int rc = cli_wait(&a, MQTT_PUBLISH, 1500, &pk);

        if (rc != 0) {
            break;
        }
        if (payload_eq(&pk, "offline-kept")) {
            got++;
        }
        mqtt_packet_cleanup(&pk);
    }
    CHECK_EQ_INT(got, 1, "offline message survived restart");
    cli_close(&a);

    /* new subscriber receives the retained message */
    CHECK(cli_open(&c, g_port_persist, MQTT_VERSION_5) == 0, "c open");
    CHECK(cli_connect(&c, "p-c", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "c connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&c, 1, f, o, 0, 0) == 0, "c subscribe");
    CHECK(cli_wait(&c, MQTT_SUBACK, 3000, &sa) == 0, "c suback");
    mqtt_packet_cleanup(&sa);
    /* the retained message may have arrived before the SUBACK */
    CHECK(cli_next_publish(&c, &pk, 3000) == 0, "retained delivered");
    CHECK_EQ_INT(MQTT_FH_RETAIN(pk.f.flags), 1, "retain flag");
    CHECK(payload_eq(&pk, "retained-kept"), "retained payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&c);
    test_end();
}

/* ================================================================== */
/* v5 protocol edge cases                                              */
/* ================================================================== */

static void
test_v5_client_id_too_long(void) {
    cli_t cli;
    mqtt_packet_t ca;

    test_begin("v5 client id longer than 23 chars -> CONNACK 0x85");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "abcdefghijklmnopqrstuvwx", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_CLIENT_IDENTIFIER_NOT_VALID, "reason 0x85");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_v5_assigned_client_id(void) {
    cli_t cli;
    mqtt_packet_t ca;
    mqtt_property_t *prop;

    test_begin("v5 empty client id -> CONNACK carries ASSIGNED_CLIENT_IDENTIFIER");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    CHECK_EQ_INT(ca.v.connack.v5.reason_code, MQTT_RC_SUCCESS, "reason");
    prop = mqtt_properties_find(&ca.v.connack.v5.properties, MQTT_PROPERTY_ASSIGNED_CLIENT_IDENTIFIER);
    CHECK(prop != 0, "assigned client id property present");
    CHECK(prop && prop->str.n > 0, "assigned client id non-empty");
    mqtt_packet_cleanup(&ca);
    cli_close(&cli);
    test_end();
}

static void
test_v5_bad_protocol_name(void) {
    cli_t cli;
    mqtt_packet_t ca;
    static const unsigned char pkt[] = {
        0x10, 0x11,
        0x00, 0x04, 'M', 'Q', 'T', 'T', 'F', /* protocol name "MQTTF" */
        0x05, 0x02, 0x00, 0x3C,               /* level 5, clean, keepalive 60 */
        0x00, 0x05, 'a', 'b', 'c', 'd', 'e'};

    test_begin("v5 CONNECT with bad protocol name -> connection closed");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_send_raw(&cli, (const char *)pkt, sizeof pkt) == 0, "send");
    CHECK(cli_wait(&cli, MQTT_CONNACK, 2500, &ca) == -2, "no connack, connection closed");
    cli_close(&cli);
    test_end();
}

static void
test_v5_bad_protocol_level(void) {
    cli_t cli;
    mqtt_packet_t ca;
    static const unsigned char pkt[] = {
        0x10, 0x11,
        0x00, 0x04, 'M', 'Q', 'T', 'T', /* protocol name "MQTT" */
        0x03, 0x02, 0x00, 0x3C,         /* level 3: unsupported */
        0x00, 0x05, 'a', 'b', 'c', 'd', 'e'};

    test_begin("v5 CONNECT with unsupported protocol level -> connection closed");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_send_raw(&cli, (const char *)pkt, sizeof pkt) == 0, "send");
    CHECK(cli_wait(&cli, MQTT_CONNACK, 2500, &ca) == -2, "no connack, connection closed");
    cli_close(&cli);
    test_end();
}

static void
test_v5_invalid_publish_topic(void) {
    cli_t cli;
    mqtt_packet_t ca, pk;
    /* PUBLISH QoS1, topic "bad/#/topic" (wildcards are invalid in a topic
     * name), packet id 1, no properties, payload "x". Sent raw: the client
     * serializer refuses to build such a packet. */
    static const unsigned char pkt[] = {
        0x32, 0x11,
        0x00, 0x0B, 'b', 'a', 'd', '/', '#', '/', 't', 'o', 'p', 'i', 'c',
        0x00, 0x01,
        0x00, /* no properties */
        'x'};

    test_begin("v5 PUBLISH with invalid topic name -> PUBACK 0x90 + disconnect");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "badtopic-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_send_raw(&cli, (const char *)pkt, sizeof pkt) == 0, "publish");
    CHECK(cli_wait(&cli, MQTT_PUBACK, 3000, &pk) == 0, "puback");
    CHECK_EQ_INT(pk.v.puback.v5.reason_code, MQTT_RC_TOPIC_NAME_INVALID, "reason 0x90");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_wait(&cli, MQTT_PUBLISH, 1500, &pk) == -2, "connection closed");
    cli_close(&cli);
    test_end();
}

static void
test_v5_duplicate_publish(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk, pkt;
    const char *f[] = {"dup/t"};
    uint8_t o[] = {MQTT_QOS_2};
    uint16_t id = 0;

    test_begin("v5 duplicate QoS2 PUBLISH (same id, dup=1) -> re-acked, not re-delivered");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "dup-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "dup-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "dup/t", MQTT_QOS_2, 0, "first", &id) == 0, "publish");
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "delivered once");
    CHECK(payload_eq(&pk, "first"), "payload");
    mqtt_packet_cleanup(&pk);

    /* hold the incoming publication in the REL state: do not let the client
     * answer the PUBREC (as if the PUBREC was lost) */
    pub.no_ack = 1;
    CHECK(cli_wait(&pub, MQTT_PUBREC, 3000, &pk) == 0, "pubrec");
    mqtt_packet_cleanup(&pk);

    /* retransmit the same PUBLISH (same id, dup=1): the broker must not
     * re-dispatch it, only re-send the PUBREC */
    mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBLISH);
    pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, MQTT_QOS_2, 0);
    pkt.v.publish.packet_id = id;
    mqtt_str_from(&pkt.v.publish.topic_name, "dup/t");
    mqtt_str_from(&pkt.p.publish.message, "first");
    CHECK(cli_send_pkt(&pub, &pkt) == 0, "duplicate publish");
    CHECK(cli_wait(&pub, MQTT_PUBREC, 3000, &pk) == 0, "re-acked (pubrec again)");
    mqtt_packet_cleanup(&pk);
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 1500, &pk) == -1, "not re-delivered");

    /* complete the QoS2 flow */
    pub.no_ack = 0;
    mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBREL);
    pkt.v.pubrel.packet_id = id;
    CHECK(cli_send_pkt(&pub, &pkt) == 0, "pubrel");
    CHECK(cli_wait(&pub, MQTT_PUBCOMP, 3000, &pk) == 0, "pubcomp");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_qos1_redelivery_dup(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk, pr;
    const char *f[] = {"redel/t"};
    uint8_t o[] = {MQTT_QOS_1};

    test_begin("v5 unacked QoS1 PUBLISH is retransmitted with dup=1");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "redel-sub", 1, 6, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "redel-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "redel/t", MQTT_QOS_1, 0, "redel", 0) == 0, "publish");

    /* first delivery: received but deliberately not acked */
    sub.no_ack = 1;
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "first delivery");
    CHECK_EQ_INT(MQTT_FH_DUP(pk.f.flags), 0, "first: no dup");
    mqtt_packet_cleanup(&pk);

    /* refresh the keepalive so the broker keeps us until the retransmit */
    CHECK(cli_ping(&sub) == 0, "ping");
    CHECK(cli_wait(&sub, MQTT_PINGRESP, 3000, &pr) == 0, "pong");
    mqtt_packet_cleanup(&pr);

    /* keep_alive=6: the broker retransmits after the interval, with dup=1 */
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 10000, &pk) == 0, "retransmission");
    CHECK_EQ_INT(MQTT_FH_DUP(pk.f.flags), 1, "dup flag set");
    CHECK(payload_eq(&pk, "redel"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_sub_id_max(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk;
    mqtt_property_t *prop;
    const char *f[] = {"bigsid/t"};
    uint8_t o[] = {MQTT_QOS_0};

    /* 0x0FFFFFFF is the largest value a variable byte integer can carry */
    test_begin("v5 subscription identifier at the max VBI value is used");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "bigsid-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0x0FFFFFFFu, 0) == 0, "subscribe (sub id 0x0FFFFFFF)");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    CHECK_EQ_INT(suback_rc5(&sa, 0), MQTT_RC_SUCCESS, "granted");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "bigsid-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_publish(&pub, "bigsid/t", MQTT_QOS_0, 0, "big", 0) == 0, "publish");
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received");
    prop = mqtt_properties_find(&pk.v.publish.v5.properties, MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER);
    CHECK(prop != 0, "sub id on delivery");
    CHECK(prop && prop->bv == 0x0FFFFFFFu, "sub id value");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_pubrel_unknown_id(void) {
    cli_t cli;
    mqtt_packet_t ca, pkt, comp;

    test_begin("v5 PUBREL with unknown packet id -> PUBCOMP 0x92");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "pubrel-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBREL);
    pkt.v.pubrel.packet_id = 999;
    CHECK(cli_send_pkt(&cli, &pkt) == 0, "pubrel");
    CHECK(cli_wait(&cli, MQTT_PUBCOMP, 3000, &comp) == 0, "pubcomp");
    CHECK_EQ_INT(comp.v.pubcomp.v5.reason_code, MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND, "reason 0x92");
    mqtt_packet_cleanup(&comp);
    cli_close(&cli);
    test_end();
}

static void
test_v5_puback_unknown_id(void) {
    cli_t cli;
    mqtt_packet_t ca, pkt, pr;

    test_begin("v5 PUBACK with unknown packet id is ignored");
    CHECK(cli_open(&cli, g_port_main, MQTT_VERSION_5) == 0, "open");
    CHECK(cli_connect(&cli, "puback-cli", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "connack");
    mqtt_packet_cleanup(&ca);
    mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBACK);
    pkt.v.puback.packet_id = 999;
    CHECK(cli_send_pkt(&cli, &pkt) == 0, "puback");
    /* connection must stay usable */
    CHECK(cli_ping(&cli) == 0, "ping");
    CHECK(cli_wait(&cli, MQTT_PINGRESP, 3000, &pr) == 0, "pong");
    mqtt_packet_cleanup(&pr);
    cli_close(&cli);
    test_end();
}

static void
test_v5_disconnect_session_expiry(void) {
    cli_t a, b;
    mqtt_packet_t ca;

    test_begin("v5 DISCONNECT session expiry: kept in the window, gone after");
    CHECK(cli_open(&a, g_port_main, MQTT_VERSION_5) == 0, "a open");
    CHECK(cli_connect(&a, "dse-a", 0, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "a connack");
    mqtt_packet_cleanup(&ca);
    /* set a 2s session expiry on the way out */
    {
        mqtt_packet_t pkt;
        uint32_t v4 = 2;

        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_DISCONNECT);
        mqtt_properties_add(&pkt.v.disconnect.v5.properties, MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL, &v4, NULL);
        CHECK(cli_send_pkt(&a, &pkt) == 0, "disconnect with expiry 2s");
    }
    msleep(1000);
    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b open");
    CHECK(cli_connect(&b, "dse-a", 0, 60, 0, 0, 2, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 1, "session kept in window");
    mqtt_packet_cleanup(&ca);
    cli_close(&b);

    msleep(3000); /* past the 2s expiry */
    CHECK(cli_open(&b, g_port_main, MQTT_VERSION_5) == 0, "b reopen");
    CHECK(cli_connect(&b, "dse-a", 0, 60, 0, 0, 2, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "b connack 2");
    CHECK_EQ_INT(ca.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT, 0, "session expired");
    mqtt_packet_cleanup(&ca);
    cli_close(&b);
    cli_close(&a);
    test_end();
}

static void
test_v5_will_retain(void) {
    cli_t sub, pub, sub2;
    mqtt_packet_t ca, sa, pk, conn;
    const char *f[] = {"wrt/t"};
    uint8_t o[] = {0};

    test_begin("v5 will with retain=1 is stored as retained");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "wrt-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    /* connect with a retained will (custom CONNECT: will retain flag) */
    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    {
        mqtt_packet_t pkt;
        int rc;

        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_CONNECT);
        pkt.v.connect.connect_flags |= MQTT_CF_CLEAN_SESSION | MQTT_CF_WILL_FLAG | MQTT_CF_WILL_RETAIN |
                                       ((uint8_t)MQTT_QOS_1 << 3);
        pkt.v.connect.keep_alive = 60;
        mqtt_str_from(&pkt.p.connect.client_id, "wrt-pub");
        mqtt_str_from(&pkt.p.connect.will_topic, "wrt/t");
        mqtt_str_from(&pkt.p.connect.will_message, "wrt-will");
        rc = cli_send_pkt(&pub, &pkt);
        CHECK(rc == 0, "connect with retained will");
        CHECK(cli_wait(&pub, MQTT_CONNACK, 3000, &conn) == 0, "connack");
        mqtt_packet_cleanup(&conn);
    }
    cli_close(&pub); /* abnormal close: the will fires */

    /* existing subscriber: live delivery (retain flag cleared) */
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "will delivered");
    CHECK_EQ_INT(MQTT_FH_RETAIN(pk.f.flags), 0, "live delivery: retain cleared");
    CHECK(payload_eq(&pk, "wrt-will"), "payload");
    mqtt_packet_cleanup(&pk);

    /* a fresh subscriber receives it as a retained message */
    CHECK(cli_open(&sub2, g_port_main, MQTT_VERSION_5) == 0, "sub2 open");
    CHECK(cli_connect(&sub2, "wrt-sub2", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub2 connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub2, 1, f, o, 0, 0) == 0, "sub2 subscribe");
    CHECK(cli_wait(&sub2, MQTT_SUBACK, 3000, &sa) == 0, "sub2 suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_next_publish(&sub2, &pk, 3000) == 0, "retained delivered to new sub");
    CHECK_EQ_INT(MQTT_FH_RETAIN(pk.f.flags), 1, "retained: retain flag set");
    CHECK(payload_eq(&pk, "wrt-will"), "retained payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&sub2);
    test_end();
}

static void
test_v5_retained_expiry(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk, pubpkt;
    const char *f[] = {"rexp/t"};
    uint8_t o[] = {0};
    uint32_t expiry = 2;

    test_begin("v5 retained message with message expiry is not delivered after it lapses");
    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "rexp-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);

    mqtt_packet_init(&pubpkt, MQTT_VERSION_5, MQTT_PUBLISH);
    pubpkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_0, 1);
    mqtt_str_from(&pubpkt.v.publish.topic_name, "rexp/t");
    mqtt_str_from(&pubpkt.p.publish.message, "rexp-hello");
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL, &expiry, NULL);
    CHECK(cli_send_pkt(&pub, &pubpkt) == 0, "publish retained (expiry 2s)");

    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "rexp-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_next_publish(&sub, &pk, 3000) == 0, "retained delivered before expiry");
    CHECK(payload_eq(&pk, "rexp-hello"), "payload");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);

    msleep(3000); /* past the 2s message expiry */

    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub reopen");
    CHECK(cli_connect(&sub, "rexp-sub2", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub2 connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "sub2 subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "sub2 suback");
    mqtt_packet_cleanup(&sa);
    CHECK(cli_wait(&sub, MQTT_PUBLISH, 1500, &pk) == -1, "no retained after expiry");
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

static void
test_v5_multi_user_props(void) {
    cli_t sub, pub;
    mqtt_packet_t ca, sa, pk, pubpkt;
    const char *f[] = {"mup/t"};
    uint8_t o[] = {0};

    test_begin("v5 multiple user properties are passed through");
    CHECK(cli_open(&sub, g_port_main, MQTT_VERSION_5) == 0, "sub open");
    CHECK(cli_connect(&sub, "mup-sub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "sub connack");
    mqtt_packet_cleanup(&ca);
    CHECK(cli_subscribe(&sub, 1, f, o, 0, 0) == 0, "subscribe");
    CHECK(cli_wait(&sub, MQTT_SUBACK, 3000, &sa) == 0, "suback");
    mqtt_packet_cleanup(&sa);

    CHECK(cli_open(&pub, g_port_main, MQTT_VERSION_5) == 0, "pub open");
    CHECK(cli_connect(&pub, "mup-pub", 1, 60, 0, 0, 0, 0, 0, 0, 0, MQTT_QOS_0, 0, &ca) == 0, "pub connack");
    mqtt_packet_cleanup(&ca);

    mqtt_packet_init(&pubpkt, MQTT_VERSION_5, MQTT_PUBLISH);
    pubpkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_0, 0);
    mqtt_str_from(&pubpkt.v.publish.topic_name, "mup/t");
    mqtt_str_from(&pubpkt.p.publish.message, "mup-payload");
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_USER_PROPERTY, "v1", "k1");
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_USER_PROPERTY, "v2", "k2");
    mqtt_properties_add(&pubpkt.v.publish.v5.properties, MQTT_PROPERTY_USER_PROPERTY, "v3", "k3");
    CHECK(cli_send_pkt(&pub, &pubpkt) == 0, "publish with 3 user props");

    CHECK(cli_wait(&sub, MQTT_PUBLISH, 3000, &pk) == 0, "received");
    CHECK(prop_user_eq(&pk.v.publish.v5.properties, "k1", "v1"), "user prop 1");
    CHECK(prop_user_eq(&pk.v.publish.v5.properties, "k2", "v2"), "user prop 2");
    CHECK(prop_user_eq(&pk.v.publish.v5.properties, "k3", "v3"), "user prop 3");
    mqtt_packet_cleanup(&pk);
    cli_close(&sub);
    cli_close(&pub);
    test_end();
}

/* ================================================================== */

static void
on_fatal_signal(int sig) {
    /* do not leave broker children behind when the suite dies */
    broker_stop_all();
    signal(sig, SIG_DFL);
    raise(sig);
}

int
main(int argc, char *argv[]) {
    int base = 18831 + (int)(getpid() % 2000); /* unique per run: no port clashes */

    if (argc > 1) {
        base = atoi(argv[1]);
    }
    g_port_main = base;
    g_port_auth = base + 1;
    g_port_rate = base + 2;
    g_port_sys = base + 3;
    g_port_ws = base + 4;
    g_port_persist = base + 5;

    init_paths(base);
    fprintf(stderr, "mqtt_broker_test: broker=%s tmp=%s base_port=%d\n", g_broker_path, g_tmpdir, base);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_fatal_signal);
    signal(SIGINT, on_fatal_signal);
    signal(SIGSEGV, on_fatal_signal);
    signal(SIGABRT, on_fatal_signal);
    start_all_brokers();

    /* A. connection */
    test_v5_connack_caps();
    test_v5_empty_client_id();
    test_v5_session_present();
    test_v5_clean_session();
    test_v4_connack();
    test_auth();
    test_session_takeover();
    test_v5_ping();
    test_v5_auth_packet();
    test_v5_disconnect_props();
    test_non_connect_first();
    test_keepalive_timeout();

    /* B. pub/sub */
    test_v5_qos0();
    test_v5_qos1();
    test_v5_qos2();
    test_v5_qos_downgrade();
    test_v5_props_passthrough();
    test_v5_retained();
    test_v5_rap();
    test_v5_retain_handling();
    test_v5_no_local();
    test_v5_wildcards();
    test_v5_sub_id();
    test_v5_shared();
    test_v5_shared_malformed();
    test_v5_invalid_filter();
    test_v5_unsub_reasons();
    test_v5_unsub_invalid_filter();
    test_v5_alias_in();
    test_v5_alias_out();
    test_v5_alias_range();
    test_v5_alias_unknown();

    /* C. will & sessions */
    test_will_immediate();
    test_will_delayed();
    test_will_cancelled();
    test_offline_queue();
    test_session_expiry();
    test_session_expiry_keep();

    /* D. limits, $SYS, WS, persistence */
    test_rate_limit();
    test_sys_topics();
    test_ws();
    test_persistence();

    /* E. v5 protocol edge cases */
    test_v5_client_id_too_long();
    test_v5_assigned_client_id();
    test_v5_bad_protocol_name();
    test_v5_bad_protocol_level();
    test_v5_invalid_publish_topic();
    test_v5_duplicate_publish();
    test_v5_qos1_redelivery_dup();
    test_v5_sub_id_max();
    test_v5_pubrel_unknown_id();
    test_v5_puback_unknown_id();
    test_v5_disconnect_session_expiry();
    test_v5_will_retain();
    test_v5_retained_expiry();
    test_v5_multi_user_props();

    broker_stop_all();

    fprintf(stderr, "========================================\n");
    fprintf(stderr, "tests: %d (%d failed), checks: %d (%d failed)\n", g_tests, g_tests_failed, g_checks, g_checks_failed);
    fprintf(stderr, "========================================\n");
    return g_checks_failed ? 1 : 0;
}
