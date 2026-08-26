#define WSHTTP

#include "mqtt.h"
#include "snowflake.h"
#include "map.h"
#include "tls.h"
#include "websocket.h"
#include "uv.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/sha.h>

#define MQTT_ACL_ALL "*" /* ACL username wildcard = all users */

/* ================================================================== */
/* 连接模式                                                           */
/* ================================================================== */

typedef enum {
    MQTT_BROKER_MODE_TCP,
    MQTT_BROKER_MODE_TLS,
    MQTT_BROKER_MODE_WS,
    MQTT_BROKER_MODE_WSS
} mqtt_broker_mode_t;

/* ================================================================== */
/* Listener                                                           */
/* ================================================================== */

typedef struct mqtt_broker_listener_s mqtt_broker_listener_t;

struct mqtt_broker_listener_s {
    uv_tcp_t server;
    char *id;
    char *host;
    int port;
    mqtt_broker_mode_t mode;
    tls_ctx_t *tls_ctx;
    char *cert_file;
    char *key_file;
    char *auth_type; /* per-listener auth, NULL = broker-level */
    char *auth_api;
    map_node_t node;
};

/* ================================================================== */
/* 配置                                                               */
/* ================================================================== */

#define MQTT_BROKER_DEFAULT_PORT             1883
#define MQTT_BROKER_DEFAULT_MAX_CONN         4096
#define MQTT_BROKER_DEFAULT_RATE_LIMIT       0             /* 0 = 不限制 */
#define MQTT_BROKER_DEFAULT_HEARTBEAT_MS     1000

typedef struct {
    /* 网络 */
    const char *host;           /* 默认 "0.0.0.0" */
    int port;                   /* 默认 MQTT_BROKER_DEFAULT_PORT */
    int max_connections;        /* 默认 MQTT_BROKER_DEFAULT_MAX_CONN */
    int tls_enabled;            /* 默认 0 */
    const char *cert_file;      /* TLS 证书，NULL = 不需要 */
    const char *key_file;       /* TLS 私钥，NULL = 不需要 */

    /* 认证 */
    const char *auth_type;      /* "config" | "api" | NULL = 不认证 */
    const char *auth_api;       /* HTTP API URL */

    /* 日志 */
    const char *log_file;       /* NULL = 标准输出 */

    /* 速率限制 (msgs/sec per client, 0 = 不限) */
    int rate_limit;             /* 默认 MQTT_BROKER_DEFAULT_RATE_LIMIT */

    /* 用户表 (auth_type=config 用) */
    struct { const char *user; const char *pass; const char *client_id; } *users;
    int user_count;

    /* 预留 */
    uint32_t reserved;
    void *ud;                   /* 用户数据，传给认证回调 */

    /* Listeners */
    map_t listeners;
} mqtt_broker_config_t;

static inline void mqtt_broker_config_init(mqtt_broker_config_t *c) {
    memset(c, 0, sizeof(*c));
    c->host = "0.0.0.0";
    c->port = MQTT_BROKER_DEFAULT_PORT;
    c->max_connections = MQTT_BROKER_DEFAULT_MAX_CONN;
    c->rate_limit = MQTT_BROKER_DEFAULT_RATE_LIMIT;
}

/* ================================================================== */
/* 回调接口                                                           */
/* ================================================================== */

/* 认证回调 — 由调用者实现，返回 0=通过，非 0=拒绝 */
typedef int (*mqtt_broker_auth_callback_t)(const char *client_id, int client_id_len,
                                           const char *username, int username_len,
                                           const char *password, int password_len,
                                           void *ud);

/* ================================================================== */
/* 核心结构体 (opaque)                                                */
/* ================================================================== */

typedef struct mqtt_broker_s mqtt_broker_t;
typedef struct mqtt_client_s mqtt_client_t;
typedef struct mqtt_session_s mqtt_session_t;

/* ================================================================== */
/* 公共 API                                                           */
/* ================================================================== */

/* 生命周期 */
int mqtt_broker_create(mqtt_broker_config_t *config, uv_loop_t *loop, mqtt_broker_t *b);
int            mqtt_broker_start(mqtt_broker_t *b);
void           mqtt_broker_stop(mqtt_broker_t *b);
void           mqtt_broker_destroy(mqtt_broker_t *b);
int            mqtt_broker_run(mqtt_broker_t *b);

/* 事件注册 */
void mqtt_broker_set_auth_callback(mqtt_broker_t *b, mqtt_broker_auth_callback_t cb, void *ud);

#define MQTT_IMPL
#include "mqtt.h"

#define SNOWFLAKE_IMPL
#include "snowflake.h"

#define WEBSOCKET_IMPL
#include "websocket.h"

#define TLS_IMPL
#include "tls.h"

#define INI_IMPL
#include "ini.h"

#define LOG_IMPL
#include "log.h"

#define HTTP_IMPL
#define BASE64_IMPL
#define URLCODE_IMPL
#include "http.h"

#define MQTT_MEMPOOL_IMPL
#include "mqtt_mempool.h"

#include "map.h"
#include "queue.h"

#include "uv.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_DUMP(...) broker_log_dump(__VA_ARGS__)
#define LOG_PROP(...) broker_log_prop(__VA_ARGS__)

typedef enum {
    MQTT_PUBLICATION_STATE_ACK,
    MQTT_PUBLICATION_STATE_REC,
    MQTT_PUBLICATION_STATE_REL,
    MQTT_PUBLICATION_STATE_COMP,
} mqtt_publication_state_t;

typedef struct mqtt_client_s mqtt_client_t;
typedef struct mqtt_publication_s mqtt_publication_t;
typedef struct mqtt_subscription_s mqtt_subscription_t;
typedef struct mqtt_session_s mqtt_session_t;
typedef struct mqtt_message_s mqtt_message_t;
typedef struct mqtt_subscriber_s mqtt_subscriber_t;
typedef struct mqtt_trie_s mqtt_trie_t;
typedef struct mqtt_account_s mqtt_account_t;
typedef struct mqtt_broker_s mqtt_broker_t;
typedef struct mqtt_offline_msg_s mqtt_offline_msg_t;
typedef struct mqtt_alias_entry_s mqtt_alias_entry_t;
typedef struct mqtt_share_rr_s mqtt_share_rr_t;
typedef struct mqtt_acl_rule_s mqtt_acl_rule_t;

static void mqtt_subscriber_destroy(mqtt_subscriber_t *suber);
static void mqtt_trie_destroy_recursive(mqtt_trie_t *trie);
static void mqtt_broker_persist_mark(mqtt_broker_t *b);
static void mqtt_broker_persist_save(mqtt_broker_t *b);
static int  mqtt_broker_persist_load(mqtt_broker_t *b);

/* Protocol callbacks forward declarations */
static void _broker_ws_on_open(wshttp_t *wh, void *io, void *ud);
static void _broker_ws_on_data(wshttp_t *wh, void *io, void *ud, int opcode, websocket_binary_t payload);
static void _broker_ws_on_close(wshttp_t *wh, void *io, void *ud, websocket_binary_t payload);
static int _broker_ws_write(wshttp_t *wh, void *io, void *ud, const char *data, int size);
static void _broker_tls_on_open(tls_t *tls, void *io, void *ud);
static void _broker_tls_on_data(tls_t *tls, void *io, void *ud, const void *data, int size);
static void _broker_tls_on_close(tls_t *tls, void *io, void *ud);
static int _broker_tls_write(tls_t *tls, void *io, void *ud, const void *data, int size);
static void _broker_on_connection(uv_stream_t *server, int status);
static void _broker_on_signal(uv_signal_t *handle, int signum);

struct mqtt_client_s {
    uv_tcp_t *tcp;
    uv_shutdown_t shutdown;
    mqtt_parser_t parser;
    mqtt_str_t buff;
    char ip[INET6_ADDRSTRLEN];
    int port;
    uint64_t t_last;
    uint8_t clean_session;
    uint8_t ver;
    uint16_t keep_alive;
    int t_rate;          /* rate limit window (b->t_now) */
    int rate_count;      /* publish count in current window */
    size_t pending_write; /* bytes queued in uv_write (backpressure) */
    mqtt_str_t username; /* authenticated username (for ACL), empty if none */
    queue_t node;
    mqtt_session_t *s;
    mqtt_broker_t *b;
    int closed;
    /* per-listener auth (falls back to broker-level) */
    char *auth_type;
    char *auth_api;
    /* async HTTP auth state */
    int auth_pending;
    uv_tcp_t *auth_tcp;
    uv_connect_t auth_connect;
    uv_write_t auth_write;
    uv_timer_t auth_timer;
    mqtt_str_t auth_req;
    mqtt_str_t auth_res;
    /* Protocol */
    mqtt_broker_mode_t mode;
    tls_t *tls;
    wshttp_t *wh;
};

struct mqtt_publication_s {
    uint16_t packet_id;
    mqtt_publication_state_t state;
    mqtt_message_t *msg;
    mqtt_qos_t qos;
    uint8_t retain;
    uint32_t t_send;
    map_node_t node;
};

struct mqtt_offline_msg_s {
    mqtt_message_t *msg;
    mqtt_str_t topic_filter; /* subscription the message was queued for */
    mqtt_qos_t qos;
    uint8_t retain;
    queue_t node;
};

struct mqtt_alias_entry_s {
    uint16_t alias;
    mqtt_str_t topic;
    map_node_t node;
};

struct mqtt_subscription_s {
    mqtt_str_t topic_filter;
    mqtt_str_t share_group; /* $share group name, empty = not shared */
    uint32_t sub_id;        /* subscription identifier, 0 = none */
    mqtt_qos_t granted_qos;
    uint8_t nl;               /* No Local: don't receive own messages */
    uint8_t rap;              /* Retain as Published */
    uint8_t retain_handling;  /* 0=send, 1=send on new sub, 2=never send */
    map_node_t node;
};

struct mqtt_session_s {
    mqtt_str_t client_id;
    mqtt_client_t *c;
    mqtt_broker_t *b;
    uint16_t next_packet_id;
    map_node_t node;
    map_t sub_m;
    map_t incoming_m; /* packet_id -> publication (client -> broker) */
    map_t outgoing_m; /* packet_id -> publication (broker -> client) */
    uint16_t inflight_in;
    uint16_t inflight_out;
    queue_t offline;  /* undelivered messages while offline / in-flight full */
    /* will */
    mqtt_message_t *lwt;
    uint32_t will_delay;
    uv_timer_t will_timer;
    int will_timer_on;
    /* session expiry (v5) */
    uint32_t session_expiry;
    uv_timer_t expiry_timer;
    int expiry_timer_on;
    int closing_handles; /* embedded uv handles still closing; 0 = freeable */
    /* topic alias (v5) */
    map_t in_alias_m;  /* alias -> topic (client -> broker) */
    map_t out_alias_m; /* topic -> alias (broker -> client) */
    uint16_t in_alias_max;
    uint16_t out_alias_max;
    uint16_t receive_max; /* client's Receive Maximum, 0 = default 10 */
};

struct mqtt_message_s {
    uint8_t dup;
    uint8_t retain;
    mqtt_str_t topic_name;
    mqtt_qos_t qos;
    mqtt_str_t payload;
    mqtt_str_t client_id;
    mqtt_properties_t props; /* v5 properties to pass through */
    uint32_t expiry;         /* absolute expiry (b->t_now), 0 = never */
    queue_t node;
    int ref;
};

struct mqtt_subscriber_s {
    mqtt_session_t *s;
    mqtt_subscription_t *sub;
    map_node_t node;
};

struct mqtt_share_rr_s {
    mqtt_str_t group;
    uint32_t count;
    map_node_t node;
};

struct mqtt_acl_rule_s {
    mqtt_str_t username; /* user this rule applies to, "*" = all users */
    mqtt_str_t topic;    /* topic filter */
    uint8_t pub;
    uint8_t sub;
    uint8_t deny;
    queue_t node;
};

struct mqtt_trie_s {
    mqtt_str_t topic;
    map_t suber_m;
    map_t children_m;
    map_node_t node;
    mqtt_trie_t *parent;
    mqtt_message_t *retain;
};

struct mqtt_account_s {
    mqtt_str_t client_id;
    mqtt_str_t username;
    mqtt_str_t password;
    queue_t node;
};

struct mqtt_broker_s {
    uv_loop_t *loop;
    uv_idle_t idle;
    uv_timer_t timer;
    uv_timer_t shutdown_timer;
    int shutdown_timer_on;
    uv_signal_t signal_term;
    uv_signal_t signal_int;
    int signals_on;
    mqtt_trie_t *sub_root;
    char *host;
    int port;
    char *auth_type;
    char *auth_api;
    mqtt_broker_auth_callback_t auth_callback;
    void *auth_ud;
    int t_now;
    snowflake_t snowflake;
    queue_t client_q;
    map_t session_m;
    queue_t msg_q;
    queue_t account_q;
    queue_t acl_q;
    int max_connections;
    int connections;
    int rate_limit;
    size_t max_write_pending; /* per-client backpressure limit, 0 = off */
    int server_receive_max;   /* in-flight PUBLISHes accepted from a client */
    uint16_t server_alias_max;
    uint8_t server_max_qos;
    uint8_t server_retain_available;
    uint8_t server_wildcard_available;
    uint8_t server_sub_id_available;
    uint8_t server_shared_available;
    map_t listener_m;
    map_t share_rr_m; /* $share group -> round-robin counter */
    int shutdown_pending;
    int pending_clients;
    int trie_dump_enabled;
    int tls_on;
    /* stats */
    uint64_t msgs_received;
    uint64_t msgs_sent;
    uint32_t subscriptions;
    uint32_t retained_count;
    /* $SYS */
    uv_timer_t sys_timer;
    int sys_interval; /* seconds, 0 = off */
    /* metrics HTTP endpoint */
    uv_tcp_t metrics_server;
    int metrics_on;
    int metrics_port;
    /* persistence */
    char *persist_file;
    int persist_dirty;
};

static void
_broker_dump(void *ud, const char *str) {
    (void)ud;

    logger_print(logger_default(), LOG_LEVEL_DEBUG, "%s", str);
}

static void
broker_log_dump(const void *data, size_t size) {
    mqtt_str_t str = {.s = (char *)data, .n = size};
    mqtt_str_dump(&str, 0, _broker_dump);
}

static void
broker_log_prop(mqtt_properties_t *properties) {
    mqtt_property_t *property;

    if (!properties) {
        return;
    }

    property = properties->head;
    while (property) {
        mqtt_property_type_t type;
        const char *name;
        int i;
        const mqtt_property_def_t *def = 0;

        for (i = 0; i < MQTT_PROPERTY_DEFS_COUNT; i++) {
            if (MQTT_PROPERTY_DEFS[i].code == property->code) {
                def = &MQTT_PROPERTY_DEFS[i];
                break;
            }
        }
        if (!def) {
            property = property->next;
            continue;
        }
        name = def->name;
        type = def->type;
        switch (type) {
        case MQTT_PROPERTY_TYPE_BYTE:
            LOG_I("%s : %" PRIu8, name, property->b1);
            break;
        case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
            LOG_I("%s : %" PRIu16, name, property->b2);
            break;
        case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
            LOG_I("%s : %" PRIu32, name, property->b4);
            break;
        case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
            LOG_I("%s : %" PRIu32, name, property->bv);
            break;
        case MQTT_PROPERTY_TYPE_BINARY_DATA:
            LOG_I("%s : %.*s", name, (int)property->data.n, property->data.s);
            break;
        case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
            LOG_I("%s : %.*s", name, (int)property->str.n, property->str.s);
            break;
        case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
            LOG_I("%s : %.*s = %.*s", name, (int)property->pair.name.n, property->pair.name.s,
                  (int)property->pair.value.n, property->pair.value.s);
            break;
        }
        property = property->next;
    }
}

static mqtt_str_t
mqtt_topic_segment(mqtt_str_t *topic) {
    mqtt_str_t seg = MQTT_STR_INITIALIZER;

    if (topic->n) {
        size_t i;
        for (i = 0; i < topic->n; i++) {
            if (topic->s[i] == '/') {
                seg.n = i + 1;
                seg.s = topic->s;
                break;
            }
        }
        if (i == topic->n) {
            seg.n = topic->n;
            seg.s = topic->s;
            topic->n = 0;
            topic->s = NULL;
        } else {
            topic->s += i + 1;
            topic->n -= i + 1;
        }
    }
    return seg;
}

static void
mqtt_properties_copy(mqtt_properties_t *dst, const mqtt_properties_t *src) {
    const mqtt_property_t *p;
    mqtt_property_t **tail;

    /* build the nodes directly: mqtt_properties_add() takes C strings and
     * would misinterpret the property value union */
    tail = &dst->head;
    while (*tail) {
        tail = &(*tail)->next;
    }
    for (p = src->head; p; p = p->next) {
        mqtt_property_t *np;

        np = (mqtt_property_t *)MQTT_MALLOC(sizeof *np);
        if (!np) {
            break;
        }
        memset(np, 0, sizeof *np);
        np->code = p->code;
        switch (mqtt_property_type(p->code)) {
        case MQTT_PROPERTY_TYPE_BYTE:
            np->b1 = p->b1;
            break;
        case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
            np->b2 = p->b2;
            break;
        case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
            np->b4 = p->b4;
            break;
        case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
            np->bv = p->bv;
            break;
        case MQTT_PROPERTY_TYPE_BINARY_DATA: {
            mqtt_str_t tmp = p->data;

            mqtt_str_copy(&np->data, &tmp);
            break;
        }
        case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING: {
            mqtt_str_t tmp = p->str;

            mqtt_str_copy(&np->str, &tmp);
            break;
        }
        case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR: {
            mqtt_str_t tmp_name = p->pair.name;
            mqtt_str_t tmp_value = p->pair.value;

            mqtt_str_copy(&np->pair.name, &tmp_name);
            mqtt_str_copy(&np->pair.value, &tmp_value);
            break;
        }
        }
        dst->length += __property_len(np) + 1;
        *tail = np;
        tail = &np->next;
    }
}

/* free the value bytes owned by deep-copied property nodes (mqtt_properties_copy);
 * the nodes themselves are released by __properties_free / mqtt_packet_cleanup */
static void
mqtt_props_free_bytes(mqtt_properties_t *props) {
    mqtt_property_t *p;

    for (p = props->head; p; p = p->next) {
        switch (mqtt_property_type(p->code)) {
        case MQTT_PROPERTY_TYPE_BINARY_DATA:
            mqtt_str_free(&p->data);
            break;
        case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
            mqtt_str_free(&p->str);
            break;
        case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
            mqtt_str_free(&p->pair.name);
            mqtt_str_free(&p->pair.value);
            break;
        default:
            break;
        }
    }
}

/* copy the pass-through properties of a v5 PUBLISH into a message */
static void
mqtt_message_props_extract(mqtt_message_t *msg, mqtt_broker_t *b, mqtt_packet_t *pkt) {
    mqtt_property_t *prop;

    if (pkt->ver != MQTT_VERSION_5) {
        return;
    }
    mqtt_properties_copy(&msg->props, &pkt->v.publish.v5.properties);
    /* the topic alias is session-specific ([MQTT-3.3.2-6]) and must not be
     * forwarded to subscribers */
    {
        mqtt_property_t *ta = mqtt_properties_remove(&msg->props, MQTT_PROPERTY_TOPIC_ALIAS);

        if (ta) {
            MQTT_FREE(ta);
        }
    }

    prop = mqtt_properties_find(&msg->props, MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL);
    if (prop && prop->b4 > 0) {
        msg->expiry = (uint32_t)b->t_now + prop->b4;
    }
}

static mqtt_message_t *
mqtt_message_create(mqtt_broker_t *b, mqtt_session_t *s, mqtt_packet_t *pkt) {
    mqtt_message_t *msg;

    msg = (mqtt_message_t *)malloc(sizeof *msg);
    memset(msg, 0, sizeof *msg);

    if (pkt) {
        msg->dup = MQTT_FH_DUP(pkt->f.flags);
        msg->retain = MQTT_FH_RETAIN(pkt->f.flags);
        msg->qos = MQTT_FH_QOS(pkt->f.flags);
        mqtt_str_copy(&msg->topic_name, &pkt->v.publish.topic_name);
        mqtt_str_copy(&msg->payload, &pkt->p.publish.message);
        mqtt_message_props_extract(msg, b, pkt);
    }

    if (s) {
        mqtt_str_copy(&msg->client_id, &s->client_id);
    }

    msg->ref = 1;

    return msg;
}

static void
mqtt_message_destroy(mqtt_message_t *msg) {
    if (--msg->ref) {
        return;
    }
    mqtt_str_free(&msg->topic_name);
    mqtt_str_free(&msg->payload);
    mqtt_str_free(&msg->client_id);
    if (msg->props.head) {
        mqtt_property_t *p = msg->props.head;
        while (p) {
            mqtt_property_t *next = p->next;
            switch (mqtt_property_type(p->code)) {
            case MQTT_PROPERTY_TYPE_BINARY_DATA:
                mqtt_str_free(&p->data);
                break;
            case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
                mqtt_str_free(&p->str);
                break;
            case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
                mqtt_str_free(&p->pair.name);
                mqtt_str_free(&p->pair.value);
                break;
            default:
                break;
            }
            MQTT_FREE(p);
            p = next;
        }
        msg->props.head = NULL;
    }
    free(msg);
}

static void
mqtt_message_add_ref(mqtt_message_t *msg) {
    msg->ref++;
}

static mqtt_message_t *
mqtt_lwt_create(mqtt_session_t *s, mqtt_packet_t *pkt) {
    mqtt_message_t *msg;

    msg = (mqtt_message_t *)malloc(sizeof *msg);
    memset(msg, 0, sizeof *msg);

    msg->dup = 0;
    msg->retain = (pkt->v.connect.connect_flags & MQTT_CF_WILL_RETAIN) ? 1 : 0;
    msg->qos = MQTT_CF_WILL_QOS(pkt->v.connect.connect_flags);
    mqtt_str_copy(&msg->topic_name, &pkt->p.connect.will_topic);
    mqtt_str_copy(&msg->payload, &pkt->p.connect.will_message);
    mqtt_str_copy(&msg->client_id, &s->client_id);
    msg->ref = 1;

    return msg;
}

static mqtt_publication_t *
mqtt_publication_create(mqtt_message_t *msg, uint16_t packet_id, mqtt_qos_t qos, uint8_t retain,
                        mqtt_publication_state_t state, int t_now) {
    mqtt_publication_t *pub;

    pub = (mqtt_publication_t *)malloc(sizeof *pub);
    memset(pub, 0, sizeof *pub);
    mqtt_message_add_ref(msg);
    pub->msg = msg;
    pub->packet_id = packet_id;
    pub->qos = qos;
    pub->retain = retain;
    pub->state = state;
    pub->t_send = t_now;

    return pub;
}

static void
mqtt_publication_destroy(mqtt_publication_t *pub) {
    mqtt_message_destroy(pub->msg);
    free(pub);
}

static void *
_mqtt_publication_id_key(map_node_t *node) {
    mqtt_publication_t *pub;

    pub = map_data(node, mqtt_publication_t, node);
    return &pub->packet_id;
}

static int
_mqtt_publication_id_cmp(void *a, void *b) {
    return (int)(*(uint16_t *)a - *(uint16_t *)b);
}

static void
mqtt_session_incoming_store(mqtt_session_t *s, mqtt_publication_t *pub) {
    map_push(&s->incoming_m, &pub->packet_id, &pub->node);
    s->inflight_in++;
}

static int
mqtt_session_incoming_discard(mqtt_session_t *s, uint16_t packet_id) {
    map_node_t *node;
    mqtt_publication_t *pub;

    node = map_find(&s->incoming_m, &packet_id);
    if (!node) {
        return -1;
    }
    pub = map_data(node, mqtt_publication_t, node);
    if (pub->state != MQTT_PUBLICATION_STATE_REL) {
        return -1;
    }
    map_erase(&s->incoming_m, node);
    s->inflight_in--;
    mqtt_publication_destroy(pub);
    return 0;
}

static mqtt_message_t *
mqtt_session_incoming_message(mqtt_session_t *s, uint16_t packet_id) {
    map_node_t *node;
    mqtt_publication_t *pub;

    node = map_find(&s->incoming_m, &packet_id);
    if (!node) {
        return 0;
    }
    pub = map_data(node, mqtt_publication_t, node);
    if (pub->state != MQTT_PUBLICATION_STATE_REL) {
        return 0;
    }
    return pub->msg;
}

static void
mqtt_session_outgoing_store(mqtt_session_t *s, mqtt_publication_t *pub) {
    map_push(&s->outgoing_m, &pub->packet_id, &pub->node);
    s->inflight_out++;
}

static int
mqtt_session_outgoing_discard(mqtt_session_t *s, uint16_t packet_id, mqtt_publication_state_t state) {
    map_node_t *node;
    mqtt_publication_t *pub;

    node = map_find(&s->outgoing_m, &packet_id);
    if (!node) {
        return -1;
    }
    pub = map_data(node, mqtt_publication_t, node);
    if (pub->state != state) {
        return -1;
    }
    map_erase(&s->outgoing_m, node);
    s->inflight_out--;
    mqtt_publication_destroy(pub);
    return 0;
}

static int
mqtt_session_outgoing_update(mqtt_broker_t *b, mqtt_session_t *s, uint16_t packet_id, mqtt_publication_state_t state,
                              mqtt_publication_state_t new_state) {
    map_node_t *node;
    mqtt_publication_t *pub;

    node = map_find(&s->outgoing_m, &packet_id);
    if (!node) {
        return -1;
    }
    pub = map_data(node, mqtt_publication_t, node);
    if (pub->state != state) {
        return -1;
    }
    pub->state = new_state;
    pub->t_send = b->t_now;
    return 0;
}

static void
_mqtt_on_shutdown(uv_shutdown_t *req, int status) {
    (void)req;

    if (status != 0) {
        LOG_W("shutdown: %s", uv_strerror(status));
    }
}

static void
mqtt_client_shutdown(mqtt_client_t *c) {
    if (c->closed) {
        return;
    }
    LOG_D("client.%p.shutdown %s:%d", c, c->ip, c->port);
    c->closed = 1;
    uv_shutdown(&c->shutdown, (uv_stream_t *)c->tcp, _mqtt_on_shutdown);
}

typedef struct {
    uv_write_t req;
    char *data;
    size_t size;
    mqtt_client_t *c;
} broker_write_t;

static void
_mqtt_on_write(uv_write_t *req, int status) {
    broker_write_t *w;

    w = (broker_write_t *)req;
    if (status) {
        LOG_W("write: %s", uv_strerror(status));
    }
    if (w->c) {
        if (w->c->pending_write >= w->size) {
            w->c->pending_write -= w->size;
        } else {
            w->c->pending_write = 0;
        }
    }
    free(w->data);
    free(w);
}

static int
mqtt_client_send_raw(mqtt_client_t *c, const char *data, size_t size) {
    broker_write_t *w;
    uv_buf_t buf;
    int rc;

    if (c->closed) {
        return -1;
    }
    w = (broker_write_t *)malloc(sizeof *w);
    w->data = (char *)malloc(size);
    memcpy(w->data, data, size);
    w->size = size;
    w->c = c;
    buf = uv_buf_init(w->data, (unsigned int)size);
    rc = uv_write(&w->req, (uv_stream_t *)c->tcp, &buf, 1, _mqtt_on_write);
    if (rc) {
        LOG_W("write: %s", uv_strerror(rc));
        free(w->data);
        free(w);
        return rc;
    }
    c->pending_write += size;
    return 0;
}

static int
mqtt_client_send(mqtt_client_t *c, mqtt_packet_t *pkt) {
    mqtt_str_t b = MQTT_STR_INITIALIZER;
    int rc;

    if (c->closed) {
        return -1;
    }
    rc = mqtt_serialize(pkt, &b);
    mqtt_packet_cleanup(pkt);
    if (!rc) {
        logger_print(logger_default(), LOG_LEVEL_DEBUG, "send:\n");
        logger_print(logger_default(), LOG_LEVEL_DEBUG, "++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        LOG_DUMP(b.s, b.n);
        logger_print(logger_default(), LOG_LEVEL_DEBUG, "--------------------------------------------------\n");

        if (c->mode == MQTT_BROKER_MODE_TCP) {
            rc = mqtt_client_send_raw(c, b.s, b.n);
            mqtt_str_free(&b);
        } else if (c->mode == MQTT_BROKER_MODE_TLS) {
            rc = tls_write(c->tls, b.s, b.n);
            mqtt_str_free(&b);
        } else if (c->mode == MQTT_BROKER_MODE_WS || c->mode == MQTT_BROKER_MODE_WSS) {
            websocket_binary_t wsb = {.data = b.s, .length = b.n};
            rc = wshttp_write(c->wh, WS_OPCODE_BINARY, &wsb);
            mqtt_str_free(&b);
        } else {
            rc = -1;
            mqtt_str_free(&b);
        }
    }
    return rc;
}

static int
mqtt_client_disconnect(mqtt_client_t *c, uint8_t reason_code) {
    mqtt_packet_t pkt;

    /* the version must be set or mqtt_serialize() refuses the packet and the
     * v5 reason code would never reach the client */
    mqtt_packet_init(&pkt, c->parser.version, MQTT_DISCONNECT);
    pkt.v.disconnect.v5.reason_code = reason_code;

    /* server-initiated disconnect: the will is not published */
    if (c->s && c->s->lwt) {
        mqtt_message_destroy(c->s->lwt);
        c->s->lwt = 0;
        mqtt_broker_persist_mark(c->b);
    }

    if (mqtt_client_send(c, &pkt) == 0) {
        mqtt_client_shutdown(c);
        return 0;
    }
    mqtt_client_shutdown(c);
    return -1;
}

static uint16_t
mqtt_session_packet_id_generate(mqtt_session_t *s) {
    uint16_t id;

    for (;;) {
        id = ++s->next_packet_id;
        if (id == 0)
            id = ++s->next_packet_id;
        if (!map_find(&s->outgoing_m, &id)) {
            return id;
        }
    }
}

/* ================================================================== */
/* Topic alias (v5)                                                   */
/* ================================================================== */

static void *
_mqtt_alias_num_key(map_node_t *node) {
    mqtt_alias_entry_t *e;

    e = map_data(node, mqtt_alias_entry_t, node);
    return &e->alias;
}

static int
_mqtt_alias_num_cmp(void *a, void *b) {
    return (int)(*(uint16_t *)a - *(uint16_t *)b);
}

static void *
_mqtt_alias_topic_key(map_node_t *node) {
    mqtt_alias_entry_t *e;

    e = map_data(node, mqtt_alias_entry_t, node);
    return &e->topic;
}

static int
_mqtt_alias_topic_cmp(void *a, void *b) {
    mqtt_str_t *s1 = (mqtt_str_t *)a;
    mqtt_str_t *s2 = (mqtt_str_t *)b;
    int rc;

    rc = s1->n - s2->n;
    if (!rc) {
        rc = strncmp(s1->s, s2->s, s1->n);
    }
    return rc;
}

static mqtt_alias_entry_t *
mqtt_session_alias_in_lookup(mqtt_session_t *s, uint16_t alias) {
    map_node_t *node;

    node = map_find(&s->in_alias_m, &alias);
    if (node) {
        return map_data(node, mqtt_alias_entry_t, node);
    }
    return 0;
}

static void
mqtt_session_alias_in_store(mqtt_session_t *s, uint16_t alias, mqtt_str_t *topic) {
    mqtt_alias_entry_t *e;

    e = mqtt_session_alias_in_lookup(s, alias);
    if (!e) {
        e = (mqtt_alias_entry_t *)malloc(sizeof *e);
        memset(e, 0, sizeof *e);
        e->alias = alias;
        map_push(&s->in_alias_m, &e->alias, &e->node);
    }
    mqtt_str_free(&e->topic);
    mqtt_str_copy(&e->topic, topic);
}

static mqtt_alias_entry_t *
mqtt_session_alias_out_lookup(mqtt_session_t *s, mqtt_str_t *topic) {
    map_node_t *node;

    node = map_find(&s->out_alias_m, topic);
    if (node) {
        return map_data(node, mqtt_alias_entry_t, node);
    }
    return 0;
}

static uint16_t
mqtt_session_alias_out_assign(mqtt_session_t *s, mqtt_str_t *topic) {
    mqtt_alias_entry_t *e;
    map_node_t *node;
    uint16_t alias, used;

    if (s->out_alias_max == 0) {
        return 0;
    }
    for (alias = 1; alias <= s->out_alias_max; alias++) {
        used = 0;
        map_foreach(node, &s->out_alias_m) {
            mqtt_alias_entry_t *o;

            o = map_data(node, mqtt_alias_entry_t, node);
            if (o->alias == alias) {
                used = 1;
                break;
            }
        }
        if (!used) {
            break;
        }
    }
    if (alias > s->out_alias_max) {
        return 0; /* no free slot */
    }

    e = (mqtt_alias_entry_t *)malloc(sizeof *e);
    memset(e, 0, sizeof *e);
    e->alias = alias;
    mqtt_str_copy(&e->topic, topic);
    map_push(&s->out_alias_m, &e->topic, &e->node);
    return alias;
}

static void
mqtt_session_alias_clear(mqtt_session_t *s) {
    map_node_t *node, *next;

    map_foreach_safe(node, next, &s->in_alias_m) {
        mqtt_alias_entry_t *e;

        e = map_data(node, mqtt_alias_entry_t, node);
        map_erase(&s->in_alias_m, node);
        mqtt_str_free(&e->topic);
        free(e);
    }
    map_foreach_safe(node, next, &s->out_alias_m) {
        mqtt_alias_entry_t *e;

        e = map_data(node, mqtt_alias_entry_t, node);
        map_erase(&s->out_alias_m, node);
        mqtt_str_free(&e->topic);
        free(e);
    }
}

/* ================================================================== */
/* Offline message queue (persistent sessions)                        */
/* ================================================================== */

static void
mqtt_session_offline_store(mqtt_session_t *s, mqtt_message_t *msg, mqtt_str_t *topic_filter, mqtt_qos_t qos,
                           uint8_t retain) {
    mqtt_offline_msg_t *om;

    om = (mqtt_offline_msg_t *)malloc(sizeof *om);
    memset(om, 0, sizeof *om);
    mqtt_message_add_ref(msg);
    om->msg = msg;
    if (topic_filter) {
        mqtt_str_copy(&om->topic_filter, topic_filter);
    }
    om->qos = qos;
    om->retain = retain;
    queue_insert_tail(&s->offline, &om->node);
    mqtt_broker_persist_mark(s->b);
}

static void
mqtt_session_publish(mqtt_broker_t *b, mqtt_session_t *s, mqtt_message_t *msg, mqtt_str_t *topic_filter,
                     mqtt_qos_t qos, uint8_t retain, uint32_t sub_id);

static void
mqtt_session_offline_pump(mqtt_broker_t *b, mqtt_session_t *s) {
    uint16_t rmax;

    if (!s->c) {
        return;
    }
    rmax = s->receive_max ? s->receive_max : 10;

    for (;;) {
        queue_t *qnode;
        mqtt_offline_msg_t *om;
        map_node_t *snode;
        mqtt_subscription_t *sub;

        if (s->inflight_out >= rmax) {
            break;
        }
        /* backpressure active: stop and retry on the next tick */
        if (b->max_write_pending > 0 && s->c->pending_write >= b->max_write_pending) {
            break;
        }
        qnode = queue_head(&s->offline);
        if (qnode == &s->offline) {
            break;
        }
        om = queue_data(qnode, mqtt_offline_msg_t, node);
        queue_remove(qnode);
        mqtt_broker_persist_mark(b);

        /* dropped while the subscription was removed */
        snode = map_find(&s->sub_m, &om->topic_filter);
        if (!snode) {
            mqtt_message_destroy(om->msg);
            mqtt_str_free(&om->topic_filter);
            free(om);
            continue;
        }
        sub = map_data(snode, mqtt_subscription_t, node);

        if (om->msg->expiry && (uint32_t)b->t_now >= om->msg->expiry) {
            mqtt_message_destroy(om->msg);
            mqtt_str_free(&om->topic_filter);
            free(om);
            continue;
        }

        mqtt_session_publish(b, s, om->msg, &om->topic_filter, om->qos, om->retain, sub->sub_id);
        mqtt_message_destroy(om->msg);
        mqtt_str_free(&om->topic_filter);
        free(om);
    }
}

static void
mqtt_session_publish(mqtt_broker_t *b, mqtt_session_t *s, mqtt_message_t *msg, mqtt_str_t *topic_filter,
                     mqtt_qos_t qos, uint8_t retain, uint32_t sub_id) {
    mqtt_client_t *c;
    mqtt_publication_t *pub;
    mqtt_alias_entry_t *ae;
    mqtt_str_t empty = {0};
    uint16_t packet_id;
    mqtt_packet_t res;
    int rc;

    c = s->c;
    if (!c || s->inflight_out >= (uint16_t)(s->receive_max ? s->receive_max : 10)) {
        mqtt_session_offline_store(s, msg, topic_filter, qos, retain);
        return;
    }
    /* write backpressure: buffer when the client's socket write queue is saturated */
    if (b->max_write_pending > 0 && c->pending_write >= b->max_write_pending) {
        mqtt_session_offline_store(s, msg, topic_filter, qos, retain);
        return;
    }

    if (qos > 0) {
        packet_id = mqtt_session_packet_id_generate(s);
    } else {
        packet_id = 0;
    }

    mqtt_packet_init(&res, c->parser.version, MQTT_PUBLISH);
    res.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, qos, retain);
    res.v.publish.packet_id = packet_id;
    mqtt_str_set(&res.v.publish.topic_name, &msg->topic_name);
    mqtt_str_set(&res.p.publish.message, &msg->payload);

    if (res.ver == MQTT_VERSION_5) {
        /* pass-through properties from the publisher */
        if (msg->props.head) {
            mqtt_properties_copy(&res.v.publish.v5.properties, &msg->props);
        }
        /* subscription identifier */
        if (sub_id) {
            mqtt_properties_add(&res.v.publish.v5.properties, MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER, &sub_id, NULL);
        }
        /* topic alias */
        ae = mqtt_session_alias_out_lookup(s, &msg->topic_name);
        if (ae) {
            uint16_t alias = ae->alias;

            mqtt_properties_add(&res.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS, &alias, NULL);
            mqtt_str_set(&res.v.publish.topic_name, &empty);
        } else {
            uint16_t alias = mqtt_session_alias_out_assign(s, &msg->topic_name);

            if (alias) {
                mqtt_properties_add(&res.v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS, &alias, NULL);
            }
        }
    }

    LOG_I("[%.*s] sending PUBLISH (id: %" PRIu16 ", dup: %" PRIu8 ", retain: %" PRIu8 ", qos: %" PRIu8
          ", topic_name: %.*s, ...(%d bytes))",
          MQTT_STR_PRINT(s->client_id), res.v.publish.packet_id, MQTT_FH_DUP(res.f.flags),
          MQTT_FH_RETAIN(res.f.flags), MQTT_FH_QOS(res.f.flags),
          MQTT_STR_PRINT(res.v.publish.topic_name), res.p.publish.message.n);
    if (res.ver == MQTT_VERSION_5) {
        LOG_PROP(&res.v.publish.v5.properties);
    }

    rc = mqtt_client_send(c, &res);
    if (res.ver == MQTT_VERSION_5) {
        mqtt_props_free_bytes(&res.v.publish.v5.properties);
    }
    mqtt_packet_cleanup(&res); /* release the copied pass-through properties */
    if (rc) {
        mqtt_client_shutdown(c);
    }
    b->msgs_sent++;

    switch (qos) {
    case MQTT_QOS_0:
        break;
    case MQTT_QOS_1:
        pub = mqtt_publication_create(msg, packet_id, qos, retain, MQTT_PUBLICATION_STATE_ACK, b->t_now);
        mqtt_session_outgoing_store(s, pub);
        break;
    case MQTT_QOS_2:
        pub = mqtt_publication_create(msg, packet_id, qos, retain, MQTT_PUBLICATION_STATE_REC, b->t_now);
        mqtt_session_outgoing_store(s, pub);
        break;
    }
}

static void
mqtt_publication_resend_publish(mqtt_broker_t *b, mqtt_session_t *s, mqtt_publication_t *pub) {
    mqtt_client_t *c;
    mqtt_packet_t res;
    int rc;
    (void)b;

    c = s->c;
    if (!c) {
        return;
    }

    mqtt_packet_init(&res, c->parser.version, MQTT_PUBLISH);
    res.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, pub->qos, pub->retain);
    res.v.publish.packet_id = pub->packet_id;
    mqtt_str_set(&res.v.publish.topic_name, &pub->msg->topic_name);
    mqtt_str_set(&res.p.publish.message, &pub->msg->payload);

    LOG_W("[%.*s] resend PUBLISH (id: %" PRIu16 ", dup: 1, qos: %" PRIu8 ", topic: %.*s)",
          MQTT_STR_PRINT(s->client_id), pub->packet_id, pub->qos, MQTT_STR_PRINT(pub->msg->topic_name));
    rc = mqtt_client_send(c, &res);
    if (rc) {
        mqtt_client_shutdown(c);
    }
}

static void
mqtt_publication_resend_pubrel(mqtt_broker_t *b, mqtt_session_t *s, mqtt_publication_t *pub) {
    mqtt_client_t *c;
    mqtt_packet_t res;
    int rc;
    (void)b;

    c = s->c;
    if (!c) {
        return;
    }

    mqtt_packet_init(&res, c->parser.version, MQTT_PUBREL);
    res.v.pubrel.packet_id = pub->packet_id;

    LOG_W("[%.*s] resend PUBREL (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), pub->packet_id);
    rc = mqtt_client_send(c, &res);
    if (rc) {
        mqtt_client_shutdown(c);
    }
}

static void
mqtt_client_retransmit(mqtt_broker_t *b, mqtt_client_t *c) {
    mqtt_session_t *s;
    map_node_t *node;
    int timeout;

    s = c->s;
    if (!s) {
        return;
    }

    timeout = c->keep_alive > 0 ? (int)c->keep_alive : 30;

    map_foreach(node, &s->outgoing_m) {
        mqtt_publication_t *pub;

        pub = map_data(node, mqtt_publication_t, node);
        if ((int)(b->t_now - pub->t_send) <= timeout) {
            continue;
        }
        switch (pub->state) {
        case MQTT_PUBLICATION_STATE_ACK: /* QoS1: waiting PUBACK */
        case MQTT_PUBLICATION_STATE_REC: /* QoS2: waiting PUBREC */
            mqtt_publication_resend_publish(b, s, pub);
            break;
        case MQTT_PUBLICATION_STATE_REL: /* QoS2: waiting PUBCOMP */
            mqtt_publication_resend_pubrel(b, s, pub);
            break;
        default:
            break;
        }
        pub->t_send = b->t_now;
    }
}

static void *
_mqtt_subscriber_key(map_node_t *node) {
    mqtt_subscriber_t *suber;

    suber = map_data(node, mqtt_subscriber_t, node);
    return &suber->s->client_id;
}

static int
_mqtt_subscriber_cmp(void *a, void *b) {
    mqtt_str_t *s1 = (mqtt_str_t *)a;
    mqtt_str_t *s2 = (mqtt_str_t *)b;
    int rc;

    rc = s1->n - s2->n;
    if (!rc) {
        rc = strncmp(s1->s, s2->s, s1->n);
    }
    return rc;
}

static void *
_mqtt_trie_key(map_node_t *node) {
    mqtt_trie_t *trie;

    trie = map_data(node, mqtt_trie_t, node);
    return &trie->topic;
}

static int
_mqtt_trie_cmp(void *a, void *b) {
    mqtt_str_t *s1 = (mqtt_str_t *)a;
    mqtt_str_t *s2 = (mqtt_str_t *)b;
    int rc;

    rc = s1->n - s2->n;
    if (!rc) {
        rc = strncmp(s1->s, s2->s, s1->n);
    }
    return rc;
}

static mqtt_trie_t *
mqtt_trie_create(mqtt_trie_t *parent, mqtt_str_t *topic) {
    mqtt_trie_t *trie;

    trie = (mqtt_trie_t *)malloc(sizeof *trie);
    memset(trie, 0, sizeof *trie);
    map_init(&trie->suber_m, _mqtt_subscriber_key, _mqtt_subscriber_cmp);
    map_init(&trie->children_m, _mqtt_trie_key, _mqtt_trie_cmp);

    if (topic) {
        mqtt_str_copy(&trie->topic, topic);
    }
    if (parent) {
        trie->parent = parent;
        map_push(&parent->children_m, topic, &trie->node);
    }
    return trie;
}

static void
mqtt_trie_destroy_recursive(mqtt_trie_t *trie) {
    map_node_t *node, *next;

    /* Recursively destroy children first */
    map_foreach_safe(node, next, &trie->children_m) {
        mqtt_trie_t *child;

        child = map_data(node, mqtt_trie_t, node);
        map_erase(&trie->children_m, node);
        mqtt_trie_destroy_recursive(child);
    }

    /* Free all subscribers */
    map_foreach_safe(node, next, &trie->suber_m) {
        mqtt_subscriber_t *suber;

        suber = map_data(node, mqtt_subscriber_t, node);
        map_erase(&trie->suber_m, node);
        mqtt_subscriber_destroy(suber);
    }

    /* Free retained message */
    if (trie->retain) {
        mqtt_message_destroy(trie->retain);
        trie->retain = NULL;
    }

    mqtt_str_free(&trie->topic);
    free(trie);
}

static void
mqtt_trie_destroy(mqtt_trie_t *trie) {
    if (!trie) {
        return;
    }
    if (trie->parent) {
        map_erase(&trie->parent->children_m, &trie->node);
    }
    mqtt_trie_destroy_recursive(trie);
}

static mqtt_trie_t *
mqtt_trie_find(mqtt_trie_t *trie, mqtt_str_t *topic) {
    map_node_t *node;

    node = map_find(&trie->children_m, topic);
    if (node) {
        return map_data(node, mqtt_trie_t, node);
    }
    return 0;
}

static void
mqtt_trie_remove(mqtt_broker_t *b, mqtt_trie_t *trie) {
    do {
        mqtt_trie_t *node;

        node = trie->parent;
        if (!map_empty(&trie->children_m) || !map_empty(&trie->suber_m) || trie->retain || trie == b->sub_root) {
            break;
        }
        mqtt_trie_destroy(trie);
        trie = node;
    } while (trie);
}

static mqtt_subscriber_t *
mqtt_trie_find_subscriber(mqtt_trie_t *trie, mqtt_str_t *client_id) {
    map_node_t *node;

    node = map_find(&trie->suber_m, client_id);
    if (node) {
        return map_data(node, mqtt_subscriber_t, node);
    }
    return 0;
}

static void
mqtt_trie_add_subscriber(mqtt_trie_t *trie, mqtt_subscriber_t *suber) {
    map_push(&trie->suber_m, &suber->s->client_id, &suber->node);
}

static void
mqtt_trie_remove_subscriber(mqtt_trie_t *trie, mqtt_subscriber_t *suber) {
    map_erase(&trie->suber_m, &suber->node);
}

static int
mqtt_trie_has_children(mqtt_trie_t *trie) {
    return !map_empty(&trie->children_m);
}

static void *
_mqtt_share_group_key(map_node_t *node) {
    mqtt_share_rr_t *rr;

    rr = map_data(node, mqtt_share_rr_t, node);
    return &rr->group;
}

static int
_mqtt_share_group_cmp(void *a, void *b) {
    mqtt_str_t *s1 = (mqtt_str_t *)a;
    mqtt_str_t *s2 = (mqtt_str_t *)b;
    int rc;

    rc = s1->n - s2->n;
    if (!rc) {
        rc = strncmp(s1->s, s2->s, s1->n);
    }
    return rc;
}

static mqtt_share_rr_t *
mqtt_share_rr_fetch(mqtt_broker_t *b, mqtt_str_t *group) {
    map_node_t *node;
    mqtt_share_rr_t *rr;

    node = map_find(&b->share_rr_m, group);
    if (node) {
        return map_data(node, mqtt_share_rr_t, node);
    }
    rr = (mqtt_share_rr_t *)malloc(sizeof *rr);
    memset(rr, 0, sizeof *rr);
    mqtt_str_copy(&rr->group, group);
    map_push(&b->share_rr_m, &rr->group, &rr->node);
    return rr;
}

/* is this subscriber the one chosen for its $share group this dispatch? */
static int
mqtt_share_is_chosen(mqtt_broker_t *b, mqtt_trie_t *trie, mqtt_subscriber_t *suber) {
    mqtt_str_t *group;
    mqtt_share_rr_t *rr;
    map_node_t *n;
    int count = 0, idx = 0;

    group = &suber->sub->share_group;
    map_foreach(n, &trie->suber_m) {
        mqtt_subscriber_t *o;

        o = map_data(n, mqtt_subscriber_t, node);
        if (mqtt_str_equal(&o->sub->share_group, group)) {
            if (o == suber) {
                idx = count;
            }
            count++;
        }
    }
    rr = mqtt_share_rr_fetch(b, group);
    if (idx == 0) {
        rr->count++;
    }
    return (int)(rr->count % (uint32_t)count) == idx;
}

static void
mqtt_trie_deliver(mqtt_broker_t *b, mqtt_trie_t *trie, mqtt_message_t *msg) {
    map_node_t *node;

    map_foreach(node, &trie->suber_m) {
        mqtt_subscriber_t *suber;
        mqtt_qos_t qos;
        uint8_t retain;

        suber = map_data(node, mqtt_subscriber_t, node);

        /* nl (No Local): don't deliver to publisher's own subscriptions */
        if (suber->sub->nl && mqtt_str_equal(&suber->s->client_id, &msg->client_id)) {
            continue;
        }

        /* $share: only the round-robin chosen member of the group gets it */
        if (suber->sub->share_group.n > 0 && !mqtt_share_is_chosen(b, trie, suber)) {
            continue;
        }

        qos = msg->qos < suber->sub->granted_qos ? msg->qos : suber->sub->granted_qos;

        /* rap (Retain as Published): preserve publisher's retain flag */
        retain = suber->sub->rap ? msg->retain : 0;

        mqtt_session_publish(b, suber->s, msg, &suber->sub->topic_filter, qos, retain, suber->sub->sub_id);
    }
}

static void
mqtt_trie_dispatch(mqtt_broker_t *b, mqtt_trie_t *trie, mqtt_str_t topic_name, mqtt_message_t *msg) {
    mqtt_str_t seg, single, single_sep, multi, *topic;

    mqtt_str_from(&single, "+");
    mqtt_str_from(&single_sep, "+/");
    mqtt_str_from(&multi, "#");

    topic = &topic_name;
    seg = mqtt_topic_segment(topic);
    if (seg.n) {
        mqtt_trie_t *branch;

        branch = mqtt_trie_find(trie, &seg);
        if (branch) {
            mqtt_trie_dispatch(b, branch, *topic, msg);
            if (!topic->n) {
                mqtt_trie_deliver(b, branch, msg);
            }
        }

        branch = mqtt_trie_find(trie, &single);
        if (branch) {
            mqtt_trie_dispatch(b, branch, *topic, msg);
            if (!topic->n) {
                mqtt_trie_deliver(b, branch, msg);
            }
        }

        branch = mqtt_trie_find(trie, &single_sep);
        if (branch) {
            mqtt_trie_dispatch(b, branch, *topic, msg);
            if (!topic->n) {
                mqtt_trie_deliver(b, branch, msg);
            }
        }

        branch = mqtt_trie_find(trie, &multi);
        if (branch && !mqtt_trie_has_children(branch)) {
            mqtt_trie_deliver(b, branch, msg);
        }
    }
}

static void
mqtt_trie_dump(mqtt_trie_t *trie, int d) {
    map_node_t *node;
    char buf[4096] = {0};
    int i, n = 0;

    for (i = 0; i < d * 2; i++) {
        n += sprintf(buf + n, " ");
    }

    n += sprintf(buf + n, "%.*s (%p, p:%p)", MQTT_STR_PRINT(trie->topic), trie, trie->parent);

    if (trie->retain) {
        n += sprintf(buf + n, " r");
    }

    map_foreach(node, &trie->suber_m) {
        mqtt_subscriber_t *suber;

        suber = map_data(node, mqtt_subscriber_t, node);
        n += sprintf(buf + n, " (%.*s, %d) ", MQTT_STR_PRINT(suber->s->client_id), suber->sub->granted_qos);
    }

    logger_print(logger_default(), LOG_LEVEL_DEBUG, "%d %s\n", d, buf);

    map_foreach(node, &trie->children_m) {
        mqtt_trie_t *sub;

        sub = map_data(node, mqtt_trie_t, node);
        mqtt_trie_dump(sub, d + 1);
    }
}

static mqtt_subscriber_t *
mqtt_subscriber_create(mqtt_session_t *s, mqtt_subscription_t *sub) {
    mqtt_subscriber_t *suber;

    suber = (mqtt_subscriber_t *)malloc(sizeof *suber);
    memset(suber, 0, sizeof *suber);

    suber->s = s;
    suber->sub = sub;

    return suber;
}

static void
mqtt_subscriber_destroy(mqtt_subscriber_t *suber) {
    free(suber);
}

static mqtt_subscription_t *
mqtt_subscription_create(mqtt_str_t *topic_filter, mqtt_str_t *share_group, uint32_t sub_id, mqtt_qos_t requested_qos,
                          uint8_t nl, uint8_t rap, uint8_t retain_handling) {
    mqtt_subscription_t *sub;

    sub = (mqtt_subscription_t *)malloc(sizeof *sub);
    memset(sub, 0, sizeof *sub);

    sub->granted_qos = requested_qos;
    sub->nl = nl;
    sub->rap = rap;
    sub->retain_handling = retain_handling;
    sub->sub_id = sub_id;
    mqtt_str_copy(&sub->topic_filter, topic_filter);
    if (share_group && share_group->n) {
        mqtt_str_copy(&sub->share_group, share_group);
    }

    return sub;
}

static void
mqtt_subscription_destroy(mqtt_subscription_t *sub) {
    mqtt_str_free(&sub->topic_filter);
    mqtt_str_free(&sub->share_group);
    free(sub);
}

static void
mqtt_subscription_update(mqtt_subscription_t *sub, mqtt_str_t *share_group, uint32_t sub_id, mqtt_qos_t requested_qos,
                          uint8_t nl, uint8_t rap, uint8_t retain_handling) {
    if (requested_qos > sub->granted_qos) {
        sub->granted_qos = requested_qos;
    }
    sub->nl = nl;
    sub->rap = rap;
    sub->retain_handling = retain_handling;
    sub->sub_id = sub_id;
    if (share_group && share_group->n) {
        mqtt_str_free(&sub->share_group);
        mqtt_str_copy(&sub->share_group, share_group);
    }
}

static void *
_mqtt_session_client_id_key(map_node_t *node) {
    mqtt_session_t *s;

    s = map_data(node, mqtt_session_t, node);
    return &s->client_id;
}

static int
_mqtt_session_client_id_cmp(void *a, void *b) {
    mqtt_str_t *s1 = (mqtt_str_t *)a;
    mqtt_str_t *s2 = (mqtt_str_t *)b;
    int rc;

    rc = s1->n - s2->n;
    if (!rc) {
        rc = strncmp(s1->s, s2->s, s1->n);
    }
    return rc;
}

static void
mqtt_broker_add_client(mqtt_broker_t *b, mqtt_client_t *c) {
    b->connections++;
    queue_insert_tail(&b->client_q, &c->node);
}

static void
mqtt_broker_remove_client(mqtt_broker_t *b, mqtt_client_t *c) {
    b->connections--;
    queue_remove(&c->node);
}

static void
mqtt_broker_add_session(mqtt_broker_t *b, mqtt_session_t *s) {
    map_push(&b->session_m, &s->client_id, &s->node);
}

static void
mqtt_broker_remove_session(mqtt_broker_t *b, mqtt_session_t *s) {
    map_erase(&b->session_m, &s->node);
}

static mqtt_session_t *
mqtt_broker_find_session(mqtt_broker_t *b, mqtt_str_t *client_id) {
    map_node_t *node;

    node = map_find(&b->session_m, client_id);
    if (node) {
        return map_data(node, mqtt_session_t, node);
    }
    return 0;
}

/* [MQTT-3.5.1-1]: a retained message whose Message Expiry Interval has
 * elapsed must not be delivered (lazy purge on access) */
static int
mqtt_trie_retain_expired(mqtt_broker_t *b, mqtt_trie_t *trie) {
    if (trie->retain && trie->retain->expiry && (uint32_t)b->t_now >= trie->retain->expiry) {
        LOG_I("retained message %.*s expired, purging", MQTT_STR_PRINT(trie->topic));
        mqtt_message_destroy(trie->retain);
        trie->retain = 0;
        mqtt_broker_persist_mark(b);
    }
    return trie->retain ? 1 : 0;
}

static void
mqtt_broker_subscribe(mqtt_broker_t *b, mqtt_session_t *s, mqtt_subscription_t *sub) {
    mqtt_str_t topic;
    mqtt_str_t seg;
    mqtt_trie_t *trie;
    mqtt_subscriber_t *suber;

    topic = sub->topic_filter;

    /* $share/group/filter: the trie path is the actual filter */
    if (sub->share_group.n > 0) {
        topic.s += 7 + sub->share_group.n + 1;
        topic.n -= 7 + sub->share_group.n + 1;
    }

    trie = b->sub_root;
    while ((seg = mqtt_topic_segment(&topic)).n && trie) {
        mqtt_trie_t *branch;

        branch = mqtt_trie_find(trie, &seg);
        if (!branch) {
            branch = mqtt_trie_create(trie, &seg);
        }
        trie = branch;
    }

    suber = mqtt_trie_find_subscriber(trie, &s->client_id);
    if (!suber) {
        suber = mqtt_subscriber_create(s, sub);
        mqtt_trie_add_subscriber(trie, suber);

        if (mqtt_trie_retain_expired(b, trie)) {
            /* retain_handling: 0=send, 1=send on new sub, 2=never send */
            int deliver = 1;

            if (sub->retain_handling == 2) {
                deliver = 0;
            } else if (sub->share_group.n > 0) {
                /* retained: one member of the shared group gets it */
                deliver = mqtt_share_is_chosen(b, trie, suber);
            }
            if (deliver) {
                mqtt_qos_t qos = sub->granted_qos < trie->retain->qos ? sub->granted_qos : trie->retain->qos;
                /* retain-as-published: deliver with the retain flag cleared */
                mqtt_session_publish(b, s, trie->retain, &sub->topic_filter, qos, sub->rap ? 0 : 1, sub->sub_id);
            }
        }
    } else if (sub->retain_handling == 0 && mqtt_trie_retain_expired(b, trie)) {
        /* retain_handling=0: send retained messages even on updated subscription */
        int deliver = 1;

        if (sub->share_group.n > 0) {
            deliver = mqtt_share_is_chosen(b, trie, suber);
        }
        if (deliver) {
            mqtt_qos_t qos = sub->granted_qos < trie->retain->qos ? sub->granted_qos : trie->retain->qos;
            mqtt_session_publish(b, s, trie->retain, &sub->topic_filter, qos, sub->rap ? 0 : 1, sub->sub_id);
        }
    }

    mqtt_broker_persist_mark(b);
    if (b->trie_dump_enabled) {
        mqtt_trie_dump(b->sub_root, 0);
    }
}

static mqtt_qos_t
mqtt_session_subscribe(mqtt_broker_t *b, mqtt_session_t *s, mqtt_str_t *topic_filter, mqtt_str_t *share_group,
                        uint32_t sub_id, mqtt_qos_t requested_qos, uint8_t nl, uint8_t rap, uint8_t retain_handling) {
    map_node_t *node;
    mqtt_subscription_t *sub;

    node = map_find(&s->sub_m, topic_filter);
    if (node) {
        sub = map_data(node, mqtt_subscription_t, node);
        mqtt_subscription_update(sub, share_group, sub_id, requested_qos, nl, rap, retain_handling);
    } else {
        sub = mqtt_subscription_create(topic_filter, share_group, sub_id, requested_qos, nl, rap, retain_handling);
        map_push(&s->sub_m, &sub->topic_filter, &sub->node);
        b->subscriptions++;
    }

    mqtt_broker_subscribe(b, s, sub);
    return sub->granted_qos;
}

static int
mqtt_broker_unsubscribe(mqtt_broker_t *b, mqtt_session_t *s, mqtt_subscription_t *sub) {
    mqtt_str_t topic;
    mqtt_str_t seg;
    mqtt_trie_t *trie;
    int rc;

    topic = sub->topic_filter;
    /* $share/group/filter: the trie path is the actual filter */
    if (sub->share_group.n > 0) {
        topic.s += 7 + sub->share_group.n + 1;
        topic.n -= 7 + sub->share_group.n + 1;
    }
    rc = -1;

    trie = b->sub_root;
    while ((seg = mqtt_topic_segment(&topic)).n && trie) {
        trie = mqtt_trie_find(trie, &seg);
    }
    if (trie) {
        mqtt_subscriber_t *suber;

        suber = mqtt_trie_find_subscriber(trie, &s->client_id);
        if (suber) {
            mqtt_trie_remove_subscriber(trie, suber);
            mqtt_subscriber_destroy(suber);
            rc = 0;
        }
        mqtt_trie_remove(b, trie);
    }

    mqtt_broker_persist_mark(b);
    if (b->trie_dump_enabled) {
        mqtt_trie_dump(b->sub_root, 0);
    }
    return rc;
}

static int
mqtt_session_unsubscribe(mqtt_broker_t *b, mqtt_session_t *s, mqtt_str_t *topic_filter) {
    map_node_t *node;

    node = map_find(&s->sub_m, topic_filter);
    if (node) {
        mqtt_subscription_t *sub;
        int rc;

        sub = map_data(node, mqtt_subscription_t, node);
        rc = mqtt_broker_unsubscribe(b, s, sub);
        map_erase(&s->sub_m, node);
        mqtt_subscription_destroy(sub);
        b->subscriptions--;

        return rc;
    }
    return -1;
}

static void
mqtt_broker_retain(mqtt_broker_t *b, mqtt_message_t *msg) {
    mqtt_str_t topic;
    mqtt_str_t seg;
    mqtt_trie_t *trie;

    topic = msg->topic_name;
    trie = b->sub_root;
    while ((seg = mqtt_topic_segment(&topic)).n) {
        mqtt_trie_t *branch;

        branch = mqtt_trie_find(trie, &seg);
        if (!branch) {
            branch = mqtt_trie_create(trie, &seg);
        }
        trie = branch;
    };

    if (trie->retain) {
        mqtt_message_destroy(trie->retain);
        trie->retain = 0;
        b->retained_count--;
    }
    if (msg->payload.n > 0) {
        mqtt_message_add_ref(msg);
        trie->retain = msg;
        b->retained_count++;
    } else {
        mqtt_trie_remove(b, trie);
    }
    mqtt_broker_persist_mark(b);
    if (b->trie_dump_enabled) {
        mqtt_trie_dump(b->sub_root, 0);
    }
}

static void
_mqtt_on_idle(uv_idle_t *handle) {
    mqtt_broker_t *b = handle->data;
    mqtt_message_t *msg;
    queue_t *node;
    (void)handle;

    if (queue_empty(&b->msg_q)) {
        uv_idle_stop(&b->idle);
        return;
    }

    node = queue_head(&b->msg_q);
    queue_remove(node);
    msg = queue_data(node, mqtt_message_t, node);

    if (msg->retain) {
        mqtt_broker_retain(b, msg);
    }
    mqtt_trie_dispatch(b, b->sub_root, msg->topic_name, msg);
    mqtt_message_destroy(msg);
}

static void
mqtt_broker_dispatch(mqtt_broker_t *b, mqtt_message_t *msg) {
    int empty;

    empty = queue_empty(&b->msg_q);
    queue_insert_tail(&b->msg_q, &msg->node);
    if (empty) {
        uv_idle_start(&b->idle, _mqtt_on_idle);
    }
}

static void *
_mqtt_subscription_topic_filter_key(map_node_t *node) {
    mqtt_subscription_t *s;

    s = map_data(node, mqtt_subscription_t, node);
    return &s->topic_filter;
}

static int
_mqtt_subscription_topic_filter_cmp(void *a, void *b) {
    mqtt_str_t *s1 = (mqtt_str_t *)a;
    mqtt_str_t *s2 = (mqtt_str_t *)b;
    int rc;

    rc = s1->n - s2->n;
    if (!rc) {
        rc = strncmp(s1->s, s2->s, s1->n);
    }
    return rc;
}

static void
_broker_on_will_timer(uv_timer_t *handle);
static void
_broker_on_session_expiry(uv_timer_t *handle);

static mqtt_session_t *
mqtt_session_create(mqtt_broker_t *b, mqtt_str_t *client_id) {
    mqtt_session_t *s;

    s = (mqtt_session_t *)malloc(sizeof *s);
    memset(s, 0, sizeof *s);
    mqtt_str_copy(&s->client_id, client_id);
    s->b = b;

    map_init(&s->sub_m, _mqtt_subscription_topic_filter_key, _mqtt_subscription_topic_filter_cmp);
    map_init(&s->incoming_m, _mqtt_publication_id_key, _mqtt_publication_id_cmp);
    map_init(&s->outgoing_m, _mqtt_publication_id_key, _mqtt_publication_id_cmp);
    map_init(&s->in_alias_m, _mqtt_alias_num_key, _mqtt_alias_num_cmp);
    map_init(&s->out_alias_m, _mqtt_alias_topic_key, _mqtt_alias_topic_cmp);

    queue_init(&s->offline);

    uv_timer_init(b->loop, &s->will_timer);
    s->will_timer.data = s;
    uv_timer_init(b->loop, &s->expiry_timer);
    s->expiry_timer.data = s;

    LOG_D("session.%p.create %.*s", s, MQTT_STR_PRINT(s->client_id));

    return s;
}

static void
_session_on_timers_close(uv_handle_t *handle) {
    mqtt_session_t *s;

    s = (mqtt_session_t *)handle->data;
    /* the timers are embedded in the session: free it only once both
     * asynchronous closes have completed */
    if (--s->closing_handles == 0) {
        free(s);
    }
}

static void
mqtt_session_destroy(mqtt_broker_t *b, mqtt_session_t *s) {
    map_node_t *node, *next;
    queue_t *qnode;

    LOG_D("session.%p.destroy %.*s", s, MQTT_STR_PRINT(s->client_id));

    mqtt_broker_persist_mark(b);
    if (s->will_timer_on) {
        uv_timer_stop(&s->will_timer);
        s->will_timer_on = 0;
    }
    if (s->expiry_timer_on) {
        uv_timer_stop(&s->expiry_timer);
        s->expiry_timer_on = 0;
    }
    s->closing_handles = 2;
    uv_close((uv_handle_t *)&s->will_timer, _session_on_timers_close);
    uv_close((uv_handle_t *)&s->expiry_timer, _session_on_timers_close);

    if (s->lwt) {
        mqtt_message_destroy(s->lwt);
        s->lwt = 0;
    }

    /* Free incoming publications */
    map_foreach_safe(node, next, &s->incoming_m) {
        mqtt_publication_t *pub = map_data(node, mqtt_publication_t, node);
        map_erase(&s->incoming_m, node);
        mqtt_publication_destroy(pub);
    }

    /* Free outgoing publications */
    map_foreach_safe(node, next, &s->outgoing_m) {
        mqtt_publication_t *pub = map_data(node, mqtt_publication_t, node);
        map_erase(&s->outgoing_m, node);
        mqtt_publication_destroy(pub);
    }

    /* Free offline messages */
    while (!queue_empty(&s->offline)) {
        mqtt_offline_msg_t *om;

        qnode = queue_head(&s->offline);
        om = queue_data(qnode, mqtt_offline_msg_t, node);
        queue_remove(qnode);
        mqtt_message_destroy(om->msg);
        mqtt_str_free(&om->topic_filter);
        free(om);
    }

    mqtt_session_alias_clear(s);

    map_foreach_safe(node, next, &s->sub_m) {
        mqtt_subscription_t *sub;

        sub = map_data(node, mqtt_subscription_t, node);
        mqtt_broker_unsubscribe(b, s, sub);
        map_erase(&s->sub_m, node);
        mqtt_subscription_destroy(sub);
    }
    mqtt_str_free(&s->client_id);
    /* s is freed by _session_on_timers_close once both timer handles are closed */
}

static void
_broker_on_will_timer(uv_timer_t *handle) {
    mqtt_session_t *s = handle->data;
    mqtt_broker_t *b;

    s->will_timer_on = 0;
    b = s->b;

    if (s->lwt) {
        mqtt_message_t *lwt;

        lwt = s->lwt;
        s->lwt = 0;
        LOG_I("[%.*s] publishing will (delay elapsed)", MQTT_STR_PRINT(s->client_id));
        mqtt_broker_dispatch(b, lwt);
    }
}

static void
_broker_on_session_expiry(uv_timer_t *handle) {
    mqtt_session_t *s = handle->data;
    mqtt_broker_t *b;

    s->expiry_timer_on = 0;
    b = s->b;

    LOG_I("[%.*s] session expired", MQTT_STR_PRINT(s->client_id));
    mqtt_broker_remove_session(b, s);
    mqtt_session_destroy(b, s);
}

/* ================================================================== */
/* Protocol callbacks (TLS/WS)                                        */
/* ================================================================== */

static int
mqtt_client_data(mqtt_client_t *c, const char *data, ssize_t size);

static void
_broker_ws_on_open(wshttp_t *wh, void *io, void *ud) {
    mqtt_client_t *c;
    (void)wh;
    (void)ud;

    c = (mqtt_client_t *)io;

    LOG_D("client.%p websocket open", c);

    /* keep reading: wshttp_feed() is driven from _client_on_read() */
}

static void
_broker_ws_on_data(wshttp_t *wh, void *io, void *ud, int opcode, websocket_binary_t payload) {
    mqtt_client_t *c;
    (void)ud;
    (void)opcode;

    c = (mqtt_client_t *)io;

    if (mqtt_client_data(c, payload.data, (ssize_t)payload.length)) {
        wshttp_close(wh, WS_STATUS_NORMAL, "BYE");
    }
}

static void
_broker_ws_on_close(wshttp_t *wh, void *io, void *ud, websocket_binary_t payload) {
    mqtt_client_t *c;
    (void)wh;
    (void)ud;

    c = (mqtt_client_t *)io;

    if (payload.length) {
        LOG_D("client.%p websocket close status: %d, reason: %.*s", c, WS_CLOSE_STATUS(payload),
              WS_CLOSE_REASON_LEN(payload), WS_CLOSE_REASON(payload));
    } else {
        LOG_D("client.%p websocket close", c);
    }

    if (c->mode == MQTT_BROKER_MODE_WS) {
        mqtt_client_shutdown(c);
    } else if (c->mode == MQTT_BROKER_MODE_WSS) {
        tls_shutdown(c->tls);
    }
}

static int
_broker_ws_write(wshttp_t *wh, void *io, void *ud, const char *data, int size) {
    mqtt_client_t *c;
    (void)wh;
    (void)ud;

    c = (mqtt_client_t *)io;

    if (c->mode == MQTT_BROKER_MODE_WS) {
        return mqtt_client_send_raw(c, data, size);
    } else if (c->mode == MQTT_BROKER_MODE_WSS) {
        return tls_write(c->tls, data, size);
    }
    return -1;
}

static void
_broker_tls_on_open(tls_t *tls, void *io, void *ud) {
    mqtt_client_t *c;
    (void)tls;
    (void)ud;

    c = (mqtt_client_t *)io;

    LOG_D("client.%p tls open", c);

    if (c->mode == MQTT_BROKER_MODE_TLS) {
        uv_read_stop((uv_stream_t *)c->tcp);
    }
}

static void
_broker_tls_on_data(tls_t *tls, void *io, void *ud, const void *data, int size) {
    mqtt_client_t *c;
    (void)ud;

    c = (mqtt_client_t *)io;

    if (c->mode == MQTT_BROKER_MODE_TLS) {
        if (mqtt_client_data(c, (const char *)data, size)) {
            tls_shutdown(tls);
        }
    } else if (c->mode == MQTT_BROKER_MODE_WSS) {
        websocket_binary_t wsb = {.data = (char *)data, .length = (uint64_t)size};
        if (wshttp_feed(c->wh, &wsb)) {
            wshttp_close(c->wh, WS_STATUS_PROTOCOL_ERROR, "BYE");
        }
    }
}

static void
_broker_tls_on_close(tls_t *tls, void *io, void *ud) {
    mqtt_client_t *c;
    (void)tls;
    (void)ud;

    c = (mqtt_client_t *)io;

    LOG_D("client.%p tls close", c);
}

static int
_broker_tls_write(tls_t *tls, void *io, void *ud, const void *data, int size) {
    mqtt_client_t *c;
    (void)tls;
    (void)ud;

    c = (mqtt_client_t *)io;
    return mqtt_client_send_raw(c, (const char *)data, size);
}

/* ================================================================== */
/* Listener management                                                */
/* ================================================================== */

static void *
_mqtt_listener_key_pt(map_node_t *node) {
    mqtt_broker_listener_t *ln;

    ln = map_data(node, mqtt_broker_listener_t, node);
    return ln->id;
}

static int
_mqtt_listener_cmp_pt(void *a, void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static mqtt_broker_listener_t *
mqtt_listener_fetch(mqtt_broker_t *b, const char *id) {
    mqtt_broker_listener_t *ln;
    map_node_t *node;

    node = map_find(&b->listener_m, (void *)id);
    if (!node) {
        ln = (mqtt_broker_listener_t *)malloc(sizeof *ln);
        memset(ln, 0, sizeof *ln);
        ln->id = strdup(id);
        map_push(&b->listener_m, (void *)id, &ln->node);
    } else {
        ln = map_data(node, mqtt_broker_listener_t, node);
    }
    return ln;
}

static int
mqtt_listener_start(uv_loop_t *loop, mqtt_broker_t *b, mqtt_broker_listener_t *ln) {
    struct sockaddr_in addr;
    int rc;

    ln->server.data = ln;
    uv_tcp_init(loop, &ln->server);
    rc = uv_ip4_addr(ln->host, ln->port, &addr);
    if (rc) {
        LOG_E("ip4_addr %s:%d %s", ln->host, ln->port, uv_strerror(rc));
        return -1;
    }
    rc = uv_tcp_bind(&ln->server, (const struct sockaddr *)&addr, 0);
    if (rc) {
        LOG_E("bind %s:%d %s", ln->host, ln->port, uv_strerror(rc));
        return -1;
    }
    rc = uv_listen((uv_stream_t *)&ln->server, SOMAXCONN, _broker_on_connection);
    if (rc) {
        LOG_E("listen %s:%d %s", ln->host, ln->port, uv_strerror(rc));
        return -1;
    }

    if (ln->mode == MQTT_BROKER_MODE_TLS || ln->mode == MQTT_BROKER_MODE_WSS) {
        ln->tls_ctx = tls_server_ctx(ln->cert_file, ln->key_file);
        if (!ln->tls_ctx) {
            LOG_E("tls context init error");
            return -1;
        }
    }

    return 0;
}

/* ================================================================== */
/* Client ID generation                                               */
/* ================================================================== */

static void
mqtt_client_id_generate(mqtt_broker_t *b, mqtt_str_t *client_id) {
    long id;

    client_id->s = (char *)MQTT_MALLOC(SNOWFLAKE_ID_LEN + 1);
    id = snowflake_id(&b->snowflake);
    client_id->n = (size_t)sprintf(client_id->s, "%ld", id);
}

/* does topic filter F match concrete topic T? (+ = one level, # = rest) */
static int
_topic_filter_matches(mqtt_str_t *filter, mqtt_str_t *topic) {
    size_t fi = 0, ti = 0;

    while (fi < filter->n) {
        size_t fseg_end, tseg_end;

        if (filter->s[fi] == '#' && (fi == 0 || filter->s[fi - 1] == '/')) {
            return 1;
        }
        fseg_end = fi;
        while (fseg_end < filter->n && filter->s[fseg_end] != '/')
            fseg_end++;
        tseg_end = ti;
        while (tseg_end < topic->n && topic->s[tseg_end] != '/')
            tseg_end++;

        if (filter->s[fi] != '+') {
            if (fseg_end - fi != tseg_end - ti || strncmp(filter->s + fi, topic->s + ti, fseg_end - fi) != 0) {
                return 0;
            }
        }

        fi = fseg_end;
        ti = tseg_end;
        if (fi < filter->n && filter->s[fi] == '/')
            fi++;
        if (ti < topic->n && topic->s[ti] == '/')
            ti++;
    }
    return ti >= topic->n;
}

/* ACL check: 0 = allowed, -1 = denied. Empty acl_q = ACL disabled (allow all). */
static int
_mqtt_acl_check(mqtt_broker_t *b, mqtt_str_t *username, mqtt_str_t *topic, int is_publish) {
    queue_t *node;
    mqtt_str_t all = {.s = (char *)MQTT_ACL_ALL, .n = sizeof MQTT_ACL_ALL - 1};
    int allowed = 0;

    if (queue_empty(&b->acl_q)) {
        return 0;
    }

    queue_foreach(node, &b->acl_q) {
        mqtt_acl_rule_t *rule;

        rule = queue_data(node, mqtt_acl_rule_t, node);
        if (!(mqtt_str_equal(&rule->username, username) || mqtt_str_equal(&rule->username, &all))) {
            continue;
        }
        if (!_topic_filter_matches(&rule->topic, topic)) {
            continue;
        }
        if (rule->deny) {
            return -1;
        }
        if (is_publish && rule->pub)
            allowed = 1;
        if (!is_publish && rule->sub)
            allowed = 1;
    }
    return allowed ? 0 : -1;
}

/* does the provided password match the stored one?
 * stored may be plaintext or "sha256:<hex>" */
static int
_password_matches(mqtt_str_t *stored, mqtt_str_t *provided) {
    const char *prefix = "sha256:";
    size_t prefix_len = sizeof prefix - 1;

    if (stored->n > prefix_len && strncmp(stored->s, prefix, prefix_len) == 0) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        char hex[SHA256_DIGEST_LENGTH * 2 + 1];
        size_t i;

        SHA256((const unsigned char *)provided->s, provided->n, digest);
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            snprintf(hex + i * 2, 3, "%02x", digest[i]);
        }
        hex[SHA256_DIGEST_LENGTH * 2] = '\0';
        /* accept the stored hash in either case */
        if (stored->n - prefix_len != strlen(hex)) {
            return 0;
        }
        for (i = 0; i < strlen(hex); i++) {
            char c = stored->s[prefix_len + i];
            if (c >= 'A' && c <= 'F')
                c = c - 'A' + 'a';
            if (c != hex[i])
                return 0;
        }
        return 1;
    }
    return mqtt_str_equal(stored, provided);
}

static int
_authenticate_from_config(mqtt_broker_t *b, mqtt_p_connect_t *connect) {
    queue_t *node;

    queue_foreach(node, &b->account_q) {
        mqtt_account_t *acc;

        acc = queue_data(node, mqtt_account_t, node);
        if (mqtt_str_equal(&acc->username, &connect->username) && _password_matches(&acc->password, &connect->password)) {
            if (0 == mqtt_str_strcmp(&acc->client_id, "*") || mqtt_str_equal(&acc->client_id, &connect->client_id)) {
                return 0;
            }
        }
    }

    return -1;
}

static int
_tcp_connect(const char *host, int port) {
    struct addrinfo hints, *servinfo, *p;
    char ip[16];
    char portstr[6];
    int fd, rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_TCP;

    fd = -1;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if ((rc = getaddrinfo(host, portstr, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo %s e: %s\n", host, gai_strerror(rc));
        return -1;
    }
    for (p = servinfo; p; p = p->ai_next) {
        struct timeval timeout = {1, 0};
        int on = 1;

        if ((rc = getnameinfo(p->ai_addr, p->ai_addrlen, ip, sizeof(ip), portstr, sizeof(portstr),
                              NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
            continue;
        }
        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            fd = -1;
            continue;
        }
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    }
    freeaddrinfo(servinfo);

    return fd;
}

static ssize_t
_tcp_send(int fd, const void *data, size_t size) {
    ssize_t nsend, totlen = 0;
    char *buf = (char *)data;

    while ((size_t)totlen != size) {
        nsend = send(fd, buf, size - totlen, 0);
        if (nsend == 0)
            return -1;
        if (nsend == -1) {
            if (errno == EAGAIN)
                continue;
            return -1;
        }
        totlen += nsend;
        buf += nsend;
    }
    return totlen;
}

static ssize_t
_tcp_recv(int fd, void *data, size_t size) {
    ssize_t nrecv;

    nrecv = recv(fd, data, size, 0);
    if (nrecv == 0)
        return -1;
    if (nrecv == -1) {
        if (errno == EAGAIN)
            return 0;
        return -1;
    }
    return nrecv;
}

/* append a JSON-escaped copy of s[0..n) to dst (capacity cap); returns bytes written or -1 */
static int
_json_escape(char *dst, size_t cap, const char *s, size_t n) {
    size_t o = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        const char *esc = 0;
        char tmp[8];

        switch (ch) {
        case '"':
            esc = "\\\"";
            break;
        case '\\':
            esc = "\\\\";
            break;
        case '\b':
            esc = "\\b";
            break;
        case '\f':
            esc = "\\f";
            break;
        case '\n':
            esc = "\\n";
            break;
        case '\r':
            esc = "\\r";
            break;
        case '\t':
            esc = "\\t";
            break;
        default:
            if (ch < 0x20) {
                sprintf(tmp, "\\u%04x", ch);
                esc = tmp;
            }
            break;
        }
        if (esc) {
            size_t elen = strlen(esc);
            if (o + elen >= cap)
                return -1;
            memcpy(dst + o, esc, elen);
            o += elen;
        } else {
            if (o + 1 >= cap)
                return -1;
            dst[o++] = (char)ch;
        }
    }
    return (int)o;
}

static int
_authenticate_from_httpapi(mqtt_broker_t *b, const char *auth_api, mqtt_p_connect_t *connect) {
    char buf[4096] = {0};
    int ret_status = 401;
    int len;

    http_str_t req_body;

    (void)b;
    {
        int e;

        len = sprintf(buf, "{\"client_id\":\"");
        e = _json_escape(buf + len, sizeof buf - (size_t)len, connect->client_id.s, connect->client_id.n);
        if (e < 0)
            return -1;
        len += e;
        len += sprintf(buf + len, "\",\"username\":\"");
        e = _json_escape(buf + len, sizeof buf - (size_t)len, connect->username.s, connect->username.n);
        if (e < 0)
            return -1;
        len += e;
        len += sprintf(buf + len, "\",\"password\":\"");
        e = _json_escape(buf + len, sizeof buf - (size_t)len, connect->password.s, connect->password.n);
        if (e < 0)
            return -1;
        len += e;
        len += sprintf(buf + len, "\"}");
        if (len < 0 || (size_t)len >= sizeof buf)
            return -1;
    }

    req_body.s = buf;
    req_body.n = (size_t)len;

    http_request_t req;

    http_request_init(&req);
    http_url_parse(&req.url, auth_api);
    http_request_set_method(&req, "POST");
    http_request_set_header(&req, "Content-Type", "application/json");
    http_request_set_body(&req, req_body);
    http_str_t req_data = http_request_build(&req);

    int fd = _tcp_connect(req.url.host, req.url.port);
    if (-1 == fd) {
        free(req_data.s);
        http_request_unit(&req);
        LOG_W("can not connect to auth api:%s", auth_api);
        return -1;
    }

    _tcp_send(fd, req_data.s, req_data.n);
    LOG_D("auth api send: %.*s", (int)req_data.n, req_data.s);
    free(req_data.s);
    http_request_unit(&req);

    http_str_t res_data;
    res_data.n = _tcp_recv(fd, buf, 4096);
    res_data.s = buf;
    LOG_D("auth api recv: %.*s", (int)res_data.n, res_data.s);

    close(fd);

    http_response_t res;
    http_response_init(&res);
    if (0 == http_response_parse(&res, res_data)) {
        ret_status = res.status;
    }
    http_response_unit(&res);

    if (ret_status == 200) {
        return 0;
    }

    LOG_I("auth api status:%d", ret_status);

    return -1;
}

static int
mqtt_client_authenticate(mqtt_broker_t *b, mqtt_client_t *c, mqtt_p_connect_t *connect) {
    const char *auth_type;
    const char *auth_api;

    /* per-listener auth takes precedence over broker-level */
    auth_type = c->auth_type ? c->auth_type : b->auth_type;
    auth_api = c->auth_api ? c->auth_api : b->auth_api;

    if (!auth_type) {
        return 0;
    }
    if (b->auth_callback) {
        return b->auth_callback(connect->client_id.s, (int)connect->client_id.n,
                                connect->username.s, (int)connect->username.n,
                                connect->password.s, (int)connect->password.n,
                                b->auth_ud);
    }
    if (!strcmp(auth_type, "config"))
        return _authenticate_from_config(b, connect);
    else
        return _authenticate_from_httpapi(b, auth_api, connect);
}

static int
mqtt_on_connect(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_str_t client_id = MQTT_STR_INITIALIZER;
    mqtt_session_t *s;

    /* never log the password, only whether one was provided */
    LOG_I("[%.*s] received CONNECT (id: %.*s, v: %s, c: %" PRIu8 ", k: %" PRIu16 ", u: %.*s, p: %s)",
          MQTT_STR_PRINT(req->p.connect.client_id), MQTT_STR_PRINT(req->p.connect.client_id),
          mqtt_version_name(req->v.connect.protocol_version),
          (req->v.connect.connect_flags & MQTT_CF_CLEAN_SESSION) ? 1 : 0,
          req->v.connect.keep_alive, MQTT_STR_PRINT(req->p.connect.username),
          (req->v.connect.connect_flags & MQTT_CF_PASSWORD) ? "yes" : "no");
    if (req->v.connect.connect_flags & MQTT_CF_WILL_FLAG) {
        LOG_I("\tLWT (retain: %d, topic: %.*s, qos: %d, message: %.*s)",
              (req->v.connect.connect_flags & MQTT_CF_WILL_RETAIN) ? 1 : 0,
              MQTT_STR_PRINT(req->p.connect.will_topic), MQTT_CF_WILL_QOS(req->v.connect.connect_flags),
              MQTT_STR_PRINT(req->p.connect.will_message));
    }
    if (req->ver == MQTT_VERSION_5) {
        if (req->v.connect.connect_flags & MQTT_CF_WILL_FLAG) {
            LOG_PROP(&req->p.connect.v5.will_properties);
        }
        LOG_PROP(&req->v.connect.v5.properties);
    }

    res->f.flags = MQTT_FH_BUILD(MQTT_CONNACK, 0, 0, 0);

    switch (req->ver) {
    case MQTT_VERSION_3:
        if (req->p.connect.client_id.n < 1 || req->p.connect.client_id.n > 23) {
            res->v.connack.v3.return_code = MQTT_CRC_REFUSED_IDENTIFIER_REJECTED;
            goto e;
        }
        break;
    case MQTT_VERSION_4:
        if (!(req->v.connect.connect_flags & MQTT_CF_CLEAN_SESSION) && req->p.connect.client_id.n == 0) {
            res->v.connack.v4.return_code = MQTT_CRC_REFUSED_IDENTIFIER_REJECTED;
            goto e;
        }
        break;
    case MQTT_VERSION_5:
        if (req->p.connect.client_id.n > 23) {
            res->v.connack.v5.reason_code = MQTT_RC_CLIENT_IDENTIFIER_NOT_VALID;
            goto e;
        }
        break;
    }

    // authenticate
    if (mqtt_client_authenticate(b, c, &req->p.connect) != 0) {
        res->v.connack.v3.return_code = MQTT_CRC_REFUSED_BAD_USERNAME_PASSWORD;
        res->v.connack.v4.return_code = MQTT_CRC_REFUSED_BAD_USERNAME_PASSWORD;
        res->v.connack.v5.reason_code = MQTT_RC_BAD_USERNAME_OR_PASSWORD;
        goto e;
    }

    s = 0;
    if (req->p.connect.client_id.n > 0) {
        mqtt_str_copy(&client_id, &req->p.connect.client_id);
        s = mqtt_broker_find_session(b, &client_id);
        if (s) {
            if (s->c) {
                LOG_D("client.%p.kick", s->c);
                if (s->c->ver == MQTT_VERSION_5) {
                    mqtt_client_disconnect(s->c, MQTT_RC_SESSION_TAKEN_OVER);
                } else {
                    mqtt_client_shutdown(s->c);
                }
                s->c->s = 0;
                s->c = 0;
            }
            if (!(req->v.connect.connect_flags & MQTT_CF_CLEAN_SESSION)) {
                /* session resumed: cancel the pending expiry/will-delay timers */
                if (s->expiry_timer_on) {
                    uv_timer_stop(&s->expiry_timer);
                    s->expiry_timer_on = 0;
                }
                if (s->will_timer_on) {
                    uv_timer_stop(&s->will_timer);
                    s->will_timer_on = 0;
                }
                switch (req->ver) {
                case MQTT_VERSION_3:
                    break;
                case MQTT_VERSION_4:
                    res->v.connack.v4.acknowledge_flags.flags |= MQTT_ACK_SESSION_PRESENT;
                    break;
                case MQTT_VERSION_5:
                    res->v.connack.v5.acknowledge_flags.flags |= MQTT_ACK_SESSION_PRESENT;
                    break;
                }
            } else {
                mqtt_broker_remove_session(b, s);
                mqtt_session_destroy(b, s);
                s = 0;
            }
        }
    } else {
        /* a generated id must never collide with an existing session: map_push
         * silently drops a duplicate key, leaving an orphaned session whose
         * later erase corrupts the whole session map */
        for (;;) {
            mqtt_client_id_generate(b, &client_id);
            if (!mqtt_broker_find_session(b, &client_id))
                break;
            mqtt_str_free(&client_id);
        }
    }

    if (!s) {
        s = mqtt_session_create(b, &client_id);
        if (s) {
            mqtt_broker_add_session(b, s);
        }
    }
    if (!s) {
        switch (req->ver) {
        case MQTT_VERSION_3:
            res->v.connack.v3.return_code = MQTT_CRC_REFUSED_SERVER_UNAVAILABLE;
            break;
        case MQTT_VERSION_4:
            res->v.connack.v4.return_code = MQTT_CRC_REFUSED_SERVER_UNAVAILABLE;
            break;
        case MQTT_VERSION_5:
            res->v.connack.v5.reason_code = MQTT_RC_SERVER_UNAVAILABLE;
            break;
        }
        goto e;
    }

    c->clean_session = (req->v.connect.connect_flags & MQTT_CF_CLEAN_SESSION) ? 1 : 0;
    c->ver = req->ver;
    c->keep_alive = req->v.connect.keep_alive;
    mqtt_str_copy(&c->username, &req->p.connect.username);

    /* v5: read client capabilities from CONNECT properties.
     * in_alias_max  = what we accept from the client (what we advertise in CONNACK)
     * out_alias_max = what we may send to the client (what the client advertises,
     *                 0 = no topic aliases, [MQTT-3.3.2-8]) */
    s->in_alias_max = b->server_alias_max;
    s->out_alias_max = 0;
    s->receive_max = b->server_receive_max;
    s->session_expiry = 0;
    if (req->ver == MQTT_VERSION_5) {
        mqtt_property_t *prop;

        prop = mqtt_properties_find(&req->v.connect.v5.properties, MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL);
        if (prop) {
            s->session_expiry = prop->b4;
        }
        prop = mqtt_properties_find(&req->v.connect.v5.properties, MQTT_PROPERTY_RECEIVE_MAXIMUM);
        if (prop && prop->b2 > 0) {
            s->receive_max = prop->b2;
        }
        prop = mqtt_properties_find(&req->v.connect.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM);
        if (prop) {
            s->out_alias_max = prop->b2;
        }
        mqtt_session_alias_clear(s);
    }

    /* session is active again: cancel any pending will/expiry timers */
    if (s->will_timer_on) {
        uv_timer_stop(&s->will_timer);
        s->will_timer_on = 0;
    }
    if (s->expiry_timer_on) {
        uv_timer_stop(&s->expiry_timer);
        s->expiry_timer_on = 0;
    }

    /* will: stored on the session, replaces any previous will */
    if (s->lwt) {
        mqtt_message_destroy(s->lwt);
        s->lwt = 0;
    }
    s->will_delay = 0;
    if (req->v.connect.connect_flags & MQTT_CF_WILL_FLAG) {
        s->lwt = mqtt_lwt_create(s, req);
        if (req->ver == MQTT_VERSION_5) {
            mqtt_property_t *prop;

            prop = mqtt_properties_find(&req->p.connect.v5.will_properties, MQTT_PROPERTY_WILL_DELAY_INTERVAL);
            if (prop) {
                s->will_delay = prop->b4;
            }
        }
    }
    mqtt_broker_persist_mark(b);
    c->s = s;
    s->c = c;

    /* v5: advertise server capabilities in CONNACK */
    if (req->ver == MQTT_VERSION_5) {
        if (req->p.connect.client_id.n == 0) {
            mqtt_properties_add(&res->v.connack.v5.properties, MQTT_PROPERTY_ASSIGNED_CLIENT_IDENTIFIER, client_id.s, NULL);
        }
        mqtt_properties_add(&res->v.connack.v5.properties, MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL, &s->session_expiry, NULL);
        mqtt_properties_add(&res->v.connack.v5.properties, MQTT_PROPERTY_RECEIVE_MAXIMUM, &s->receive_max, NULL);
        mqtt_properties_add(&res->v.connack.v5.properties, MQTT_PROPERTY_MAXIMUM_QOS, &b->server_max_qos, NULL);
        mqtt_properties_add(&res->v.connack.v5.properties, MQTT_PROPERTY_RETAIN_AVAILABLE, &b->server_retain_available, NULL);
        mqtt_properties_add(&res->v.connack.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM, &b->server_alias_max, NULL);
        mqtt_properties_add(&res->v.connack.v5.properties, MQTT_PROPERTY_WILDCARD_SUBSCRIPTION_AVAILABLE,
                            &b->server_wildcard_available, NULL);
        mqtt_properties_add(&res->v.connack.v5.properties, MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIERS_AVAILABLE,
                            &b->server_sub_id_available, NULL);
        mqtt_properties_add(&res->v.connack.v5.properties, MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE,
                            &b->server_shared_available, NULL);
    }

    switch (req->ver) {
    case MQTT_VERSION_3:
        res->v.connack.v3.return_code = MQTT_CRC_ACCEPTED;
        break;
    case MQTT_VERSION_4:
        res->v.connack.v4.return_code = MQTT_CRC_ACCEPTED;
        break;
    case MQTT_VERSION_5:
        res->v.connack.v5.reason_code = MQTT_RC_SUCCESS;
        break;
    }

e:
    switch (req->ver) {
    case MQTT_VERSION_3:
        LOG_I("[%.*s] sending CONNACK (rc: 0x%02X %s)", MQTT_STR_PRINT(client_id), res->v.connack.v3.return_code,
              mqtt_crc_name(res->v.connack.v3.return_code));
        break;
    case MQTT_VERSION_4:
        LOG_I("[%.*s] sending CONNACK (sp: %" PRIu8 ", rc: 0x%02X %s)", MQTT_STR_PRINT(client_id),
              (uint8_t)(res->v.connack.v4.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT),
              res->v.connack.v4.return_code,
              mqtt_crc_name(res->v.connack.v4.return_code));
        break;
    case MQTT_VERSION_5:
        LOG_I("[%.*s] sending CONNACK (sp: %" PRIu8 ", rc: 0x%02X %s)", MQTT_STR_PRINT(client_id),
              (uint8_t)(res->v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT),
              res->v.connack.v5.reason_code,
              mqtt_rc_name(res->v.connack.v5.reason_code));
        LOG_PROP(&res->v.connack.v5.properties);
        break;
    }
    mqtt_str_free(&client_id);
    return 0;
}

static int
mqtt_on_auth(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_session_t *s;
    mqtt_property_t *method, *data;
    int rc;

    s = c->s;
    if (!s) {
        return -1;
    }

    method = mqtt_properties_find(&req->v.auth.v5.properties, MQTT_PROPERTY_AUTHENTICATION_METHOD);
    data = mqtt_properties_find(&req->v.auth.v5.properties, MQTT_PROPERTY_AUTHENTICATION_DATA);

    LOG_I("[%.*s] received AUTH (rc: 0x%02X %s, method: %.*s, data: %.*s)",
          MQTT_STR_PRINT(s->client_id), req->v.auth.v5.reason_code, mqtt_rc_name(req->v.auth.v5.reason_code),
          method ? (int)method->str.n : 0, method ? method->str.s : (char *)"",
          data ? (int)data->data.n : 0, data ? data->data.s : (char *)"");
    LOG_PROP(&req->v.auth.v5.properties);

    /* Extended authentication (MQTT 5): delegated to the custom auth callback,
     * which receives the authentication method as username and the
     * authentication data as password. Without a callback AUTH is a no-op. */
    if (b->auth_callback) {
        rc = b->auth_callback(s->client_id.s, (int)s->client_id.n,
                              method ? method->str.s : "", method ? (int)method->str.n : 0,
                              data ? data->data.s : "", data ? (int)data->data.n : 0,
                              b->auth_ud);
        if (rc != 0) {
            LOG_W("[%.*s] AUTH rejected by callback", MQTT_STR_PRINT(s->client_id));
            mqtt_packet_cleanup(res);
            mqtt_client_disconnect(c, MQTT_RC_NOT_AUTHORIZED);
            return -1;
        }
    }

    res->f.flags = MQTT_FH_BUILD(MQTT_AUTH, 0, 0, 0);
    res->v.auth.v5.reason_code = MQTT_RC_SUCCESS;

    LOG_I("[%.*s] sending AUTH (rc: 0x00 %s)", MQTT_STR_PRINT(s->client_id), mqtt_rc_name(MQTT_RC_SUCCESS));
    return 0;
}

static int
mqtt_on_publish(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_session_t *s;
    mqtt_message_t *msg;
    uint8_t dup;

    s = c->s;
    if (!s) {
        return -1;
    }

    if (b->rate_limit > 0) {
        if (c->t_rate != b->t_now) {
            c->t_rate = b->t_now;
            c->rate_count = 0;
        }
        if (++c->rate_count > b->rate_limit) {
            LOG_W("[%.*s] rate limit (%d msg/s) exceeded, disconnect", MQTT_STR_PRINT(s->client_id), b->rate_limit);
            if (c->ver == MQTT_VERSION_5) {
                mqtt_client_disconnect(c, MQTT_RC_QUOTA_EXCEEDED);
            } else {
                mqtt_client_shutdown(c);
            }
            return -1;
        }
    }
    b->msgs_received++;

    LOG_I("[%.*s] received PUBLISH (id: %" PRIu16 ", qos: %" PRIu8 ", retain: %" PRIu8 ", dup: %" PRIu8
          ", topic_name: %.*s, ...(%zu bytes))",
          MQTT_STR_PRINT(s->client_id), req->v.publish.packet_id, MQTT_FH_QOS(req->f.flags),
          MQTT_FH_RETAIN(req->f.flags), MQTT_FH_DUP(req->f.flags),
          MQTT_STR_PRINT(req->v.publish.topic_name), req->p.publish.message.n);
    if (req->ver == MQTT_VERSION_5) {
        LOG_PROP(&req->v.publish.v5.properties);
    }

    /* v5 incoming topic alias (client -> broker) */
    if (req->ver == MQTT_VERSION_5) {
        mqtt_property_t *alias_prop;

        alias_prop = mqtt_properties_find(&req->v.publish.v5.properties, MQTT_PROPERTY_TOPIC_ALIAS);
        if (alias_prop) {
            uint16_t alias = alias_prop->b2;

            if (alias == 0 || alias > s->in_alias_max) {
                LOG_W("[%.*s] invalid topic alias %" PRIu16 " (max %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), alias,
                      s->in_alias_max);
                if (MQTT_FH_QOS(req->f.flags) > MQTT_QOS_0) {
                    res->f.flags = MQTT_FH_BUILD(MQTT_PUBACK, 0, 0, 0);
                    res->v.puback.packet_id = req->v.publish.packet_id;
                    res->v.puback.v5.reason_code = MQTT_RC_TOPIC_ALIAS_INVALID;
                }
                return -1;
            }
            if (req->v.publish.topic_name.n > 0) {
                mqtt_session_alias_in_store(s, alias, &req->v.publish.topic_name);
            } else {
                mqtt_alias_entry_t *ae;

                ae = mqtt_session_alias_in_lookup(s, alias);
                if (!ae) {
                    LOG_W("[%.*s] unknown topic alias %" PRIu16, MQTT_STR_PRINT(s->client_id), alias);
                    if (MQTT_FH_QOS(req->f.flags) > MQTT_QOS_0) {
                        res->f.flags = MQTT_FH_BUILD(MQTT_PUBACK, 0, 0, 0);
                        res->v.puback.packet_id = req->v.publish.packet_id;
                        res->v.puback.v5.reason_code = MQTT_RC_TOPIC_ALIAS_INVALID;
                    }
                    return -1;
                }
                mqtt_str_set(&req->v.publish.topic_name, &ae->topic);
            }
        }
    }

    if (mqtt_topic_name_validate(&req->v.publish.topic_name) != 0) {
        LOG_W("invalid publish topic name %.*s", MQTT_STR_PRINT(req->v.publish.topic_name));
        if (req->ver == MQTT_VERSION_5 && MQTT_FH_QOS(req->f.flags) > MQTT_QOS_0) {
            res->f.flags = MQTT_FH_BUILD(MQTT_PUBACK, 0, 0, 0);
            res->v.puback.packet_id = req->v.publish.packet_id;
            res->v.puback.v5.reason_code = MQTT_RC_TOPIC_NAME_INVALID;
        }
        return -1;
    }

    if (_mqtt_acl_check(b, &c->username, &req->v.publish.topic_name, 1) != 0) {
        LOG_W("[%.*s] ACL denied PUBLISH on %.*s", MQTT_STR_PRINT(s->client_id),
              MQTT_STR_PRINT(req->v.publish.topic_name));
        if (c->ver == MQTT_VERSION_5) {
            mqtt_client_disconnect(c, MQTT_RC_NOT_AUTHORIZED);
        } else {
            mqtt_client_shutdown(c);
        }
        return -1;
    }

    msg = 0;
    if (MQTT_FH_QOS(req->f.flags) > MQTT_QOS_0) {
        msg = mqtt_session_incoming_message(s, req->v.publish.packet_id);
    }
    if (!msg) {
        dup = 0;
        msg = mqtt_message_create(b, s, req);
    } else {
        dup = 1;
    }

    if (!dup) {
        mqtt_broker_dispatch(b, msg);
    }

    switch (MQTT_FH_QOS(req->f.flags)) {
    case MQTT_QOS_0:
        break;
    case MQTT_QOS_1:
        res->f.flags = MQTT_FH_BUILD(MQTT_PUBACK, 0, 0, 0);
        res->v.puback.packet_id = req->v.publish.packet_id;
        LOG_I("[%.*s] sending PUBACK (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.puback.packet_id);
        break;
    case MQTT_QOS_2:
        res->f.flags = MQTT_FH_BUILD(MQTT_PUBREC, 0, 0, 0);
        res->v.pubrec.packet_id = req->v.publish.packet_id;
        if (!dup) {
            mqtt_publication_t *pub;

            pub = mqtt_publication_create(msg, req->v.publish.packet_id, msg->qos, msg->retain,
                                          MQTT_PUBLICATION_STATE_REL, b->t_now);
            mqtt_session_incoming_store(s, pub);
        }
        LOG_I("[%.*s] sending PUBREC (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.pubrec.packet_id);
        break;
    }
    return 0;
}

static int
mqtt_on_puback(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    (void)b;
    mqtt_session_t *s;
    (void)res;

    s = c->s;
    if (!s) {
        return -1;
    }
    switch (req->ver) {
    case MQTT_VERSION_3:
    case MQTT_VERSION_4:
        LOG_I("[%.*s] received PUBACK (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), req->v.puback.packet_id);
        break;
    case MQTT_VERSION_5:
        LOG_I("[%.*s] received PUBACK (id: %" PRIu16 ", rc: 0x%02X %s)", MQTT_STR_PRINT(s->client_id),
              req->v.puback.packet_id, req->v.puback.v5.reason_code, mqtt_rc_name(req->v.puback.v5.reason_code));
        LOG_PROP(&req->v.puback.v5.properties);
        break;
    }

    mqtt_session_outgoing_discard(s, req->v.puback.packet_id, MQTT_PUBLICATION_STATE_ACK);
    return 0;
}

static int
mqtt_on_pubrec(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_session_t *s;

    s = c->s;
    if (!s) {
        return -1;
    }
    switch (req->ver) {
    case MQTT_VERSION_3:
    case MQTT_VERSION_4:
        LOG_I("[%.*s] received PUBREC (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), req->v.pubrec.packet_id);
        break;
    case MQTT_VERSION_5:
        LOG_I("[%.*s] received PUBREC (id: %" PRIu16 ", rc: 0x%02X %s)", MQTT_STR_PRINT(s->client_id),
              req->v.pubrec.packet_id, req->v.pubrec.v5.reason_code, mqtt_rc_name(req->v.pubrec.v5.reason_code));
        LOG_PROP(&req->v.pubrec.v5.properties);
        break;
    }

    res->f.flags = MQTT_FH_BUILD(MQTT_PUBREL, 0, 1, 0);
    res->v.pubrel.packet_id = req->v.pubrec.packet_id;

    if (mqtt_session_outgoing_update(b, s, req->v.pubrec.packet_id, MQTT_PUBLICATION_STATE_REC,
                                     MQTT_PUBLICATION_STATE_REL) &&
        req->ver == MQTT_VERSION_5) {
        res->v.pubrel.v5.reason_code = MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND;
    }

    LOG_I("[%.*s] sending PUBREL (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.pubrel.packet_id);
    return 0;
}

static int
mqtt_on_pubrel(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    (void)b;
    mqtt_session_t *s;

    s = c->s;
    if (!s) {
        return -1;
    }
    switch (req->ver) {
    case MQTT_VERSION_3:
    case MQTT_VERSION_4:
        LOG_I("[%.*s] received PUBREL (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), req->v.pubrel.packet_id);
        break;
    case MQTT_VERSION_5:
        LOG_I("[%.*s] received PUBREL (id: %" PRIu16 ", rc: 0x%02X %s)", MQTT_STR_PRINT(s->client_id),
              req->v.pubrel.packet_id, req->v.pubrel.v5.reason_code, mqtt_rc_name(req->v.pubrel.v5.reason_code));
        LOG_PROP(&req->v.pubrel.v5.properties);
        break;
    }

    res->f.flags = MQTT_FH_BUILD(MQTT_PUBCOMP, 0, 0, 0);
    res->v.pubcomp.packet_id = req->v.pubrel.packet_id;

    if (mqtt_session_incoming_discard(s, req->v.pubrel.packet_id) && req->ver == MQTT_VERSION_5) {
        res->v.pubcomp.v5.reason_code = MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND;
    }

    LOG_I("[%.*s] sending PUBCOMP (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.pubcomp.packet_id);
    return 0;
}

static int
mqtt_on_pubcomp(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    (void)b;
    mqtt_session_t *s;
    (void)res;

    s = c->s;
    if (!s) {
        return -1;
    }
    switch (req->ver) {
    case MQTT_VERSION_3:
    case MQTT_VERSION_4:
        LOG_I("[%.*s] received PUBCOMP (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), req->v.pubcomp.packet_id);
        break;
    case MQTT_VERSION_5:
        LOG_I("[%.*s] received PUBCOMP (id: %" PRIu16 ", rc: 0x%02X %s)", MQTT_STR_PRINT(s->client_id),
              req->v.pubcomp.packet_id, req->v.pubcomp.v5.reason_code, mqtt_rc_name(req->v.pubcomp.v5.reason_code));
        LOG_PROP(&req->v.pubcomp.v5.properties);
        break;
    }

    mqtt_session_outgoing_discard(s, req->v.pubcomp.packet_id, MQTT_PUBLICATION_STATE_REL);
    return 0;
}

static int
mqtt_on_subscribe(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_session_t *s;
    int i;

    s = c->s;
    if (!s) {
        return -1;
    }
    LOG_I("[%.*s] received SUBSCRIBE (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), req->v.subscribe.packet_id);

    res->f.flags = MQTT_FH_BUILD(MQTT_SUBACK, 0, 0, 0);
    res->v.suback.packet_id = req->v.subscribe.packet_id;
    if (mqtt_suback_generate(res, req->p.subscribe.n)) {
        return -1;
    }

    for (i = 0; i < req->p.subscribe.n; i++) {
        mqtt_str_t topic_filter, share_group, actual_filter;
        mqtt_qos_t requested_qos, granted_qos;
        uint8_t nl = 0, rap = 0, retain_handling = 0;
        uint32_t sub_id = 0;

        topic_filter = req->p.subscribe.topic_filters[i];
        share_group = (mqtt_str_t){0};
        actual_filter = topic_filter;
        requested_qos = (mqtt_qos_t)(req->p.subscribe.options[i].flags & MQTT_SUBOPT_QOS_MASK);

        if (req->ver == MQTT_VERSION_5) {
            mqtt_property_t *prop;

            nl = (req->p.subscribe.options[i].flags & MQTT_SUBOPT_NL) ? 1 : 0;
            rap = (req->p.subscribe.options[i].flags & MQTT_SUBOPT_RAP) ? 1 : 0;
            retain_handling = MQTT_SUBOPT_RH(req->p.subscribe.options[i].flags);
            prop = mqtt_properties_find(&req->v.subscribe.v5.properties, MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER);
            if (prop) {
                /* [MQTT-3.8.3-8]: the server MUST NOT use ids above 0x10000000 */
                sub_id = (prop->bv > 0x10000000u) ? 0 : prop->bv;
            }
        }

        /* $share/group/filter: split the shared prefix from the actual filter */
        if (topic_filter.n > 7 && memcmp(topic_filter.s, "$share/", 7) == 0) {
            mqtt_str_t rest = {.s = topic_filter.s + 7, .n = topic_filter.n - 7};
            char *slash;

            slash = memchr(rest.s, '/', rest.n);
            if (!slash || slash == rest.s) {
                if (req->ver == MQTT_VERSION_5) {
                    res->p.suback.v5.reason_codes[i] = MQTT_RC_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED;
                } else {
                    mqtt_client_disconnect(c, MQTT_RC_MALFORMED_PACKET);
                    return -1;
                }
                continue;
            }
            share_group = (mqtt_str_t){.s = rest.s, .n = (size_t)(slash - rest.s)};
            actual_filter = (mqtt_str_t){.s = slash + 1, .n = rest.n - (size_t)(slash - rest.s) - 1};
        }

        LOG_I("\ttopic_filter: %.*s, qos: %d, nl: %d, rap: %d, retain_handling: %d, sub_id: %" PRIu32,
              MQTT_STR_PRINT(topic_filter), requested_qos, nl, rap, retain_handling, sub_id);

        /* Validate the actual (non-shared) topic filter */
        if (mqtt_topic_filter_validate(&actual_filter)) {
            if (req->ver == MQTT_VERSION_5) {
                res->p.suback.v5.reason_codes[i] = MQTT_RC_TOPIC_FILTER_INVALID;
            } else {
                /* v3.x: entire SUBSCRIBE fails with 0x80 (Malformed Packet) */
                mqtt_client_disconnect(c, MQTT_RC_MALFORMED_PACKET);
                mqtt_packet_cleanup(res);
                return -1;
            }
            continue;
        }

        /* ACL: check subscribe permission on the actual filter */
        if (_mqtt_acl_check(b, &c->username, &actual_filter, 0) != 0) {
            LOG_W("[%.*s] ACL denied SUBSCRIBE on %.*s", MQTT_STR_PRINT(s->client_id), MQTT_STR_PRINT(actual_filter));
            if (req->ver == MQTT_VERSION_5) {
                res->p.suback.v5.reason_codes[i] = MQTT_RC_NOT_AUTHORIZED;
            } else {
                mqtt_client_disconnect(c, MQTT_RC_NOT_AUTHORIZED);
                mqtt_packet_cleanup(res);
                return -1;
            }
            continue;
        }

        granted_qos = mqtt_session_subscribe(b, c->s, &topic_filter, &share_group, sub_id, requested_qos, nl, rap,
                                             retain_handling);

        switch (req->ver) {
        case MQTT_VERSION_3:
            res->p.suback.v3.granted[i].flags = (uint8_t)(granted_qos & MQTT_SUBOPT_QOS_MASK);
            break;
        case MQTT_VERSION_4:
            res->p.suback.v4.return_codes[i] = mqtt_src_from_qos(granted_qos);
            break;
        case MQTT_VERSION_5:
            res->p.suback.v5.reason_codes[i] = mqtt_rc_from_qos(granted_qos);
            break;
        }
    }

    if (req->ver == MQTT_VERSION_5) {
        LOG_PROP(&req->v.subscribe.v5.properties);
    }

    LOG_I("[%.*s] sending SUBACK (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.suback.packet_id);
    for (i = 0; i < res->p.suback.n; i++) {
        switch (req->ver) {
        case MQTT_VERSION_3:
            LOG_I("\tqos: %d", res->p.suback.v3.granted[i].flags & MQTT_SUBOPT_QOS_MASK);
            break;
        case MQTT_VERSION_4:
            LOG_I("\trc: 0x%02X %s", res->p.suback.v4.return_codes[i], mqtt_src_name(res->p.suback.v4.return_codes[i]));
            break;
        case MQTT_VERSION_5:
            LOG_I("\trc: 0x%02X %s", res->p.suback.v5.reason_codes[i], mqtt_rc_name(res->p.suback.v5.reason_codes[i]));
            LOG_PROP(&res->v.suback.v5.properties);
            break;
        }
    }
    return 0;
}

static int
mqtt_on_unsubscribe(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_session_t *s;
    int i;

    s = c->s;
    if (!s) {
        return -1;
    }
    LOG_I("[%.*s] received UNSUBSCRIBE (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), req->v.unsubscribe.packet_id);

    res->f.flags = MQTT_FH_BUILD(MQTT_UNSUBACK, 0, 0, 0);
    res->v.unsuback.packet_id = req->v.unsubscribe.packet_id;
    if (mqtt_unsuback_generate(res, req->p.unsubscribe.n)) {
        return -1;
    }

    for (i = 0; i < req->p.unsubscribe.n; i++) {
        mqtt_str_t topic_filter = req->p.unsubscribe.topic_filters[i];
        int rc;

        LOG_I("\ttopic_filter: %.*s", MQTT_STR_PRINT(topic_filter));

        /* the parser does not reject invalid filters so the handler can
         * answer: v5 gets UNSUBACK 0x8F ([MQTT-3.10.4]), v3.x is closed */
        if (mqtt_topic_filter_validate(&topic_filter)) {
            if (req->ver == MQTT_VERSION_5) {
                res->p.unsuback.v5.reason_codes[i] = MQTT_RC_TOPIC_FILTER_INVALID;
            } else {
                /* v3.x: entire UNSUBSCRIBE fails with 0x80 (Malformed Packet) */
                mqtt_client_disconnect(c, MQTT_RC_MALFORMED_PACKET);
                mqtt_packet_cleanup(res);
                return -1;
            }
            continue;
        }

        rc = mqtt_session_unsubscribe(b, c->s, &topic_filter);
        if (req->ver == MQTT_VERSION_5) {
            res->p.unsuback.v5.reason_codes[i] = rc ? MQTT_RC_NO_SUBSCRIPTION_EXISTED : MQTT_RC_SUCCESS;
        }
    }
    if (req->ver == MQTT_VERSION_5) {
        LOG_PROP(&req->v.unsubscribe.v5.properties);
    }

    LOG_I("[%.*s] sending UNSUBACK (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.unsuback.packet_id);
    for (i = 0; i < res->p.unsuback.v5.n; i++) {
        if (req->ver == MQTT_VERSION_5) {
            LOG_I("\trc: 0x%02X %s", res->p.unsuback.v5.reason_codes[i],
                  mqtt_rc_name(res->p.unsuback.v5.reason_codes[i]));
            LOG_PROP(&res->v.unsuback.v5.properties);
        }
    }
    return 0;
}

static int
mqtt_on_pingreq(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    (void)b;
    mqtt_session_t *s;
    (void)req;

    s = c->s;
    if (!s) {
        return -1;
    }
    LOG_I("[%.*s] received PINGREQ", MQTT_STR_PRINT(s->client_id));

    res->f.flags = MQTT_FH_BUILD(MQTT_PINGRESP, 0, 0, 0);

    LOG_I("[%.*s] sending PINGRESP", MQTT_STR_PRINT(s->client_id));
    return 0;
}

static int
mqtt_on_disconnect(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    (void)b;
    mqtt_session_t *s;
    (void)res;

    s = c->s;
    if (!s) {
        return -1;
    }
    switch (req->ver) {
    case MQTT_VERSION_3:
    case MQTT_VERSION_4:
        LOG_I("[%.*s] received DISCONNECT", MQTT_STR_PRINT(s->client_id));
        break;
    case MQTT_VERSION_5:
        LOG_I("[%.*s] received DISCONNECT (rc: 0x%02X %s)", MQTT_STR_PRINT(s->client_id),
              req->v.disconnect.v5.reason_code, mqtt_rc_name(req->v.disconnect.v5.reason_code));
        LOG_PROP(&req->v.disconnect.v5.properties);
        break;
    }

    /* clean disconnect: the will is cancelled, not published */
    if (s->lwt) {
        mqtt_message_destroy(s->lwt);
        s->lwt = 0;
    }
    if (s->will_timer_on) {
        uv_timer_stop(&s->will_timer);
        s->will_timer_on = 0;
    }
    mqtt_broker_persist_mark(b);

    /* v5: client may set a new session expiry on disconnect */
    if (req->ver == MQTT_VERSION_5) {
        mqtt_property_t *prop;

        prop = mqtt_properties_find(&req->v.disconnect.v5.properties, MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL);
        if (prop) {
            s->session_expiry = prop->b4;
        }
    }

    return 1;
}

static int
mqtt_client_handle(mqtt_broker_t *b, mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    int rc;

    switch (MQTT_FH_TYPE(req->f.flags)) {
    case MQTT_CONNECT:
        rc = mqtt_on_connect(b, c, req, res);
        break;
    case MQTT_AUTH:
        rc = mqtt_on_auth(b, c, req, res);
        break;
    case MQTT_PUBLISH:
        rc = mqtt_on_publish(b, c, req, res);
        break;
    case MQTT_PUBACK:
        rc = mqtt_on_puback(b, c, req, res);
        break;
    case MQTT_PUBREC:
        rc = mqtt_on_pubrec(b, c, req, res);
        break;
    case MQTT_PUBREL:
        rc = mqtt_on_pubrel(b, c, req, res);
        break;
    case MQTT_PUBCOMP:
        rc = mqtt_on_pubcomp(b, c, req, res);
        break;
    case MQTT_SUBSCRIBE:
        rc = mqtt_on_subscribe(b, c, req, res);
        break;
    case MQTT_UNSUBSCRIBE:
        rc = mqtt_on_unsubscribe(b, c, req, res);
        break;
    case MQTT_PINGREQ:
        rc = mqtt_on_pingreq(b, c, req, res);
        break;
    case MQTT_DISCONNECT:
        rc = mqtt_on_disconnect(b, c, req, res);
        break;
    case MQTT_RESERVED:
    default:
        rc = -1;
        break;
    }
    return rc;
}

static int
mqtt_client_data(mqtt_client_t *c, const char *data, ssize_t size) {
    mqtt_broker_t *b = c->b;
    mqtt_str_t buf;
    mqtt_packet_t req;
    int rc;

    logger_print(logger_default(), LOG_LEVEL_DEBUG, "receive:\n");
    logger_print(logger_default(), LOG_LEVEL_DEBUG, "--------------------------------------------------\n");
    LOG_DUMP(data, size);
    logger_print(logger_default(), LOG_LEVEL_DEBUG, "++++++++++++++++++++++++++++++++++++++++++++++++++\n");

    mqtt_str_init(&buf, (char *)data, (size_t)size);
    while ((rc = mqtt_parse(&c->parser, &buf, &req)) > 0) {
        mqtt_packet_t res;

        mqtt_packet_init(&res, req.ver, MQTT_RESERVED);

        c->t_last = b->t_now;

        rc = mqtt_client_handle(b, c, &req, &res);
        /* a response is sent even when the handler errors out (e.g. PUBACK
         * 0x94 for an invalid topic alias before the connection is dropped) */
        if (MQTT_IS_PACKET_TYPE(MQTT_FH_TYPE(res.f.flags))) {
            int rc_send = mqtt_client_send(c, &res);

            if (rc == 0) {
                rc = rc_send;
            }
        }
        mqtt_packet_cleanup(&req);
        if (rc) {
            if (!c->closed) {
                mqtt_client_shutdown(c);
            }
            break;
        }
    }
    return rc;
}

static mqtt_client_t *
mqtt_client_create(mqtt_broker_t *b, uv_tcp_t *tcp, const char *ip, int port, mqtt_broker_mode_t mode, tls_ctx_t *tls_ctx) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)malloc(sizeof *c);
    memset(c, 0, sizeof *c);
    c->b = b;
    c->mode = mode;

    mqtt_parser_init(&c->parser);
    strcpy(c->ip, ip);
    c->port = port;
    c->tcp = tcp;
    c->tcp->data = c;

    if (mode == MQTT_BROKER_MODE_WS || mode == MQTT_BROKER_MODE_WSS) {
        wshttp_config_t config = {
            .mode = WS_MODE_SERVER,
            .on_open = _broker_ws_on_open,
            .on_data = _broker_ws_on_data,
            .on_close = _broker_ws_on_close,
            .write = _broker_ws_write,
            .io = c,
        };
        c->wh = wshttp_create(&config);
    }

    if (mode == MQTT_BROKER_MODE_TLS || mode == MQTT_BROKER_MODE_WSS) {
        tls_config_t cfg = {
            .on_open = _broker_tls_on_open,
            .on_data = _broker_tls_on_data,
            .on_close = _broker_tls_on_close,
            .write = _broker_tls_write,
            .io = c,
        };
        c->tls = tls_create(tls_ctx, &cfg);
    }

    LOG_D("client.%p.create ip:%s mode:%d", c, ip, mode);
    return c;
}

static void
mqtt_client_destroy(mqtt_client_t *c) {
    mqtt_broker_t *b = c->b;
    mqtt_session_t *s;

    LOG_D("client.%p.destroy %s:%d", c, c->ip, c->port);
    if (c->wh) {
        wshttp_destroy(c->wh);
    }
    if (c->tls) {
        tls_destroy(c->tls);
    }
    mqtt_parser_cleanup(&c->parser);
    mqtt_str_free(&c->buff);
    mqtt_str_free(&c->username);

    s = c->s;
    if (s) {
        /* v5: a session whose expiry interval is 0 (the default when the
         * property is absent) ends when the network connection ends,
         * [MQTT-3.1.2-24/25]; only persistent sessions (expiry > 0, or v3.x
         * clean_session=0) survive the disconnect */
        if (c->clean_session || (c->ver == MQTT_VERSION_5 && s->session_expiry == 0)) {
            mqtt_broker_remove_session(b, s);
            mqtt_session_destroy(b, s);
        } else {
            s->c = 0;
        }
    }
    free(c);
}

static int
mqtt_client_update(mqtt_broker_t *b, mqtt_client_t *c) {
    if (c->keep_alive > 0) {
        uint64_t expired = (uint64_t)c->keep_alive * 3 / 2;
        if ((int64_t)(b->t_now - c->t_last) > (int64_t)expired) {
            return -1;
        }
    }
    return 0;
}

static void
_client_on_close(uv_handle_t *handle) {
    mqtt_broker_t *b;
    mqtt_client_t *c;

    c = (mqtt_client_t *)handle->data;

    free(handle);

    if (!c) {
        return;
    }
    b = c->b;
    if (c->s && c->s->lwt) {
        /* abnormal close with a registered will */
        if (!c->clean_session && c->s->will_delay > 0) {
            /* persistent session: delay the will */
            uv_timer_start(&c->s->will_timer, _broker_on_will_timer, (uint64_t)c->s->will_delay * 1000, 0);
            c->s->will_timer_on = 1;
        } else {
            mqtt_message_t *lwt = c->s->lwt;

            c->s->lwt = 0;
            if (c->s->will_timer_on) {
                uv_timer_stop(&c->s->will_timer);
                c->s->will_timer_on = 0;
            }
            LOG_I("[%.*s] publishing will", MQTT_STR_PRINT(c->s->client_id));
            mqtt_broker_dispatch(b, lwt);
        }
        mqtt_broker_persist_mark(b);
    }
    if (c->s && !c->clean_session && c->s->session_expiry > 0) {
        uv_timer_start(&c->s->expiry_timer, _broker_on_session_expiry, (uint64_t)c->s->session_expiry * 1000, 0);
        c->s->expiry_timer_on = 1;
    }
    mqtt_broker_remove_client(b, c);
    b->connections--;
    mqtt_client_destroy(c);

    /* last client gone during shutdown: nothing left to drain */
    if (b->shutdown_pending && b->shutdown_timer_on && queue_empty(&b->client_q)) {
        uv_timer_stop(&b->shutdown_timer);
    }
}

static void
_client_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)stream->data;
    if (nread < 0) {
        if (nread != UV_EOF) {
            LOG_W("read: %s", uv_strerror(nread));
        }
        LOG_D("client.%p.close %s:%d", c, c->ip, c->port);
        /* gate off further send/shutdown on the handle while it is closing */
        c->closed = 1;
        uv_close((uv_handle_t *)stream, _client_on_close);
        return;
    }

    /* Protocol dispatch */
    if (c->mode == MQTT_BROKER_MODE_TCP) {
        if (mqtt_client_data(c, buf->base, nread)) {
            mqtt_client_shutdown(c);
        }
    } else if (c->mode == MQTT_BROKER_MODE_TLS) {
        if (tls_feed(c->tls, buf->base, nread)) {
            tls_shutdown(c->tls);
        }
    } else if (c->mode == MQTT_BROKER_MODE_WS) {
        websocket_binary_t wsb = {.data = buf->base, .length = (uint64_t)nread};
        if (wshttp_feed(c->wh, &wsb)) {
            wshttp_close(c->wh, WS_STATUS_PROTOCOL_ERROR, "BYE");
        }
    } else if (c->mode == MQTT_BROKER_MODE_WSS) {
        if (tls_feed(c->tls, buf->base, nread)) {
            tls_shutdown(c->tls);
        }
    }
}

static void
_client_on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)handle->data;
    if (c->buff.s && c->buff.n != suggested_size) {
        mqtt_str_free(&c->buff);
    }
    if (!c->buff.s) {
        c->buff.s = (char *)MQTT_MALLOC(suggested_size);
        c->buff.n = suggested_size;
    }
    buf->base = c->buff.s;
    buf->len = c->buff.n;
}

static void
_broker_on_connection(uv_stream_t *server, int status) {
    mqtt_broker_t *b = server->loop->data;
    mqtt_broker_listener_t *ln;
    uv_tcp_t *tcp;
    mqtt_client_t *c;
    struct sockaddr addr;
    char ip[INET6_ADDRSTRLEN];
    int rc, addrlen, port;

    if (status != 0) {
        LOG_W("connect: %s", uv_strerror(status));
        return;
    }

    ln = (mqtt_broker_listener_t *)server->data;

    tcp = (uv_tcp_t *)malloc(sizeof *tcp);
    uv_tcp_init(server->loop, tcp);
    tcp->data = NULL; /* uv_tcp_init does not touch the user data field */
    rc = uv_accept(server, (uv_stream_t *)tcp);
    if (rc) {
        LOG_W("accept: %s", uv_strerror(rc));
        uv_close((uv_handle_t *)tcp, _client_on_close);
        return;
    }

    addrlen = sizeof(addr);
    uv_tcp_getpeername(tcp, &addr, &addrlen);
    uv_ip4_name((struct sockaddr_in *)&addr, ip, sizeof(ip));
    port = ntohs(((struct sockaddr_in *)&addr)->sin_port);

    if (b->max_connections > 0 && b->connections >= b->max_connections) {
        LOG_W("max connections (%d) reached, reject %s:%d", b->max_connections, ip, port);
        uv_close((uv_handle_t *)tcp, _client_on_close);
        return;
    }

    uv_read_start((uv_stream_t *)tcp, _client_on_alloc, _client_on_read);

    c = mqtt_client_create(b, tcp, ip, port, ln->mode, ln->tls_ctx);
    /* per-listener auth (shared pointers, owned by the listener) */
    c->auth_type = ln->auth_type;
    c->auth_api = ln->auth_api;
    mqtt_broker_add_client(b, c);
}

static void
_broker_publish_sys(mqtt_broker_t *b, const char *topic, const char *value) {
    mqtt_message_t *msg;
    mqtt_str_t t, v;

    msg = (mqtt_message_t *)malloc(sizeof *msg);
    memset(msg, 0, sizeof *msg);
    msg->qos = MQTT_QOS_0;
    mqtt_str_from(&t, topic);
    mqtt_str_copy(&msg->topic_name, &t);
    mqtt_str_from(&v, value);
    mqtt_str_copy(&msg->payload, &v);
    msg->ref = 1;
    mqtt_broker_dispatch(b, msg);
}

static void
_broker_on_sys_timer(uv_timer_t *handle) {
    mqtt_broker_t *b = handle->data;
    char buf[64];

    (void)handle;

    snprintf(buf, sizeof buf, "%d", b->t_now);
    _broker_publish_sys(b, "$SYS/broker/uptime", buf);

    snprintf(buf, sizeof buf, "%llu", (unsigned long long)b->msgs_received);
    _broker_publish_sys(b, "$SYS/broker/messages/received", buf);

    snprintf(buf, sizeof buf, "%llu", (unsigned long long)b->msgs_sent);
    _broker_publish_sys(b, "$SYS/broker/messages/sent", buf);

    snprintf(buf, sizeof buf, "%d", b->connections);
    _broker_publish_sys(b, "$SYS/broker/clients/connected", buf);

    snprintf(buf, sizeof buf, "%u", b->subscriptions);
    _broker_publish_sys(b, "$SYS/broker/subscriptions/count", buf);

    snprintf(buf, sizeof buf, "%u", b->retained_count);
    _broker_publish_sys(b, "$SYS/broker/retained/count", buf);
}

static void
_broker_on_timer(uv_timer_t *handle) {
    mqtt_broker_t *b = handle->data;
    queue_t *node;

    b->t_now++;
    LOG_UPDATE(b->t_now);
    queue_foreach(node, &b->client_q) {
        mqtt_client_t *c;

        c = queue_data(node, mqtt_client_t, node);
        if (c->closed) {
            continue;
        }
        if (mqtt_client_update(b, c)) {
            LOG_D("client.%p.timeout", c);
            mqtt_client_shutdown(c);
            continue;
        }
        mqtt_client_retransmit(b, c);
        if (c->s && !queue_empty(&c->s->offline)) {
            mqtt_session_offline_pump(b, c->s);
        }
    }
    if (b->persist_dirty) {
        mqtt_broker_persist_save(b);
    }
}

static int
_broker_config(void *ud, const char *section, const char *key, const char *value) {
    mqtt_broker_t *b = (mqtt_broker_t *)ud;
    LOG_D("[%s] %s = %s", section, key, value);

    if (!value) {
        return 0;
    }

    if (!strcmp(section, "log")) {
        if (!strcmp(key, "level")) {
            if (!strcmp(value, "debug")) {
                LOG_SET_LEVEL(LOG_LEVEL_DEBUG);
            } else if (!strcmp(value, "info")) {
                LOG_SET_LEVEL(LOG_LEVEL_INFO);
            } else if (!strcmp(value, "warn")) {
                LOG_SET_LEVEL(LOG_LEVEL_WARN);
            } else if (!strcmp(value, "error")) {
                LOG_SET_LEVEL(LOG_LEVEL_ERROR);
            } else {
                LOG_E("invalid log level %s", value);
                return -1;
            }
        } else if (!strcmp(key, "file")) {
            LOG_SET_FILE(value);
        }
    }

    if (!strcmp(section, "net")) {
        if (!strcmp(key, "host")) {
            b->host = strdup(value);
        } else if (!strcmp(key, "port")) {
            b->port = atoi(value);
        }
    }

    if (!strcmp(section, "auth")) {
        if (!strcmp(key, "type")) {
            b->auth_type = strdup(value);
        } else if (!strcmp(key, "api")) {
            b->auth_api = strdup(value);
        }
    }

    if (!strcmp(section, "limit")) {
        if (!strcmp(key, "max_connections")) {
            b->max_connections = atoi(value);
        } else if (!strcmp(key, "rate_limit")) {
            b->rate_limit = atoi(value);
        } else if (!strcmp(key, "max_write_pending")) {
            b->max_write_pending = (size_t)atol(value);
        }
    }

    if (!strcmp(section, "debug")) {
        if (!strcmp(key, "trie_dump")) {
            b->trie_dump_enabled = atoi(value);
        }
    }

    if (!strcmp(section, "sys")) {
        if (!strcmp(key, "interval")) {
            b->sys_interval = atoi(value);
        }
    }

    if (!strcmp(section, "persist")) {
        if (!strcmp(key, "file")) {
            b->persist_file = strdup(value);
        }
    }

    if (!strcmp(section, "user")) {
        char *client_id = strchr(value, ',');
        if (!client_id) {
            return -1;
        }

        mqtt_account_t *acc = (mqtt_account_t *)malloc(sizeof *acc);
        mqtt_str_dup(&acc->username, key);
        mqtt_str_dup(&acc->client_id, client_id + 1);
        mqtt_str_dup_n(&acc->password, value, client_id - value);

        queue_insert_tail(&b->account_q, &acc->node);
    }

    if (!strcmp(section, "acl")) {
        /* key=username, value=topic,access  (access: pub|sub|rw|deny) */
        char *comma;
        mqtt_acl_rule_t *rule;

        comma = strrchr(value, ',');
        if (!comma) {
            return -1;
        }
        rule = (mqtt_acl_rule_t *)malloc(sizeof *rule);
        memset(rule, 0, sizeof *rule);
        mqtt_str_dup(&rule->username, key);
        mqtt_str_dup_n(&rule->topic, value, (size_t)(comma - value));
        if (!strcmp(comma + 1, "pub")) {
            rule->pub = 1;
        } else if (!strcmp(comma + 1, "sub")) {
            rule->sub = 1;
        } else if (!strcmp(comma + 1, "rw")) {
            rule->pub = 1;
            rule->sub = 1;
        } else if (!strcmp(comma + 1, "deny")) {
            rule->deny = 1;
        } else {
            free(rule);
            return -1;
        }
        queue_insert_tail(&b->acl_q, &rule->node);
    }

    if (!strncmp(section, "listener-", 9)) {
        mqtt_broker_listener_t *ln;
        const char *id;

        id = section + 9;
        ln = mqtt_listener_fetch(b, id);
        if (!strcmp(key, "host")) {
            ln->host = strdup(value);
        } else if (!strcmp(key, "port")) {
            ln->port = atoi(value);
        } else if (!strcmp(key, "cert")) {
            ln->cert_file = strdup(value);
        } else if (!strcmp(key, "key")) {
            ln->key_file = strdup(value);
        } else if (!strcmp(key, "auth")) {
            ln->auth_type = strdup(value);
        } else if (!strcmp(key, "api")) {
            ln->auth_api = strdup(value);
        } else if (!strcmp(key, "mode")) {
            if (!strcmp(value, "tcp")) {
                ln->mode = MQTT_BROKER_MODE_TCP;
            } else if (!strcmp(value, "tls")) {
                ln->mode = MQTT_BROKER_MODE_TLS;
                b->tls_on = 1;
            } else if (!strcmp(value, "ws")) {
                ln->mode = MQTT_BROKER_MODE_WS;
            } else if (!strcmp(value, "wss")) {
                ln->mode = MQTT_BROKER_MODE_WSS;
                b->tls_on = 1;
            }
        }
    }

    return 0;
}

/* ================================================================== */
/* Persistence: retained messages + persistent sessions               */
/* File format (one record per line, binary strings hex-encoded,      */
/* "-" marks an empty string):                                        */
/*   KMQLP1                                                           */
/*   RETAIN <qos> <topic> <payload> <props>                           */
/*   SESSION <client_id> <session_expiry>                             */
/*   SUB <filter> <share|-> <sub_id> <qos> <nl> <rap> <retain_h>      */
/*   WILL <qos> <retain> <delay> <topic> <payload>                    */
/*   OFFLINE <filter> <qos> <retain> <topic> <payload> <props>        */
/* ================================================================== */

#define PERSIST_MAGIC "KMQLP1"

static void
mqtt_broker_persist_mark(mqtt_broker_t *b) {
    if (b->persist_file) {
        b->persist_dirty = 1;
    }
}

static int
_persist_hexval(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static char *
_persist_hex_encode(const void *data, size_t n) {
    static const char digits[] = "0123456789abcdef";
    const unsigned char *p = (const unsigned char *)data;
    char *out = (char *)MQTT_MALLOC(n * 2 + 1);
    size_t i;

    if (!out) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        out[i * 2] = digits[p[i] >> 4];
        out[i * 2 + 1] = digits[p[i] & 0x0f];
    }
    out[n * 2] = '\0';
    return out;
}

static int
_persist_hex_decode(const char *hex, char **out) {
    size_t n = strlen(hex);
    char *buf;
    size_t i;

    if (n % 2) {
        return -1;
    }
    buf = (char *)MQTT_MALLOC(n / 2 ? n / 2 : 1);
    if (!buf) {
        return -1;
    }
    for (i = 0; i < n / 2; i++) {
        int hi = _persist_hexval(hex[i * 2]);
        int lo = _persist_hexval(hex[i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            MQTT_FREE(buf);
            return -1;
        }
        buf[i] = (char)(hi * 16 + lo);
    }
    *out = buf;
    return (int)(n / 2);
}

/* property list to hex (empty list = "00"), using the wire encoding */
static char *
_persist_props_encode(const mqtt_properties_t *props) {
    mqtt_str_t b;
    size_t len;
    char *buf, *hex;

    len = __properties_len(props);
    buf = (char *)MQTT_MALLOC(len);
    if (!buf) {
        return NULL;
    }
    mqtt_str_init(&b, buf, len);
    __properties_serialize(props, &b);
    hex = _persist_hex_encode(buf, b.n);
    MQTT_FREE(buf);
    return hex;
}

static int
_persist_props_decode(const char *hex, mqtt_properties_t *props) {
    char *buf;
    int n;
    mqtt_str_t b;

    n = _persist_hex_decode(hex, &buf);
    if (n < 0) {
        return -1;
    }
    mqtt_str_init(&b, buf, (size_t)n);
    if (__properties_parse(props, &b)) {
        MQTT_FREE(buf);
        return -1;
    }
    MQTT_FREE(buf);
    return 0;
}

static int
_persist_str_decode(const char *hex, mqtt_str_t *out) {
    char *buf;
    int n;

    if (strcmp(hex, "-") == 0) {
        out->s = NULL;
        out->n = 0;
        out->i = 0;
        return 0;
    }
    n = _persist_hex_decode(hex, &buf);
    if (n < 0) {
        return -1;
    }
    out->s = buf;
    out->n = (size_t)n;
    out->i = 0;
    return 0;
}

/* next space-separated token of the line (consumed in place) */
static char *
_persist_next(char **p) {
    char *s = *p;

    while (*s == ' ') {
        s++;
    }
    if (!*s) {
        return NULL;
    }
    *p = strchr(s, ' ');
    if (*p) {
        **p = '\0';
        (*p)++;
    } else {
        *p = s + strlen(s);
    }
    return s;
}

/* read one line of any length; returns a malloc'd string or NULL on EOF */
static char *
_persist_readline(FILE *f) {
    size_t cap = 256, len = 0;
    char *buf = (char *)malloc(cap);
    int c;

    if (!buf) {
        return NULL;
    }
    while ((c = fgetc(f)) != EOF) {
        if (len + 2 > cap) {
            char *nb;

            cap *= 2;
            nb = (char *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                return NULL;
            }
            buf = nb;
        }
        if (c == '\n') {
            break;
        }
        buf[len++] = (char)c;
    }
    if (c == EOF && len == 0) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

static void
_persist_write_retained(FILE *f, mqtt_trie_t *trie) {
    map_node_t *node;

    if (trie->retain) {
        char *th = _persist_hex_encode(trie->retain->topic_name.s, trie->retain->topic_name.n);
        char *ph = _persist_hex_encode(trie->retain->payload.s, trie->retain->payload.n);
        char *prh = _persist_props_encode(&trie->retain->props);

        fprintf(f, "RETAIN %u %s %s %s\n", (unsigned)trie->retain->qos, th, ph, prh);
        MQTT_FREE(th);
        MQTT_FREE(ph);
        MQTT_FREE(prh);
    }
    map_foreach(node, &trie->children_m) {
        mqtt_trie_t *child;

        child = map_data(node, mqtt_trie_t, node);
        _persist_write_retained(f, child);
    }
}

static void
mqtt_broker_persist_save(mqtt_broker_t *b) {
    char *tmp;
    FILE *f;
    map_node_t *node, *snode;
    queue_t *qnode;

    if (!b->persist_file) {
        return;
    }
    tmp = (char *)malloc(strlen(b->persist_file) + 5);
    if (!tmp) {
        return;
    }
    sprintf(tmp, "%s.tmp", b->persist_file);
    f = fopen(tmp, "w");
    if (!f) {
        LOG_E("persist: cannot open %s", tmp);
        free(tmp);
        return;
    }

    fprintf(f, "%s\n", PERSIST_MAGIC);

    _persist_write_retained(f, b->sub_root);

    map_foreach(node, &b->session_m) {
        mqtt_session_t *s = map_data(node, mqtt_session_t, node);
        char *ch = _persist_hex_encode(s->client_id.s, s->client_id.n);

        fprintf(f, "SESSION %s %u\n", ch, (unsigned)s->session_expiry);
        MQTT_FREE(ch);

        map_foreach(snode, &s->sub_m) {
            mqtt_subscription_t *sub = map_data(snode, mqtt_subscription_t, node);
            char *fh = _persist_hex_encode(sub->topic_filter.s, sub->topic_filter.n);
            char *sh = sub->share_group.n ? _persist_hex_encode(sub->share_group.s, sub->share_group.n) : strdup("-");

            fprintf(f, "SUB %s %s %u %u %u %u %u\n", fh, sh, (unsigned)sub->sub_id, (unsigned)sub->granted_qos,
                    (unsigned)sub->nl, (unsigned)sub->rap, (unsigned)sub->retain_handling);
            MQTT_FREE(fh);
            free(sh);
        }

        if (s->lwt) {
            char *th = _persist_hex_encode(s->lwt->topic_name.s, s->lwt->topic_name.n);
            char *ph = _persist_hex_encode(s->lwt->payload.s, s->lwt->payload.n);

            fprintf(f, "WILL %u %u %u %s %s\n", (unsigned)s->lwt->qos, (unsigned)s->lwt->retain, (unsigned)s->will_delay,
                    th, ph);
            MQTT_FREE(th);
            MQTT_FREE(ph);
        }

        for (qnode = queue_head(&s->offline); qnode != &s->offline; qnode = queue_next(qnode)) {
            mqtt_offline_msg_t *om = queue_data(qnode, mqtt_offline_msg_t, node);
            char *fh = _persist_hex_encode(om->topic_filter.s, om->topic_filter.n);
            char *th = _persist_hex_encode(om->msg->topic_name.s, om->msg->topic_name.n);
            char *ph = _persist_hex_encode(om->msg->payload.s, om->msg->payload.n);
            char *prh = _persist_props_encode(&om->msg->props);

            fprintf(f, "OFFLINE %s %u %u %s %s %s\n", fh, (unsigned)om->qos, (unsigned)om->retain, th, ph, prh);
            MQTT_FREE(fh);
            MQTT_FREE(th);
            MQTT_FREE(ph);
            MQTT_FREE(prh);
        }
    }

    if (fclose(f)) {
        LOG_E("persist: write error %s", tmp);
        free(tmp);
        return;
    }
    if (rename(tmp, b->persist_file)) {
        LOG_E("persist: rename %s -> %s failed", tmp, b->persist_file);
    } else {
        LOG_I("persist: saved to %s", b->persist_file);
    }
    free(tmp);
    b->persist_dirty = 0;
}

static int
mqtt_broker_persist_load(mqtt_broker_t *b) {
    FILE *f;
    char *line;
    mqtt_session_t *cur = NULL;
    int lineno = 0, errors = 0, n_retained = 0, n_sessions = 0, n_offline = 0;

    if (!b->persist_file) {
        return 0;
    }
    f = fopen(b->persist_file, "r");
    if (!f) {
        return 0; /* no file: first start */
    }
    while ((line = _persist_readline(f))) {
        char *p = line;

        lineno++;
        if (!line[0] || line[0] == '#' || strncmp(line, PERSIST_MAGIC, strlen(PERSIST_MAGIC)) == 0) {
            free(line);
            continue;
        }

        if (strncmp(p, "RETAIN ", 7) == 0) {
            mqtt_message_t *msg;
            char *qh, *th, *ph, *prh;

            p += 7;
            qh = _persist_next(&p);
            th = _persist_next(&p);
            ph = _persist_next(&p);
            prh = _persist_next(&p);
            if (!qh || !th || !ph || !prh) {
                LOG_W("persist: bad RETAIN line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            msg = (mqtt_message_t *)malloc(sizeof *msg);
            memset(msg, 0, sizeof *msg);
            msg->qos = (mqtt_qos_t)atoi(qh);
            msg->retain = 1;
            msg->ref = 1;
            if (_persist_str_decode(th, &msg->topic_name) || _persist_str_decode(ph, &msg->payload) ||
                _persist_props_decode(prh, &msg->props)) {
                LOG_W("persist: bad RETAIN data line %d", lineno);
                mqtt_message_destroy(msg);
                errors++;
                free(line);
                continue;
            }
            mqtt_broker_retain(b, msg);
            mqtt_message_destroy(msg);
            n_retained++;
        } else if (strncmp(p, "SESSION ", 8) == 0) {
            mqtt_str_t client_id;
            char *ch, *eh;

            p += 8;
            ch = _persist_next(&p);
            eh = _persist_next(&p);
            if (!ch || !eh) {
                LOG_W("persist: bad SESSION line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            if (_persist_str_decode(ch, &client_id)) {
                LOG_W("persist: bad SESSION data line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            cur = mqtt_session_create(b, &client_id);
            if (!cur) {
                mqtt_str_free(&client_id);
                LOG_W("persist: cannot create session line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            cur->session_expiry = (uint32_t)atoi(eh);
            mqtt_broker_add_session(b, cur);
            n_sessions++;
        } else if (strncmp(p, "SUB ", 4) == 0) {
            mqtt_str_t filter, share;
            char *fh, *sh, *idh, *qh, *nlh, *raph, *rhh;

            if (!cur) {
                LOG_W("persist: SUB before SESSION line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            p += 4;
            fh = _persist_next(&p);
            sh = _persist_next(&p);
            idh = _persist_next(&p);
            qh = _persist_next(&p);
            nlh = _persist_next(&p);
            raph = _persist_next(&p);
            rhh = _persist_next(&p);
            if (!fh || !sh || !idh || !qh || !nlh || !raph || !rhh) {
                LOG_W("persist: bad SUB line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            if (_persist_str_decode(fh, &filter) || _persist_str_decode(sh, &share)) {
                LOG_W("persist: bad SUB data line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            {
                mqtt_subscription_t *sub;

                sub = mqtt_subscription_create(&filter, &share, (uint32_t)atoi(idh), (mqtt_qos_t)atoi(qh),
                                               (uint8_t)atoi(nlh), (uint8_t)atoi(raph), (uint8_t)atoi(rhh));
                map_push(&cur->sub_m, &sub->topic_filter, &sub->node);
                b->subscriptions++;
                mqtt_broker_subscribe(b, cur, sub);
            }
        } else if (strncmp(p, "WILL ", 5) == 0) {
            mqtt_str_t topic, payload;
            char *qh, *rh, *dh, *th, *ph;

            if (!cur) {
                LOG_W("persist: WILL before SESSION line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            p += 5;
            qh = _persist_next(&p);
            rh = _persist_next(&p);
            dh = _persist_next(&p);
            th = _persist_next(&p);
            ph = _persist_next(&p);
            if (!qh || !rh || !dh || !th || !ph) {
                LOG_W("persist: bad WILL line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            if (_persist_str_decode(th, &topic) || _persist_str_decode(ph, &payload)) {
                LOG_W("persist: bad WILL data line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            cur->lwt = (mqtt_message_t *)malloc(sizeof *cur->lwt);
            memset(cur->lwt, 0, sizeof *cur->lwt);
            cur->lwt->qos = (mqtt_qos_t)atoi(qh);
            cur->lwt->retain = (uint8_t)atoi(rh);
            mqtt_str_copy(&cur->lwt->topic_name, &topic);
            mqtt_str_copy(&cur->lwt->payload, &payload);
            mqtt_str_copy(&cur->lwt->client_id, &cur->client_id);
            cur->lwt->ref = 1;
            cur->will_delay = (uint32_t)atoi(dh);
        } else if (strncmp(p, "OFFLINE ", 8) == 0) {
            mqtt_message_t *msg;
            mqtt_offline_msg_t *om;
            mqtt_str_t filter, topic, payload;
            char *fh, *qh, *rh, *th, *ph, *prh;

            if (!cur) {
                LOG_W("persist: OFFLINE before SESSION line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            p += 8;
            fh = _persist_next(&p);
            qh = _persist_next(&p);
            rh = _persist_next(&p);
            th = _persist_next(&p);
            ph = _persist_next(&p);
            prh = _persist_next(&p);
            if (!fh || !qh || !rh || !th || !ph || !prh) {
                LOG_W("persist: bad OFFLINE line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            if (_persist_str_decode(fh, &filter) || _persist_str_decode(th, &topic) || _persist_str_decode(ph, &payload)) {
                LOG_W("persist: bad OFFLINE data line %d", lineno);
                errors++;
                free(line);
                continue;
            }
            msg = (mqtt_message_t *)malloc(sizeof *msg);
            memset(msg, 0, sizeof *msg);
            msg->qos = (mqtt_qos_t)atoi(qh);
            msg->retain = (uint8_t)atoi(rh);
            mqtt_str_copy(&msg->topic_name, &topic);
            mqtt_str_copy(&msg->payload, &payload);
            msg->ref = 1;
            if (_persist_props_decode(prh, &msg->props)) {
                LOG_W("persist: bad OFFLINE props line %d", lineno);
                mqtt_message_destroy(msg);
                errors++;
                free(line);
                continue;
            }
            om = (mqtt_offline_msg_t *)malloc(sizeof *om);
            memset(om, 0, sizeof *om);
            mqtt_message_add_ref(msg);
            om->msg = msg;
            mqtt_str_copy(&om->topic_filter, &filter);
            om->qos = msg->qos;
            om->retain = msg->retain;
            queue_insert_tail(&cur->offline, &om->node);
            mqtt_message_destroy(msg);
            n_offline++;
        } else {
            LOG_W("persist: unknown line %d: %s", lineno, line);
            errors++;
        }
        free(line);
    }
    fclose(f);
    LOG_I("persist: loaded %s (%d retained, %d sessions, %d offline, %d errors)", b->persist_file, n_retained,
          n_sessions, n_offline, errors);
    return errors;
}

/* ---- mempool-backed allocator for the hot path (strings, packets, props) ---- */
static mqtt_mempool_t *g_mempool = NULL;

static void *
_mempool_malloc(size_t size) {
    if (g_mempool)
        return mqtt_mempool_alloc(g_mempool, size);
    return malloc(size);
}

static void
_mempool_free(void *ptr) {
    if (g_mempool) {
        mqtt_mempool_free(g_mempool, ptr);
        return;
    }
    free(ptr);
}

static void
_mempool_init(void) {
    if (!g_mempool) {
        g_mempool = mqtt_mempool_create(0);
        if (g_mempool)
            mqtt_set_allocator(_mempool_malloc, _mempool_free);
    }
}

static void
_mempool_fini(void) {
    if (g_mempool) {
        size_t allocated = 0, used = 0, allocs = 0, frees = 0;
        double hit = 0.0;

        mqtt_mempool_stats(g_mempool, &allocated, &used, &allocs, &frees, &hit);
        LOG_I("mempool stats: allocated=%zu used=%zu allocs=%zu frees=%zu hit_rate=%.2f", allocated, used, allocs, frees, hit);
        mqtt_mempool_destroy(g_mempool);
        g_mempool = NULL;
        mqtt_set_allocator(NULL, NULL);
    }
}

int
mqtt_broker_create(mqtt_broker_config_t *config, uv_loop_t *loop, mqtt_broker_t *b) {
    b->loop = loop;
    b->t_now = 0;
    b->host = b->host ? b->host : (config->host ? strdup(config->host) : strdup("0.0.0.0"));
    b->port = b->port ? b->port : (config->port ? config->port : MQTT_BROKER_DEFAULT_PORT);
    b->max_connections = b->max_connections ? b->max_connections
                                           : (config->max_connections ? config->max_connections
                                                                     : MQTT_BROKER_DEFAULT_MAX_CONN);
    b->rate_limit = b->rate_limit ? b->rate_limit : config->rate_limit;
    b->auth_type = b->auth_type ? b->auth_type : (config->auth_type ? strdup(config->auth_type) : NULL);
    b->auth_api = b->auth_api ? b->auth_api : (config->auth_api ? strdup(config->auth_api) : NULL);
    b->auth_callback = NULL;
    b->auth_ud = config->ud;
    b->connections = 0;
    b->shutdown_pending = 0;
    b->pending_clients = 0;
    b->trie_dump_enabled = 0;
    b->tls_on = b->tls_on;

    /* v5 server capabilities (advertised in CONNACK) */
    b->server_receive_max = 10;
    b->server_alias_max = 10;
    b->server_max_qos = 2;
    b->server_retain_available = 1;
    b->server_wildcard_available = 1;
    b->server_sub_id_available = 1;
    b->server_shared_available = 1;

    queue_init(&b->client_q);
    queue_init(&b->msg_q);
    /* account_q is already initialized in main() before config parsing */
    map_init(&b->session_m, _mqtt_session_client_id_key, _mqtt_session_client_id_cmp);
    map_init(&b->share_rr_m, _mqtt_share_group_key, _mqtt_share_group_cmp);
    /* listener_m is already initialized in main() before config parsing */
    b->sub_root = mqtt_trie_create(0, 0);

    if (config->users && config->user_count > 0) {
        for (int i = 0; i < config->user_count; i++) {
            mqtt_account_t *acc = (mqtt_account_t *)malloc(sizeof *acc);
            mqtt_str_dup(&acc->username, config->users[i].user ? config->users[i].user : "");
            mqtt_str_dup(&acc->password, config->users[i].pass ? config->users[i].pass : "");
            mqtt_str_dup(&acc->client_id, config->users[i].client_id ? config->users[i].client_id : "*");
            queue_insert_tail(&b->account_q, &acc->node);
        }
    }

    snowflake_init(&b->snowflake, 0, 0);
    return 0;
}

int
mqtt_broker_start(mqtt_broker_t *b) {
    uv_loop_t *loop = b->loop;
    map_node_t *node;
    int any_listener = 0;

    if (b->tls_on) {
        tls_init();
    }

    loop->data = b;

    mqtt_broker_persist_load(b);

    uv_signal_init(loop, &b->signal_term);
    b->signal_term.data = b;
    uv_signal_start(&b->signal_term, _broker_on_signal, SIGTERM);
    uv_signal_init(loop, &b->signal_int);
    b->signal_int.data = b;
    uv_signal_start(&b->signal_int, _broker_on_signal, SIGINT);
    b->signals_on = 1;

    uv_timer_init(loop, &b->timer);
    b->timer.data = b;
    uv_timer_start(&b->timer, _broker_on_timer, 1000, 1000);

    uv_idle_init(loop, &b->idle);
    b->idle.data = b;

    if (b->sys_interval > 0) {
        uv_timer_init(loop, &b->sys_timer);
        b->sys_timer.data = b;
        uv_timer_start(&b->sys_timer, _broker_on_sys_timer, (uint64_t)b->sys_interval * 1000,
                       (uint64_t)b->sys_interval * 1000);
        LOG_I("$SYS publishing enabled (interval: %ds)", b->sys_interval);
    }

    /* Start all configured listeners */
    map_foreach(node, &b->listener_m) {
        mqtt_broker_listener_t *ln;

        ln = map_data(node, mqtt_broker_listener_t, node);
        if (mqtt_listener_start(loop, b, ln)) {
            LOG_E("start listener %s failed", ln->id);
            return -1;
        } else {
            LOG_I("listener %s at %s:%d started", ln->id, ln->host, ln->port);
            any_listener = 1;
        }
    }

    /* If no listeners configured, start default TCP listener */
    if (!any_listener) {
        mqtt_broker_listener_t *ln;

        ln = mqtt_listener_fetch(b, "tcp");
        ln->host = strdup(b->host);
        ln->port = b->port;
        ln->mode = MQTT_BROKER_MODE_TCP;

        if (mqtt_listener_start(loop, b, ln)) {
            LOG_E("start default listener failed");
            return -1;
        }
        LOG_I("mqtt broker at %s:%d started", b->host, b->port);
    }

    return 0;
}

static void
_broker_on_shutdown_timeout(uv_timer_t *handle) {
    mqtt_broker_t *b = handle->data;

    LOG_W("shutdown timeout, force stop");
    uv_stop(b->loop);
}

static void
_broker_on_signal(uv_signal_t *handle, int signum) {
    mqtt_broker_t *b = handle->data;

    LOG_I("received signal %d, shutting down", signum);
    mqtt_broker_stop(b);
}

void
mqtt_broker_stop(mqtt_broker_t *b) {
    map_node_t *node;
    queue_t *qnode;

    if (b->shutdown_pending) {
        return;
    }
    b->shutdown_pending = 1;
    LOG_I("broker stopping");

    mqtt_broker_persist_save(b);
    uv_timer_stop(&b->timer);

    /* stop accepting new connections */
    map_foreach(node, &b->listener_m) {
        mqtt_broker_listener_t *ln;

        ln = map_data(node, mqtt_broker_listener_t, node);
        if (!uv_is_closing((uv_handle_t *)&ln->server)) {
            uv_close((uv_handle_t *)&ln->server, NULL);
        }
    }

    /* let the loop drain: no new ticks, no more signals */
    if (b->signals_on) {
        uv_signal_stop(&b->signal_term);
        uv_signal_stop(&b->signal_int);
    }

    /* disconnect all clients (will messages are not published) */
    queue_foreach(qnode, &b->client_q) {
        mqtt_client_t *c;

        c = queue_data(qnode, mqtt_client_t, node);
        if (c->closed) {
            continue;
        }
        if (c->s && c->s->lwt) {
            mqtt_message_destroy(c->s->lwt);
            c->s->lwt = 0;
        }
        if (c->s && c->s->c == c && c->ver == MQTT_VERSION_5) {
            mqtt_client_disconnect(c, MQTT_RC_SERVER_SHUTTING_DOWN);
        } else {
            mqtt_client_shutdown(c);
        }
    }

    if (queue_empty(&b->client_q)) {
        /* nothing to drain */
        uv_stop(b->loop);
        return;
    }

    /* force-stop if the loop does not drain on its own */
    uv_timer_init(b->loop, &b->shutdown_timer);
    b->shutdown_timer.data = b;
    uv_timer_start(&b->shutdown_timer, _broker_on_shutdown_timeout, 3000, 0);
    b->shutdown_timer_on = 1;
}

void
mqtt_broker_destroy(mqtt_broker_t *b) {
    queue_t *qnode;
    map_node_t *mnode, *next_mnode;

    if (b->auth_type) free(b->auth_type);
    if (b->auth_api) free(b->auth_api);
    free(b->host);
    free(b->persist_file);

    /* Clean up pending messages */
    while (!queue_empty(&b->msg_q)) {
        qnode = queue_head(&b->msg_q);
        queue_remove(qnode);
        mqtt_message_destroy(queue_data(qnode, mqtt_message_t, node));
    }

    map_foreach_safe(mnode, next_mnode, &b->session_m) {
        mqtt_session_t *s = map_data(mnode, mqtt_session_t, node);
        map_erase(&b->session_m, mnode);
        mqtt_session_destroy(b, s);
    }
    while (!queue_empty(&b->account_q)) {
        qnode = queue_head(&b->account_q);
        queue_remove(qnode);
        mqtt_account_t *acc = queue_data(qnode, mqtt_account_t, node);
        mqtt_str_free(&acc->client_id);
        mqtt_str_free(&acc->username);
        mqtt_str_free(&acc->password);
        free(acc);
    }

    /* Clean up ACL rules */
    while (!queue_empty(&b->acl_q)) {
        qnode = queue_head(&b->acl_q);
        queue_remove(qnode);
        mqtt_acl_rule_t *rule = queue_data(qnode, mqtt_acl_rule_t, node);
        mqtt_str_free(&rule->username);
        mqtt_str_free(&rule->topic);
        free(rule);
    }

    /* Clean up $share round-robin state */
    map_foreach_safe(mnode, next_mnode, &b->share_rr_m) {
        mqtt_share_rr_t *rr = map_data(mnode, mqtt_share_rr_t, node);
        map_erase(&b->share_rr_m, mnode);
        mqtt_str_free(&rr->group);
        free(rr);
    }

    /* Clean up listeners */
    map_foreach_safe(mnode, next_mnode, &b->listener_m) {
        mqtt_broker_listener_t *ln = map_data(mnode, mqtt_broker_listener_t, node);
        if (!uv_is_closing((uv_handle_t *)&ln->server)) {
            uv_close((uv_handle_t *)&ln->server, NULL);
        }
        if (ln->tls_ctx) {
            tls_ctx_destroy(ln->tls_ctx);
        }
        free(ln->id);
        free(ln->host);
        free(ln->cert_file);
        free(ln->key_file);
        free(ln->auth_type);
        free(ln->auth_api);
        map_erase(&b->listener_m, mnode);
        free(ln);
    }

    if (b->signals_on) {
        uv_signal_stop(&b->signal_term);
        uv_signal_stop(&b->signal_int);
        if (!uv_is_closing((uv_handle_t *)&b->signal_term)) {
            uv_close((uv_handle_t *)&b->signal_term, NULL);
        }
        if (!uv_is_closing((uv_handle_t *)&b->signal_int)) {
            uv_close((uv_handle_t *)&b->signal_int, NULL);
        }
    }

    uv_timer_stop(&b->timer);
    if (!uv_is_closing((uv_handle_t *)&b->timer)) {
        uv_close((uv_handle_t *)&b->timer, NULL);
    }
    if (b->sys_interval > 0) {
        uv_timer_stop(&b->sys_timer);
        if (!uv_is_closing((uv_handle_t *)&b->sys_timer)) {
            uv_close((uv_handle_t *)&b->sys_timer, NULL);
        }
    }
    if (b->shutdown_timer_on) {
        uv_timer_stop(&b->shutdown_timer);
        if (!uv_is_closing((uv_handle_t *)&b->shutdown_timer)) {
            uv_close((uv_handle_t *)&b->shutdown_timer, NULL);
        }
    }
    uv_idle_stop(&b->idle);
    if (!uv_is_closing((uv_handle_t *)&b->idle)) {
        uv_close((uv_handle_t *)&b->idle, NULL);
    }

    mqtt_trie_destroy(b->sub_root);
    if (b->tls_on) {
        tls_unit();
    }
    _mempool_fini();
    free(b);
}

void
mqtt_broker_set_auth_callback(mqtt_broker_t *b, mqtt_broker_auth_callback_t cb, void *ud) {
    b->auth_callback = cb;
    b->auth_ud = ud;
}

int
mqtt_broker_run(mqtt_broker_t *b) {
    return uv_run(b->loop, UV_RUN_DEFAULT);
}

int
main(int argc, char *argv[]) {
    uv_loop_t *loop;
    int rc;
    mqtt_broker_config_t config;
    mqtt_broker_t *b;

    signal(SIGPIPE, SIG_IGN);

    /* Route mqtt.h hot-path allocations through the mempool before any config parsing. */
    _mempool_init();

    loop = uv_default_loop();

    mqtt_broker_config_init(&config);

    b = calloc(1, sizeof(*b));
    if (!b) return EXIT_FAILURE;

    /* Init structures used during config parsing */
    map_init(&b->listener_m, _mqtt_listener_key_pt, _mqtt_listener_cmp_pt);
    queue_init(&b->account_q);
    queue_init(&b->acl_q);

    if (argc > 1 && ini_parse(argv[1], _broker_config, b)) {
        LOG_E("config file %s parse error", argv[1]);
        mqtt_broker_destroy(b);
        return EXIT_FAILURE;
    }

    mqtt_broker_create(&config, loop, b);

    rc = mqtt_broker_start(b);
    if (rc) {
        mqtt_broker_destroy(b);
        return EXIT_FAILURE;
    }

    rc = mqtt_broker_run(b);
    mqtt_broker_destroy(b);
    return rc;
}
