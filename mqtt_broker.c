#define MQTT_IMPL
#include "mqtt.h"

#define SNOWFLAKE_IMPL
#include "snowflake.h"

#define INI_IMPL
#include "ini.h"

#define LOG_IMPL
#include "log.h"

#include "map.h"
#include "queue.h"

#include "uv.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
typedef struct mqtt_broker_s mqtt_broker_t;

struct mqtt_client_s {
    uv_tcp_t *tcp;
    uv_shutdown_t shutdown;
    mqtt_parser_t parser;
    mqtt_str_t buff;
    char ip[INET6_ADDRSTRLEN];
    int port;
    uint64_t t_last;
    uint8_t clean_session;
    uint16_t keep_alive;
    queue_t node;
    mqtt_session_t *s;
    mqtt_message_t *lwt;
    int closed;
};

struct mqtt_publication_s {
    uint16_t packet_id;
    mqtt_publication_state_t state;
    mqtt_message_t *msg;
    mqtt_qos_t qos;
    uint8_t retain;
    uint16_t t_send;
    queue_t node;
};

struct mqtt_subscription_s {
    mqtt_str_t topic_filter;
    mqtt_qos_t granted_qos;
    map_node_t node;
};

struct mqtt_session_s {
    mqtt_str_t client_id;
    mqtt_client_t *c;
    uint16_t next_packet_id;
    map_node_t node;
    map_t sub_m;
    queue_t incoming;
    queue_t outgoing;
};

struct mqtt_message_s {
    uint8_t dup;
    uint8_t retain;
    mqtt_str_t topic_name;
    mqtt_qos_t qos;
    mqtt_str_t payload;
    mqtt_str_t client_id;
    queue_t node;
    int ref;
};

struct mqtt_subscriber_s {
    mqtt_session_t *s;
    mqtt_subscription_t *sub;
    map_node_t node;
};

struct mqtt_trie_s {
    mqtt_str_t topic;
    map_t suber_m;
    map_t children_m;
    map_node_t node;
    mqtt_trie_t *parent;
    mqtt_message_t *retain;
};

struct mqtt_broker_s {
    uv_loop_t *loop;
    uv_tcp_t server;
    uv_idle_t idle;
    mqtt_trie_t *sub_root;
    char *host;
    int port;
    uint64_t t_now;
    snowflake_t snowflake;
    queue_t client_q;
    map_t session_m;
    queue_t msg_q;
};

static mqtt_broker_t B = {0};

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

        name = MQTT_PROPERTY_DEFS[property->code].name;
        type = MQTT_PROPERTY_DEFS[property->code].type;
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
                seg.n = i;
                seg.s = topic->s;
                break;
            }
        }
        if (i == topic->n) {
            seg.n = topic->n;
            seg.s = topic->s;
            topic->n = 0;
            topic->s = 0;
        } else {
            topic->s += i + 1;
            topic->n -= i + 1;
        }
    }
    return seg;
}

static mqtt_message_t *
mqtt_message_create(mqtt_session_t *s, mqtt_packet_t *pkt) {
    mqtt_message_t *msg;

    msg = (mqtt_message_t *)malloc(sizeof *msg);
    memset(msg, 0, sizeof *msg);

    if (pkt) {
        msg->dup = pkt->f.bits.dup;
        msg->retain = pkt->f.bits.retain;
        msg->qos = pkt->f.bits.qos;
        mqtt_str_copy(&msg->topic_name, &pkt->v.publish.topic_name);
        mqtt_str_copy(&msg->payload, &pkt->p.publish.message);
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
    msg->retain = pkt->v.connect.connect_flags.bits.will_retain;
    msg->qos = pkt->v.connect.connect_flags.bits.will_qos;
    mqtt_str_copy(&msg->topic_name, &pkt->p.connect.will_topic);
    mqtt_str_copy(&msg->payload, &pkt->p.connect.will_message);
    mqtt_str_copy(&msg->client_id, &s->client_id);
    msg->ref = 1;

    return msg;
}

static mqtt_publication_t *
mqtt_publication_create(mqtt_message_t *msg, uint16_t packet_id, mqtt_qos_t qos, uint8_t retain,
                        mqtt_publication_state_t state) {
    mqtt_publication_t *pub;

    pub = (mqtt_publication_t *)malloc(sizeof *pub);
    memset(pub, 0, sizeof *pub);
    mqtt_message_add_ref(msg);
    pub->msg = msg;
    pub->packet_id = packet_id;
    pub->qos = qos;
    pub->retain = retain;
    pub->state = state;
    pub->t_send = B.t_now;

    return pub;
}

static void
mqtt_publication_destroy(mqtt_publication_t *pub) {
    mqtt_message_destroy(pub->msg);
    free(pub);
}

static void
mqtt_session_incoming_store(mqtt_session_t *s, mqtt_publication_t *pub) {
    queue_insert_tail(&s->incoming, &pub->node);
}

static int
mqtt_session_incoming_discard(mqtt_session_t *s, uint16_t packet_id) {
    queue_t *node;

    queue_foreach(node, &s->incoming) {
        mqtt_publication_t *pub;

        pub = queue_data(node, mqtt_publication_t, node);
        if (pub->packet_id == packet_id && pub->state == MQTT_PUBLICATION_STATE_REL) {
            queue_remove(node);
            mqtt_publication_destroy(pub);
            return 0;
        }
    }
    return -1;
}

static mqtt_message_t *
mqtt_session_incoming_message(mqtt_session_t *s, uint16_t packet_id) {
    queue_t *node;

    queue_foreach(node, &s->incoming) {
        mqtt_publication_t *pub;

        pub = queue_data(node, mqtt_publication_t, node);
        if (pub->packet_id == packet_id) {
            return pub->msg;
        }
    }
    return 0;
}

static void
mqtt_session_outgoing_store(mqtt_session_t *s, mqtt_publication_t *pub) {
    queue_insert_tail(&s->outgoing, &pub->node);
}

static int
mqtt_session_outgoing_discard(mqtt_session_t *s, uint16_t packet_id, mqtt_publication_state_t state) {
    queue_t *node;

    queue_foreach(node, &s->outgoing) {
        mqtt_publication_t *pub;

        pub = queue_data(node, mqtt_publication_t, node);
        if (pub->packet_id == packet_id && pub->state == state) {
            queue_remove(node);
            mqtt_publication_destroy(pub);
            return 0;
        }
    }
    return -1;
}

static int
mqtt_session_outgoing_update(mqtt_session_t *s, uint16_t packet_id, mqtt_publication_state_t state,
                             mqtt_publication_state_t new_state) {
    queue_t *node;

    queue_foreach(node, &s->outgoing) {
        mqtt_publication_t *pub;

        pub = queue_data(node, mqtt_publication_t, node);
        if (pub->packet_id == packet_id && pub->state == state) {
            pub->state = new_state;
            pub->t_send = B.t_now;
            return 0;
        }
    }
    return -1;
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

static void
_mqtt_on_write(uv_write_t *req, int status) {
    if (status) {
        LOG_W("write: %s", uv_strerror(status));
    }
    free(req->data);
    free(req);
}

static int
mqtt_client_send(mqtt_client_t *c, mqtt_packet_t *pkt) {
    mqtt_str_t b = MQTT_STR_INITIALIZER;
    int rc;

    if (c->closed) {
        return -1;
    }
    rc = mqtt_serialize(pkt, &b);
    mqtt_packet_unit(pkt);
    if (!rc) {
        uv_write_t *req;
        uv_buf_t buf;

        logger_print(logger_default(), LOG_LEVEL_DEBUG, "send:\n");
        logger_print(logger_default(), LOG_LEVEL_DEBUG, "++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        LOG_DUMP(b.s, b.n);
        logger_print(logger_default(), LOG_LEVEL_DEBUG, "--------------------------------------------------\n");

        req = (uv_write_t *)malloc(sizeof *req);
        req->data = b.s;
        buf = uv_buf_init(b.s, b.n);
        rc = uv_write(req, (uv_stream_t *)c->tcp, &buf, 1, _mqtt_on_write);
        if (rc) {
            LOG_W("write: %s", uv_strerror(rc));
        }
    }
    return rc;
}

static uint16_t
mqtt_session_packet_id_generate(mqtt_session_t *s) {
    uint16_t id;

    id = ++s->next_packet_id;
    if (id == 0)
        id = ++s->next_packet_id;
    return id;
}

static void
mqtt_session_publish(mqtt_session_t *s, mqtt_message_t *msg, mqtt_qos_t qos, uint8_t retain) {
    mqtt_client_t *c;
    mqtt_publication_t *pub;
    uint16_t packet_id;
    mqtt_packet_t res;
    int rc;

    if (qos > 0) {
        packet_id = mqtt_session_packet_id_generate(s);
    } else {
        packet_id = 0;
    }

    c = s->c;
    if (!c) {
        goto e;
    }

    mqtt_packet_init(&res, c->parser.version, MQTT_PUBLISH);
    res.f.bits.retain = retain;
    res.f.bits.qos = qos;
    res.v.publish.packet_id = packet_id;
    mqtt_str_set(&res.v.publish.topic_name, &msg->topic_name);
    mqtt_str_set(&res.p.publish.message, &msg->payload);

    LOG_I("[%.*s] sending PUBLISH (id: %" PRIu16 ", dup: %" PRIu8 ", retain: %" PRIu8 ", qos: %" PRIu8
          ", topic_name: %.*s, ...(%d bytes))",
          MQTT_STR_PRINT(s->client_id), res.v.publish.packet_id, res.f.bits.dup, res.f.bits.retain, res.f.bits.qos,
          MQTT_STR_PRINT(res.v.publish.topic_name), res.p.publish.message.n);
    if (res.ver == MQTT_VERSION_5) {
        LOG_PROP(&res.v.publish.v5.properties);
    }

    rc = mqtt_client_send(c, &res);
    if (rc) {
        mqtt_client_shutdown(c);
    }

e:
    switch (qos) {
    case MQTT_QOS_0:
        break;
    case MQTT_QOS_1:
        pub = mqtt_publication_create(msg, packet_id, qos, retain, MQTT_PUBLICATION_STATE_ACK);
        mqtt_session_outgoing_store(s, pub);
        break;
    case MQTT_QOS_2:
        pub = mqtt_publication_create(msg, packet_id, qos, retain, MQTT_PUBLICATION_STATE_REC);
        mqtt_session_outgoing_store(s, pub);
        break;
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
mqtt_trie_destroy(mqtt_trie_t *trie) {
    if (trie->parent) {
        map_erase(&trie->parent->children_m, &trie->node);
    }
    mqtt_str_free(&trie->topic);
    free(trie);
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
mqtt_trie_remove(mqtt_trie_t *trie) {
    do {
        mqtt_trie_t *node;

        node = trie->parent;
        if (!map_empty(&trie->children_m) || !map_empty(&trie->suber_m) || trie->retain || trie == B.sub_root) {
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

static void
mqtt_trie_deliver(mqtt_trie_t *trie, mqtt_message_t *msg) {
    map_node_t *node;

    map_foreach(node, &trie->suber_m) {
        mqtt_subscriber_t *suber;
        mqtt_qos_t qos;

        suber = map_data(node, mqtt_subscriber_t, node);
        qos = msg->qos < suber->sub->granted_qos ? msg->qos : suber->sub->granted_qos;
        mqtt_session_publish(suber->s, msg, qos, 0);
    }
}

static void
mqtt_trie_dispatch(mqtt_trie_t *trie, mqtt_str_t topic_name, mqtt_message_t *msg) {
    mqtt_str_t seg, single, multi, *topic;

    mqtt_str_from(&single, "+");
    mqtt_str_from(&multi, "#");

    topic = &topic_name;
    seg = mqtt_topic_segment(topic);
    if (seg.n) {
        mqtt_trie_t *branch;

        branch = mqtt_trie_find(trie, &seg);
        if (branch) {
            mqtt_trie_dispatch(branch, *topic, msg);
            if (!topic->n) {
                mqtt_trie_deliver(branch, msg);
            }
        }

        branch = mqtt_trie_find(trie, &single);
        if (branch) {
            mqtt_trie_dispatch(branch, *topic, msg);
            if (!topic->n) {
                mqtt_trie_deliver(branch, msg);
            }
        }

        branch = mqtt_trie_find(trie, &multi);
        if (branch && !mqtt_trie_has_children(branch)) {
            mqtt_trie_deliver(branch, msg);
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
mqtt_subscription_create(mqtt_str_t *topic_filter, mqtt_qos_t requested_qos) {
    mqtt_subscription_t *sub;

    sub = (mqtt_subscription_t *)malloc(sizeof *sub);
    memset(sub, 0, sizeof *sub);

    sub->granted_qos = requested_qos;
    mqtt_str_copy(&sub->topic_filter, topic_filter);

    return sub;
}

static void
mqtt_subscription_destroy(mqtt_subscription_t *sub) {
    mqtt_str_free(&sub->topic_filter);
    free(sub);
}

static void
mqtt_subscription_update(mqtt_subscription_t *sub, mqtt_str_t *topic_filter, mqtt_qos_t requested_qos) {
    if (requested_qos > sub->granted_qos) {
        sub->granted_qos = requested_qos;
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
mqtt_broker_add_client(mqtt_client_t *c) {
    queue_insert_tail(&B.client_q, &c->node);
}

static void
mqtt_broker_remove_client(mqtt_client_t *c) {
    queue_remove(&c->node);
}

static void
mqtt_broker_add_session(mqtt_session_t *s) {
    map_push(&B.session_m, &s->client_id, &s->node);
}

static void
mqtt_broker_remove_session(mqtt_session_t *s) {
    map_erase(&B.session_m, &s->node);
}

static mqtt_session_t *
mqtt_broker_find_session(mqtt_str_t *client_id) {
    map_node_t *node;

    node = map_find(&B.session_m, client_id);
    if (node) {
        return map_data(node, mqtt_session_t, node);
    }
    return 0;
}

static void
mqtt_broker_subscribe(mqtt_session_t *s, mqtt_subscription_t *sub) {
    mqtt_str_t topic;
    mqtt_str_t seg;
    mqtt_trie_t *trie;
    mqtt_subscriber_t *suber;

    topic = sub->topic_filter;

    trie = B.sub_root;
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

        if (trie->retain) {
            mqtt_qos_t qos = sub->granted_qos < trie->retain->qos ? sub->granted_qos : trie->retain->qos;
            mqtt_session_publish(s, trie->retain, qos, 1);
        }
    }

    mqtt_trie_dump(B.sub_root, 0);
}

static mqtt_qos_t
mqtt_session_subscribe(mqtt_session_t *s, mqtt_str_t *topic_filter, mqtt_qos_t requested_qos) {
    map_node_t *node;
    mqtt_subscription_t *sub;

    node = map_find(&s->sub_m, topic_filter);
    if (node) {
        sub = map_data(node, mqtt_subscription_t, node);
        mqtt_subscription_update(sub, topic_filter, requested_qos);
    } else {
        sub = mqtt_subscription_create(topic_filter, requested_qos);
        map_push(&s->sub_m, &sub->topic_filter, &sub->node);
    }

    mqtt_broker_subscribe(s, sub);
    return sub->granted_qos;
}

static int
mqtt_broker_unsubscribe(mqtt_session_t *s, mqtt_str_t *topic_filter) {
    mqtt_str_t topic;
    mqtt_str_t seg;
    mqtt_trie_t *sub;
    int rc;

    topic = *topic_filter;
    rc = -1;

    sub = B.sub_root;
    while ((seg = mqtt_topic_segment(&topic)).n && sub) {
        sub = mqtt_trie_find(sub, &seg);
    }
    if (sub) {
        mqtt_subscriber_t *suber;

        suber = mqtt_trie_find_subscriber(sub, &s->client_id);
        if (suber) {
            mqtt_trie_remove_subscriber(sub, suber);
            mqtt_subscriber_destroy(suber);
            rc = 0;
        }
        mqtt_trie_remove(sub);
    }

    mqtt_trie_dump(B.sub_root, 0);
    return rc;
}

static int
mqtt_session_unsubscribe(mqtt_session_t *s, mqtt_str_t *topic_filter) {
    map_node_t *node;

    node = map_find(&s->sub_m, topic_filter);
    if (node) {
        mqtt_subscription_t *sub;

        sub = map_data(node, mqtt_subscription_t, node);
        map_erase(&s->sub_m, node);
        mqtt_subscription_destroy(sub);

        return mqtt_broker_unsubscribe(s, topic_filter);
    }
    return -1;
}

static void
mqtt_broker_retain(mqtt_message_t *msg) {
    mqtt_str_t topic;
    mqtt_str_t seg;
    mqtt_trie_t *trie;

    topic = msg->topic_name;
    trie = B.sub_root;
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
    }
    if (msg->payload.n > 0) {
        mqtt_message_add_ref(msg);
        trie->retain = msg;
    } else {
        mqtt_trie_remove(trie);
    }
    mqtt_trie_dump(B.sub_root, 0);
}

static void
_mqtt_on_idle(uv_idle_t *handle) {
    mqtt_message_t *msg;
    queue_t *node;
    (void)handle;

    if (queue_empty(&B.msg_q)) {
        uv_idle_stop(&B.idle);
        return;
    }

    node = queue_head(&B.msg_q);
    queue_remove(node);
    msg = queue_data(node, mqtt_message_t, node);

    if (msg->retain) {
        mqtt_broker_retain(msg);
    }
    mqtt_trie_dispatch(B.sub_root, msg->topic_name, msg);
    mqtt_message_destroy(msg);
}

static void
mqtt_broker_dispatch(mqtt_message_t *msg) {
    int empty;

    empty = queue_empty(&B.msg_q);
    queue_insert_tail(&B.msg_q, &msg->node);
    if (empty) {
        uv_idle_start(&B.idle, _mqtt_on_idle);
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

static mqtt_session_t *
mqtt_session_create(mqtt_str_t *client_id) {
    mqtt_session_t *s;

    s = (mqtt_session_t *)malloc(sizeof *s);
    memset(s, 0, sizeof *s);
    mqtt_str_set(&s->client_id, client_id);

    map_init(&s->sub_m, _mqtt_subscription_topic_filter_key, _mqtt_subscription_topic_filter_cmp);

    queue_init(&s->incoming);
    queue_init(&s->outgoing);

    LOG_D("session.%p.create %.*s", s, MQTT_STR_PRINT(s->client_id));

    return s;
}

static void
mqtt_session_destroy(mqtt_session_t *s) {
    map_node_t *node, *next;

    LOG_D("session.%p.destroy %.*s", s, MQTT_STR_PRINT(s->client_id));

    map_foreach_safe(node, next, &s->sub_m) {
        mqtt_subscription_t *sub;

        sub = map_data(node, mqtt_subscription_t, node);
        mqtt_broker_unsubscribe(s, &sub->topic_filter);
        map_erase(&s->sub_m, node);
        mqtt_subscription_destroy(sub);
    }
    mqtt_str_free(&s->client_id);
    free(s);
}

static void
mqtt_client_id_generate(mqtt_str_t *client_id) {
    long id;

    client_id->s = (char *)malloc(SNOWFLAKE_ID_LEN + 1);
    id = snowflake_id(&B.snowflake);
    sprintf(client_id->s, "%ld", id);
    client_id->s[SNOWFLAKE_ID_LEN] = '\0';
    client_id->n = SNOWFLAKE_ID_LEN;
}

static int
mqtt_on_connect(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_str_t client_id = MQTT_STR_INITIALIZER;
    mqtt_session_t *s;

    LOG_I("[%.*s] received CONNECT (id: %.*s, v: %s, c: %" PRIu8 ", k: %" PRIu16 ", u: %.*s, p: %.*s)",
          MQTT_STR_PRINT(req->p.connect.client_id), MQTT_STR_PRINT(req->p.connect.client_id),
          mqtt_version_name(req->v.connect.protocol_version), req->v.connect.connect_flags.bits.clean_session,
          req->v.connect.keep_alive, MQTT_STR_PRINT(req->p.connect.username), MQTT_STR_PRINT(req->p.connect.password));
    if (req->v.connect.connect_flags.bits.will_flag) {
        LOG_I("\tLWT (retain: %d, topic: %.*s, qos: %d, message: %.*s)", req->v.connect.connect_flags.bits.will_retain,
              MQTT_STR_PRINT(req->p.connect.will_topic), req->v.connect.connect_flags.bits.will_qos,
              MQTT_STR_PRINT(req->p.connect.will_message));
    }
    if (req->ver == MQTT_VERSION_5) {
        if (req->v.connect.connect_flags.bits.will_flag) {
            LOG_PROP(&req->p.connect.v5.will_properties);
        }
        LOG_PROP(&req->v.connect.v5.properties);
    }

    res->f.bits.type = MQTT_CONNACK;

    switch (req->ver) {
    case MQTT_VERSION_3:
        if (req->p.connect.client_id.n < 1 || req->p.connect.client_id.n > 23) {
            res->v.connack.v3.return_code = MQTT_CRC_REFUSED_IDENTIFIER_REJECTED;
            goto e;
        }
        break;
    case MQTT_VERSION_4:
        if (req->v.connect.connect_flags.bits.clean_session == 0 && req->p.connect.client_id.n == 0) {
            res->v.connack.v4.return_code = MQTT_CRC_REFUSED_IDENTIFIER_REJECTED;
            goto e;
        }
        break;
    case MQTT_VERSION_5:
        break;
    }

    // authenticate

    s = 0;
    if (req->p.connect.client_id.n > 0) {
        mqtt_str_copy(&client_id, &req->p.connect.client_id);
        s = mqtt_broker_find_session(&client_id);
        if (s) {
            if (s->c) {
                LOG_D("client.%p.kick", s->c);
                mqtt_client_shutdown(s->c);
                s->c->s = 0;
                s->c = 0;
            }
            if (!req->v.connect.connect_flags.bits.clean_session) {
                switch (req->ver) {
                case MQTT_VERSION_3:
                    break;
                case MQTT_VERSION_4:
                    res->v.connack.v4.acknowledge_flags.bits.session_present = 1;
                    break;
                case MQTT_VERSION_5:
                    res->v.connack.v5.acknowledge_flags.bits.session_present = 1;
                    break;
                }
            } else {
                mqtt_broker_remove_session(s);
                mqtt_session_destroy(s);
                s = 0;
            }
        }
    } else {
        mqtt_client_id_generate(&client_id);
    }

    if (!s) {
        s = mqtt_session_create(&client_id);
        if (s) {
            mqtt_broker_add_session(s);
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

    c->clean_session = req->v.connect.connect_flags.bits.clean_session;
    c->keep_alive = req->v.connect.keep_alive;
    if (req->v.connect.connect_flags.bits.will_flag) {
        c->lwt = mqtt_lwt_create(s, req);
    }
    c->s = s;
    s->c = c;

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
              res->v.connack.v4.acknowledge_flags.bits.session_present, res->v.connack.v4.return_code,
              mqtt_crc_name(res->v.connack.v4.return_code));
        break;
    case MQTT_VERSION_5:
        LOG_I("[%.*s] sending CONNACK (sp: %" PRIu8 ", rc: 0x%02X %s)", MQTT_STR_PRINT(client_id),
              res->v.connack.v5.acknowledge_flags.bits.session_present, res->v.connack.v5.reason_code,
              mqtt_rc_name(res->v.connack.v5.reason_code));
        LOG_PROP(&res->v.connack.v5.properties);
        break;
    }
    return 0;
}

static int
mqtt_on_auth(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    (void)c;
    (void)req;
    (void)res;

    return 0;
}

static int
mqtt_on_publish(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_session_t *s;
    mqtt_message_t *msg;
    uint8_t dup;

    s = c->s;
    if (!s) {
        return -1;
    }
    LOG_I("[%.*s] received PUBLISH (id: %" PRIu16 ", qos: %" PRIu8 ", retain: %" PRIu8 ", dup: %" PRIu8
          ", topic_name: %.*s, ...(%zu bytes))",
          MQTT_STR_PRINT(s->client_id), req->v.publish.packet_id, req->f.bits.qos, req->f.bits.retain, req->f.bits.dup,
          MQTT_STR_PRINT(req->v.publish.topic_name), req->p.publish.message.n);
    if (req->ver == MQTT_VERSION_5) {
        LOG_PROP(&req->v.publish.v5.properties);
    }

    if (mqtt_topic_wildcard(&req->v.publish.topic_name)) {
        LOG_W("invalid publish topic name %.*s", MQTT_STR_PRINT(req->v.publish.topic_name));
        return -1;
    }

    msg = 0;
    if (req->f.bits.qos > MQTT_QOS_0) {
        msg = mqtt_session_incoming_message(s, req->v.publish.packet_id);
    }
    if (!msg) {
        dup = 0;
        msg = mqtt_message_create(s, req);
    } else {
        dup = 1;
    }

    if (!dup) {
        mqtt_broker_dispatch(msg);
    }

    switch (req->f.bits.qos) {
    case MQTT_QOS_0:
        break;
    case MQTT_QOS_1:
        res->f.bits.type = MQTT_PUBACK;
        res->v.puback.packet_id = req->v.publish.packet_id;
        LOG_I("[%.*s] sending PUBACK (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.puback.packet_id);
        break;
    case MQTT_QOS_2:
        res->f.bits.type = MQTT_PUBREC;
        res->v.pubrec.packet_id = req->v.publish.packet_id;
        if (!dup) {
            mqtt_publication_t *pub;

            pub = mqtt_publication_create(msg, req->v.publish.packet_id, msg->qos, msg->retain,
                                          MQTT_PUBLICATION_STATE_REL);
            mqtt_session_incoming_store(s, pub);
        }
        LOG_I("[%.*s] sending PUBREC (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.pubrec.packet_id);
        break;
    }
    return 0;
}

static int
mqtt_on_puback(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
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
mqtt_on_pubrec(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
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

    res->f.bits.type = MQTT_PUBREL;
    res->v.pubrel.packet_id = req->v.pubrec.packet_id;

    if (mqtt_session_outgoing_update(s, req->v.pubrec.packet_id, MQTT_PUBLICATION_STATE_REC,
                                     MQTT_PUBLICATION_STATE_COMP) &&
        req->ver == MQTT_VERSION_5) {
        res->v.pubrel.v5.reason_code = MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND;
    }

    LOG_I("[%.*s] sending PUBREL (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.pubrel.packet_id);
    return 0;
}

static int
mqtt_on_pubrel(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
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

    res->f.bits.type = MQTT_PUBCOMP;
    res->v.pubcomp.packet_id = req->v.pubrel.packet_id;

    if (mqtt_session_incoming_discard(s, req->v.pubrel.packet_id) && req->ver == MQTT_VERSION_5) {
        res->v.pubcomp.v5.reason_code = MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND;
    }

    LOG_I("[%.*s] sending PUBCOMP (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.pubcomp.packet_id);
    return 0;
}

static int
mqtt_on_pubcomp(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
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

    mqtt_session_outgoing_discard(s, req->v.pubcomp.packet_id, MQTT_PUBLICATION_STATE_COMP);
    return 0;
}

static int
mqtt_on_subscribe(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_session_t *s;
    int i;

    s = c->s;
    if (!s) {
        return -1;
    }    
    LOG_I("[%.*s] received SUBSCRIBE (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), req->v.subscribe.packet_id);

    res->f.bits.type = MQTT_SUBACK;
    res->v.suback.packet_id = req->v.subscribe.packet_id;
    mqtt_suback_generate(res, req->p.subscribe.n);

    for (i = 0; i < req->p.subscribe.n; i++) {
        mqtt_str_t topic_filter;
        mqtt_qos_t requested_qos, granted_qos;

        topic_filter = req->p.subscribe.topic_filters[i];
        requested_qos = req->p.subscribe.options[i].bits.qos;
        LOG_I("\ttopic_filter: %.*s, qos: %d", MQTT_STR_PRINT(topic_filter), requested_qos);

        granted_qos = mqtt_session_subscribe(c->s, &topic_filter, requested_qos);

        switch (req->ver) {
        case MQTT_VERSION_3:
            res->p.suback.v3.granted[i].bits.qos = granted_qos;
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
            LOG_I("\tqos: %d", res->p.suback.v3.granted[i].bits.qos);
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
mqtt_on_unsubscribe(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_session_t *s;
    int i;

    s = c->s;
    if (!s) {
        return -1;
    }    
    LOG_I("[%.*s] received UNSUBSCRIBE (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), req->v.unsubscribe.packet_id);

    res->f.bits.type = MQTT_UNSUBACK;
    res->v.unsuback.packet_id = req->v.unsubscribe.packet_id;
    mqtt_unsuback_generate(res, req->p.unsubscribe.n);

    for (i = 0; i < req->p.unsubscribe.n; i++) {
        mqtt_str_t topic_filter = req->p.unsubscribe.topic_filters[i];
        int rc;

        LOG_I("\ttopic_filter: %.*s", MQTT_STR_PRINT(topic_filter));

        rc = mqtt_session_unsubscribe(c->s, &topic_filter);
        if (req->ver == MQTT_VERSION_5) {
            res->p.unsuback.v5.reason_codes[i] = rc ? MQTT_RC_NO_SUBSCRIPTION_EXISTED : MQTT_RC_SUCCESS;
        }
    }
    if (req->ver == MQTT_VERSION_5) {
        LOG_PROP(&req->v.unsubscribe.v5.properties);
    }

    LOG_I("[%.*s] sending UNSUBACK (id: %" PRIu16 ")", MQTT_STR_PRINT(s->client_id), res->v.unsuback.packet_id);
    for (i = 0; i < res->p.suback.n; i++) {
        if (req->ver == MQTT_VERSION_5) {
            LOG_I("\trc: 0x%02X %s", res->p.unsuback.v5.reason_codes[i],
                  mqtt_rc_name(res->p.unsuback.v5.reason_codes[i]));
            LOG_PROP(&res->v.unsuback.v5.properties);
        }
    }
    return 0;
}

static int
mqtt_on_pingreq(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_session_t *s;
    (void)req;

    s = c->s;
    if (!s) {
        return -1;
    }    
    LOG_I("[%.*s] received PINGREQ", MQTT_STR_PRINT(s->client_id));

    res->f.bits.type = MQTT_PINGRESP;

    LOG_I("[%.*s] sending PINGRESP", MQTT_STR_PRINT(s->client_id));
    return 0;
}

static int
mqtt_on_disconnect(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
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

    if (c->lwt) {
        mqtt_message_destroy(c->lwt);
        c->lwt = 0;
    }

    return 1;
}

static int
mqtt_client_handle(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    int rc;

    switch (req->f.bits.type) {
    case MQTT_CONNECT:
        rc = mqtt_on_connect(c, req, res);
        break;
    case MQTT_AUTH:
        rc = mqtt_on_auth(c, req, res);
        break;
    case MQTT_PUBLISH:
        rc = mqtt_on_publish(c, req, res);
        break;
    case MQTT_PUBACK:
        rc = mqtt_on_puback(c, req, res);
        break;
    case MQTT_PUBREC:
        rc = mqtt_on_pubrec(c, req, res);
        break;
    case MQTT_PUBREL:
        rc = mqtt_on_pubrel(c, req, res);
        break;
    case MQTT_PUBCOMP:
        rc = mqtt_on_pubcomp(c, req, res);
        break;
    case MQTT_SUBSCRIBE:
        rc = mqtt_on_subscribe(c, req, res);
        break;
    case MQTT_UNSUBSCRIBE:
        rc = mqtt_on_unsubscribe(c, req, res);
        break;
    case MQTT_PINGREQ:
        rc = mqtt_on_pingreq(c, req, res);
        break;
    case MQTT_DISCONNECT:
        rc = mqtt_on_disconnect(c, req, res);
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

        c->t_last = B.t_now;

        rc = mqtt_client_handle(c, &req, &res);
        if (!rc && MQTT_IS_PACKET_TYPE(res.f.bits.type)) {
            rc = mqtt_client_send(c, &res);
        }
        mqtt_packet_unit(&req);
        if (rc) {
            break;
        }
    }
    return rc;
}

static mqtt_client_t *
mqtt_client_create(uv_tcp_t *tcp, const char *ip, int port) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)malloc(sizeof *c);
    memset(c, 0, sizeof *c);

    mqtt_parser_init(&c->parser);
    strcpy(c->ip, ip);
    c->port = port;
    c->tcp = tcp;
    c->tcp->data = c;

    LOG_D("client.%p.create ip:%s", c, ip);
    return c;
}

static void
mqtt_client_destroy(mqtt_client_t *c) {
    mqtt_session_t *s;

    LOG_D("client.%p.destroy %s:%d", c, c->ip, c->port);
    mqtt_parser_unit(&c->parser);
    mqtt_str_free(&c->buff);

    s = c->s;
    if (s) {
        if (c->clean_session) {
            mqtt_broker_remove_session(s);
            mqtt_session_destroy(s);
        } else {
            s->c = 0;
        }
    }
    free(c);
}

static int
mqtt_client_update(mqtt_client_t *c) {
    if (c->keep_alive > 0) {
        uint64_t expired = c->keep_alive * 1.5;
        if (B.t_now - c->t_last > expired) {
            return -1;
        }
    }
    return 0;
}

static void
_client_on_close(uv_handle_t *handle) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)handle->data;

    free(handle);
    if (!c) {
        return;
    }
    if (c->lwt) {
        mqtt_broker_dispatch(c->lwt);
    }
    mqtt_broker_remove_client(c);
    mqtt_client_destroy(c);
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
        uv_close((uv_handle_t *)stream, _client_on_close);
        return;
    }
    if (mqtt_client_data(c, buf->base, nread)) {
        mqtt_client_shutdown(c);
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
        c->buff.s = malloc(suggested_size);
        c->buff.n = suggested_size;
    }
    buf->base = c->buff.s;
    buf->len = c->buff.n;
}

static void
_broker_on_connection(uv_stream_t *server, int status) {
    uv_tcp_t *tcp;
    mqtt_client_t *c;
    struct sockaddr addr;
    char ip[INET6_ADDRSTRLEN];
    int rc, addrlen, port;

    if (status != 0) {
        LOG_W("connect: %s", uv_strerror(status));
        return;
    }

    tcp = (uv_tcp_t *)malloc(sizeof *tcp);
    uv_tcp_init(server->loop, tcp);
    rc = uv_accept(server, (uv_stream_t *)tcp);
    if (rc) {
        LOG_W("accept: %s", uv_strerror(rc));
        uv_close((uv_handle_t *)tcp, _client_on_close);
        return;
    }
    uv_read_start((uv_stream_t *)tcp, _client_on_alloc, _client_on_read);

    addrlen = sizeof(addr);
    uv_tcp_getpeername(tcp, &addr, &addrlen);
    uv_ip4_name((struct sockaddr_in *)&addr, ip, sizeof(ip));
    port = ntohs(((struct sockaddr_in *)&addr)->sin_port);

    c = mqtt_client_create(tcp, ip, port);
    mqtt_broker_add_client(c);
}

static void
_broker_on_timer(uv_timer_t *handle) {
    queue_t *node;
    (void)handle;

    B.t_now++;
    LOG_UPDATE(B.t_now);
    queue_foreach(node, &B.client_q) {
        mqtt_client_t *c;

        c = queue_data(node, mqtt_client_t, node);
        if (!c->closed && mqtt_client_update(c)) {
            LOG_D("client.%p.timeout", c);
            mqtt_client_shutdown(c);
        }
    }
}

static int
_broker_config(void *ud, const char *section, const char *key, const char *value) {
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
            B.host = strdup(value);
        } else if (!strcmp(key, "port")) {
            B.port = atoi(value);
        }
    }

    return 0;
}

static int
mqtt_broker_init(uv_loop_t *loop, int argc, char *argv[]) {
    B.loop = loop;
    B.t_now = 0;
    B.host = "0.0.0.0";
    B.port = 1883;

    queue_init(&B.client_q);
    queue_init(&B.msg_q);
    map_init(&B.session_m, _mqtt_session_client_id_key, _mqtt_session_client_id_cmp);
    B.sub_root = mqtt_trie_create(0, 0);

    if (argc > 1 && ini_parse(argv[1], _broker_config, 0)) {
        LOG_E("config file %s parse error", argv[1]);
        return -1;
    }

    snowflake_init(&B.snowflake, 0, 0);
    return 0;
}

int
main(int argc, char *argv[]) {
    uv_loop_t *loop;
    uv_tcp_t server;
    uv_timer_t timer;
    struct sockaddr_in addr;
    int rc;

    signal(SIGPIPE, SIG_IGN);

    loop = uv_default_loop();

    if (mqtt_broker_init(loop, argc, argv)) {
        LOG_E("broker init failed");
        return EXIT_FAILURE;
    }

    uv_tcp_init(loop, &server);
    rc = uv_ip4_addr(B.host, B.port, &addr);
    if (rc) {
        LOG_E("ip4_addr %s:%d %s", B.host, B.port, uv_strerror(rc));
        return EXIT_FAILURE;
    }
    rc = uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);
    if (rc) {
        LOG_E("bind %s:%d %s", B.host, B.port, uv_strerror(rc));
        return EXIT_FAILURE;
    }
    rc = uv_listen((uv_stream_t *)&server, SOMAXCONN, _broker_on_connection);
    if (rc) {
        LOG_E("listen %s:%d %s", B.host, B.port, uv_strerror(rc));
        return EXIT_FAILURE;
    }

    uv_timer_init(loop, &timer);
    uv_timer_start(&timer, _broker_on_timer, 1000, 1000);

    uv_idle_init(loop, &B.idle);

    LOG_I("mqtt broker at %s:%d started", B.host, B.port);
    return uv_run(loop, UV_RUN_DEFAULT);
}
