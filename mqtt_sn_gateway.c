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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_DUMP(...) gateway_log_dump(__VA_ARGS__)

typedef enum {
    MQTT_SN_STATE_DISCONNECTED,
    MQTT_SN_STATE_ACTIVE,
    MQTT_SN_STATE_ASLEEP,
    MQTT_SN_STATE_AWAKE,
    MQTT_SN_STATE_LOST,
} mqtt_sn_client_state_t;

typedef struct mqtt_client_s mqtt_client_t;
typedef struct mqtt_sn_client_s mqtt_sn_client_t;
typedef struct mqtt_sn_register_topic_s mqtt_sn_register_topic_t;
typedef struct mqtt_sn_padding_topic_s mqtt_sn_padding_topic_t;
typedef struct mqtt_sn_gateway_s mqtt_sn_gateway_t;

struct mqtt_sn_register_topic_s {
    uint16_t id;
    mqtt_str_t name;

    queue_t node;
};

struct mqtt_sn_padding_topic_s {
    uint16_t msg_id;
    mqtt_sn_topic_t topic;

    queue_t node;
};

struct mqtt_sn_client_s {
    mqtt_str_t client_id;
    uint16_t duration;
    uint8_t clean_session;

    struct sockaddr addr;
    mqtt_sn_parser_t parser;
    struct {
        uint8_t retain;
        mqtt_sn_qos_t qos;
        mqtt_str_t topic;
        mqtt_str_t message;
    } lwt;

    uint64_t t_last;
    map_node_t node;

    uint16_t topic_id;
    uint16_t msg_id;
    queue_t topic_q;
    queue_t padding_q;

    mqtt_sn_client_state_t state;

    mqtt_client_t *mc;
};

struct mqtt_client_s {
    uv_connect_t connector;
    uv_getaddrinfo_t resolver;
    uv_tcp_t tcp;
    mqtt_parser_t parser;
    mqtt_str_t buff;

    mqtt_sn_client_t *msc;
};

struct mqtt_sn_gateway_s {
    uv_loop_t *loop;
    uv_udp_t *udp;
    uint16_t gwid;
    mqtt_sn_gateway_transmission_t transmission;
    mqtt_str_t buff;
    uint16_t t_adv;
    char *host;
    int port;
    struct {
        char *host;
        int port;
    } broadcast;
    struct {
        char *host;
        char *port;
        char *username;
        char *password;
        mqtt_version_t version;
    } broker;
    struct {
        uint64_t now;
        uint64_t last_adv;
    } t;
    snowflake_t snowflake;
    map_t client_m;
};

static mqtt_sn_gateway_t G = {0};

static void
_gateway_dump(void *ud, const char *str) {
    (void)ud;

    logger_print(logger_default(), LOG_LEVEL_DEBUG, "%s", str);
}

static void
gateway_log_dump(const void *data, size_t size) {
    mqtt_str_t str = {.s = (char *)data, .n = size};
    mqtt_str_dump(&str, 0, _gateway_dump);
}

static uint16_t
_client_register_topic(mqtt_sn_client_t *c, mqtt_str_t *topic_name) {
    mqtt_sn_register_topic_t *t;
    uint16_t id;

    id = ++c->topic_id;
    if (id == 0)
        id = ++c->topic_id;

    t = (mqtt_sn_register_topic_t *)malloc(sizeof *t);
    t->id = id;
    mqtt_str_copy(&t->name, topic_name);
    queue_insert_tail(&c->topic_q, &t->node);

    return t->id;
}

static mqtt_str_t *
_client_find_topic_by_id(mqtt_sn_client_t *c, uint16_t topic_id) {
    queue_t *node;

    queue_foreach(node, &c->topic_q) {
        mqtt_sn_register_topic_t *t;

        t = queue_data(node, mqtt_sn_register_topic_t, node);
        if (t->id == topic_id)
            return &t->name;
    }

    return 0;
}

static uint16_t
_client_find_topic_by_name(mqtt_sn_client_t *c, mqtt_str_t *topic_name) {
    queue_t *node;

    queue_foreach(node, &c->topic_q) {
        mqtt_sn_register_topic_t *t;

        t = queue_data(node, mqtt_sn_register_topic_t, node);
        if (mqtt_str_equal(&t->name, topic_name))
            return t->id;
    }

    return 0;
}

static void
_client_add_padding(mqtt_sn_client_t *c, uint16_t msg_id, mqtt_sn_topic_t *topic) {
    mqtt_sn_padding_topic_t *t;

    t = (mqtt_sn_padding_topic_t *)malloc(sizeof *t);
    memset(t, 0, sizeof *t);
    t->msg_id = msg_id;
    mqtt_sn_topic_set(&t->topic, topic);

    queue_insert_tail(&c->padding_q, &t->node);
}

static mqtt_sn_padding_topic_t *
_client_find_padding(mqtt_sn_client_t *c, uint16_t msg_id) {
    queue_t *node;

    queue_foreach(node, &c->padding_q) {
        mqtt_sn_padding_topic_t *t;

        t = queue_data(node, mqtt_sn_padding_topic_t, node);
        if (t->msg_id == msg_id) {
            return t;
        }
    }
    return 0;
}

static void
_client_remove_padding(mqtt_sn_client_t *c, mqtt_sn_padding_topic_t *t) {
    queue_remove(&t->node);
    free(t);
}

static mqtt_client_t *
mqtt_client_create(mqtt_sn_client_t *msc) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)malloc(sizeof *c);
    memset(c, 0, sizeof *c);

    mqtt_parser_init(&c->parser);
    mqtt_parser_version(&c->parser, G.broker.version);
    c->msc = msc;

    return c;
}

static void
mqtt_client_destroy(mqtt_client_t *c) {
    mqtt_parser_unit(&c->parser);
    free(c);
}

static void
_gateway_on_send(uv_udp_send_t *req, int status) {
    if (status) {
        LOG_W("write: %s", uv_strerror(status));
    }
    free(req->data);
    free(req);
}

static int
_gateway_send(mqtt_sn_packet_t *pkt, struct sockaddr_in *addr) {
    mqtt_str_t b;
    uv_udp_send_t *req;
    uv_buf_t buf;

    mqtt_sn_serialize(pkt, &b);

    LOG_D("");
    LOG_DUMP(b.s, b.n);

    req = (uv_udp_send_t *)malloc(sizeof *req);
    req->data = b.s;
    buf = uv_buf_init(b.s, b.n);
    return uv_udp_send(req, G.udp, &buf, 1, (const struct sockaddr *)addr, _gateway_on_send);
}

static int
_gateway_broadcast(mqtt_sn_packet_t *pkt) {
    struct sockaddr_in addr;

    uv_ip4_addr(G.broadcast.host, G.broadcast.port, &addr);
    LOG_I("gateway broadcast: %s", mqtt_sn_packet_type_name(pkt->type));
    return _gateway_send(pkt, &addr);
}

static int
_gateway_unicast(mqtt_sn_client_t *c, mqtt_sn_packet_t *pkt) {
    LOG_I("gateway unicast: %s", mqtt_sn_packet_type_name(pkt->type));
    return _gateway_send(pkt, (struct sockaddr_in *)&c->addr);
}

static void
_broker_on_close(uv_handle_t *handle) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)handle->data;

    mqtt_client_destroy(c);
}

static void
_broker_on_write(uv_write_t *req, int status) {
    if (status) {
        LOG_W("write: %s", uv_strerror(status));
    }
    free(req->data);
    free(req);
}

static int
_broker_send(mqtt_client_t *c, mqtt_packet_t *pkt) {
    mqtt_str_t b = MQTT_STR_INITIALIZER;
    int rc;

    LOG_I("broker send: %s", mqtt_packet_type_name(pkt->f.bits.type));

    rc = mqtt_serialize(pkt, &b);
    mqtt_packet_unit(pkt);
    if (!rc) {
        uv_write_t *req;
        uv_buf_t buf;

        LOG_D("");
        LOG_DUMP(b.s, b.n);

        req = (uv_write_t *)malloc(sizeof *req);
        req->data = b.s;
        buf = uv_buf_init(b.s, b.n);
        rc = uv_write(req, (uv_stream_t *)&c->tcp, &buf, 1, _broker_on_write);
        if (rc) {
            LOG_W("write: %s", uv_strerror(rc));
        }
    }
    return rc;
}

static int
mqtt_on_connack(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_sn_client_t *msc;
    mqtt_sn_packet_t pkt;

    msc = c->msc;
    mqtt_sn_packet_init(&pkt, MQTT_SN_CONNACK);

    pkt.v.connack.return_code = MQTT_SN_RC_REJECTED_NOT_SUPPORTED;
    if (res->ver == MQTT_VERSION_3 && res->v.connack.v3.return_code == MQTT_CRC_ACCEPTED) {
        pkt.v.connack.return_code = MQTT_SN_RC_ACCEPTED;
        msc->state = MQTT_SN_STATE_ACTIVE;
    }
    if (res->ver == MQTT_VERSION_4 && res->v.connack.v4.return_code == MQTT_CRC_ACCEPTED) {
        pkt.v.connack.return_code = MQTT_SN_RC_ACCEPTED;
        msc->state = MQTT_SN_STATE_ACTIVE;
    }

    return _gateway_unicast(msc, &pkt);
}

static int
mqtt_on_publish(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    uint16_t topic_id;
    mqtt_sn_client_t *msc;
    mqtt_sn_packet_t pkt;

    msc = c->msc;

    topic_id = _client_find_topic_by_name(msc, &req->v.publish.topic_name);
    if (!topic_id) {
        uint16_t msg_id;

        msg_id = ++msc->msg_id;
        if (!msg_id)
            msg_id = ++msc->msg_id;

        topic_id = _client_register_topic(msc, &req->v.publish.topic_name);
        mqtt_sn_packet_init(&pkt, MQTT_SN_REGISTER);
        pkt.v.regist.msg_id = msg_id;
        pkt.v.regist.topic_id = topic_id;
        mqtt_str_set(&pkt.v.regist.topic_name, &req->v.publish.topic_name);

        _gateway_unicast(msc, &pkt);
    }

    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBLISH);
    pkt.v.publish.flags.bits.dup = req->f.bits.dup;
    pkt.v.publish.flags.bits.qos = req->f.bits.qos;
    pkt.v.publish.flags.bits.retain = req->f.bits.retain;
    pkt.v.publish.flags.bits.topic_id_type = MQTT_SN_TOPIC_ID_TYPE_PREDEFINED;
    pkt.v.publish.msg_id = req->v.publish.packet_id;
    pkt.v.publish.topic.id = topic_id;
    mqtt_str_set(&pkt.v.publish.data, &req->p.publish.message);

    return _gateway_unicast(msc, &pkt);
}

static int
mqtt_on_puback(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_sn_packet_t pkt;
    mqtt_sn_padding_topic_t *t;

    t = _client_find_padding(c->msc, req->v.puback.packet_id);
    if (!t)
        return -1;

    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBACK);
    pkt.v.puback.msg_id = req->v.puback.packet_id;
    mqtt_sn_topic_set(&pkt.v.puback.topic, &t->topic);
    pkt.v.puback.return_code = MQTT_SN_RC_ACCEPTED;

    _client_remove_padding(c->msc, t);

    return _gateway_unicast(c->msc, &pkt);
}

static int
mqtt_on_pubrec(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_sn_packet_t pkt;
    mqtt_sn_padding_topic_t *t;

    t = _client_find_padding(c->msc, req->v.puback.packet_id);
    if (!t)
        return -1;

    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBREC);

    pkt.v.pubrec.msg_id = req->v.pubrec.packet_id;

    _client_remove_padding(c->msc, t);

    return _gateway_unicast(c->msc, &pkt);
}

static int
mqtt_on_pubrel(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBREL);

    pkt.v.pubrel.msg_id = req->v.pubrel.packet_id;

    return _gateway_unicast(c->msc, &pkt);
}

static int
mqtt_on_pubcomp(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBCOMP);

    pkt.v.pubcomp.msg_id = req->v.pubcomp.packet_id;

    return _gateway_unicast(c->msc, &pkt);
}

static int
mqtt_on_suback(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_sn_packet_t pkt;
    mqtt_sn_padding_topic_t *t;

    t = _client_find_padding(c->msc, req->v.suback.packet_id);
    if (!t)
        return -1;

    mqtt_sn_packet_init(&pkt, MQTT_SN_SUBACK);
    pkt.v.suback.msg_id = req->v.suback.packet_id;
    if (req->ver == MQTT_VERSION_3) {
        pkt.v.suback.flags.bits.qos = req->p.suback.v3.granted[0].bits.qos;
        pkt.v.suback.return_code = MQTT_SN_RC_ACCEPTED;
    } else if (req->ver == MQTT_VERSION_4) {
        if (req->p.suback.v4.return_codes[0] == MQTT_SRC_QOS_F)
            pkt.v.suback.return_code = MQTT_SN_RC_REJECTED_NOT_SUPPORTED;
        else
            pkt.v.suback.flags.bits.qos = req->p.suback.v4.return_codes[0];
    }
    pkt.v.suback.topic_id = t->topic.id;

    _client_remove_padding(c->msc, t);

    return _gateway_unicast(c->msc, &pkt);
}

static int
mqtt_on_unsuback(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_UNSUBACK);
    pkt.v.unsuback.msg_id = req->v.unsuback.packet_id;

    return _gateway_unicast(c->msc, &pkt);
}

static int
mqtt_on_pingresp(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_PINGRESP);

    return _gateway_unicast(c->msc, &pkt);
}

static int
_broker_handle(mqtt_client_t *c, mqtt_packet_t *req, mqtt_packet_t *res) {
    int rc;

    LOG_I("broker recv: %s", mqtt_packet_type_name(req->f.bits.type));
    switch (req->f.bits.type) {
    case MQTT_CONNACK:
        rc = mqtt_on_connack(c, req, res);
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
    case MQTT_SUBACK:
        rc = mqtt_on_suback(c, req, res);
        break;
    case MQTT_UNSUBACK:
        rc = mqtt_on_unsuback(c, req, res);
        break;
    case MQTT_PINGRESP:
        rc = mqtt_on_pingresp(c, req, res);
        break;
    default:
        rc = -1;
        break;
    }
    return rc;
}

static void
_broker_on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    mqtt_client_t *c;
    mqtt_str_t b;
    mqtt_packet_t req;
    int rc;

    if (nread < 0) {
        if (nread != UV_EOF) {
            LOG_W("read: %s", uv_strerror(nread));
        }
        uv_close((uv_handle_t *)stream, _broker_on_close);
        return;
    }

    LOG_D("");
    LOG_DUMP(buf->base, nread);

    c = (mqtt_client_t *)stream->data;
    mqtt_str_init(&b, buf->base, nread);
    while ((rc = mqtt_parse(&c->parser, &b, &req)) > 0) {
        mqtt_packet_t res;

        mqtt_packet_init(&res, req.ver, MQTT_RESERVED);

        rc = _broker_handle(c, &req, &res);
        if (!rc && MQTT_IS_PACKET_TYPE(res.f.bits.type)) {
            rc = _broker_send(c, &res);
        }
        mqtt_packet_unit(&req);
        if (rc) {
            break;
        }
    }
}

static void
_broker_on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
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

static int
_mqtt_connect(mqtt_client_t *c) {
    mqtt_packet_t pkt;
    mqtt_sn_client_t *msc;

    msc = c->msc;

    mqtt_packet_init(&pkt, G.broker.version, MQTT_CONNECT);
    pkt.v.connect.connect_flags.bits.clean_session = msc->clean_session;
    pkt.v.connect.keep_alive = msc->duration;
    mqtt_str_set(&pkt.p.connect.client_id, &msc->client_id);
    if (G.broker.username) {
        pkt.v.connect.connect_flags.bits.username_flag = 1;
        mqtt_str_from(&pkt.p.connect.username, G.broker.username);
    }
    if (G.broker.password) {
        pkt.v.connect.connect_flags.bits.password_flag = 1;
        mqtt_str_from(&pkt.p.connect.password, G.broker.password);
    }
    if (!mqtt_str_empty(&msc->lwt.topic)) {
        pkt.v.connect.connect_flags.bits.will_flag = 1;
        pkt.v.connect.connect_flags.bits.will_retain = msc->lwt.retain;
        pkt.v.connect.connect_flags.bits.will_qos = (mqtt_qos_t)msc->lwt.qos;
        mqtt_str_set(&pkt.p.connect.will_topic, &msc->lwt.topic);
        mqtt_str_set(&pkt.p.connect.will_message, &msc->lwt.message);
    }

    return _broker_send(c, &pkt);
}

static void
_broker_on_connect(uv_connect_t *req, int status) {
    mqtt_client_t *c;

    if (status != 0) {
        LOG_W("connect %s:%s : %s", G.broker.host, G.broker.port, uv_strerror(status));
        return;
    }

    c = (mqtt_client_t *)req->data;
    uv_read_start((uv_stream_t *)&c->tcp, _broker_on_alloc, _broker_on_read);
    _mqtt_connect(c);
}

static void
_broker_on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
    mqtt_client_t *c;
    char ip[INET6_ADDRSTRLEN] = {0};
    int rc;

    if (status < 0) {
        LOG_W("getaddrinfo %s: %s", G.broker.host, uv_err_name(status));
        return;
    }

    c = (mqtt_client_t *)resolver->data;

    uv_ip4_name((struct sockaddr_in *)res->ai_addr, ip, sizeof(ip));
    uv_tcp_init(G.loop, &c->tcp);
    c->tcp.data = c;
    c->connector.data = c;

    rc = uv_tcp_connect(&c->connector, &c->tcp, (const struct sockaddr *)res->ai_addr, _broker_on_connect);
    if (rc) {
        LOG_W("connect %s:%s : %s", ip, G.broker.port, uv_strerror(rc));
    }

    uv_freeaddrinfo(res);
}

static int
_broker_connect(mqtt_client_t *c) {
    struct addrinfo hints;
    int rc;

    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    c->resolver.data = c;
    rc = uv_getaddrinfo(G.loop, &c->resolver, _broker_on_resolved, G.broker.host, G.broker.port, &hints);
    if (rc) {
        LOG_W("getaddrinfo %s: %s", G.broker.host, uv_strerror(rc));
    }
    return rc;
}

static mqtt_sn_client_t *
mqtt_sn_client_fetch(const struct sockaddr *addr) {
    map_node_t *node;
    mqtt_sn_client_t *c;

    node = map_find(&G.client_m, (void *)addr);
    if (!node) {
        c = (mqtt_sn_client_t *)malloc(sizeof *c);
        memset(c, 0, sizeof *c);
        memcpy(&c->addr, addr, sizeof(struct sockaddr));

        mqtt_sn_parser_init(&c->parser);
        queue_init(&c->topic_q);
        queue_init(&c->padding_q);

        c->state = MQTT_SN_STATE_DISCONNECTED;

        map_push(&G.client_m, (void *)addr, &c->node);
    } else {
        c = map_data(node, mqtt_sn_client_t, node);
    }

    LOG_D("addr: %d, c: %p", ((struct sockaddr_in *)addr)->sin_addr.s_addr, c);

    return c;
}

// static void
// mqtt_sn_client_release(mqtt_sn_client_t *c) {
//     mqtt_sn_parser_unit(&c->parser);
//     free(c);
// }

static void
_check_advertise() {
    mqtt_sn_packet_t pkt;

    if (G.t.now - G.t.last_adv < G.t_adv) {
        return;
    }

    G.t.last_adv = G.t.now;

    mqtt_sn_packet_init(&pkt, MQTT_SN_ADVERTISE);
    pkt.v.advertise.gwid = G.gwid;
    pkt.v.advertise.duration = G.t_adv;

    _gateway_broadcast(&pkt);
}

static void
_check_keepalive() {
    map_node_t *node;

    map_foreach(node, &G.client_m) {
        mqtt_sn_client_t *c;

        c = map_data(node, mqtt_sn_client_t, node);
        if (c->duration > 0 && G.t.now - c->t_last > c->duration) {
            c->state = MQTT_SN_STATE_LOST;

            if (!mqtt_str_empty(&c->lwt.topic)) {
                mqtt_packet_t pkt;

                mqtt_packet_init(&pkt, G.broker.version, MQTT_PUBLISH);
                pkt.f.bits.qos = c->lwt.qos;
                pkt.f.bits.retain = c->lwt.retain;
                mqtt_str_set(&pkt.v.publish.topic_name, &c->lwt.topic);
                mqtt_str_set(&pkt.p.publish.message, &c->lwt.message);

                _broker_send(c->mc, &pkt);
            }
        }
    }
}

static void
_gateway_on_timer(uv_timer_t *handle) {
    (void)handle;

    G.t.now++;
    LOG_UPDATE(G.t.now);

    _check_advertise();
    _check_keepalive();
}

static int
mqtt_sn_on_searchgw(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_sn_packet_t res;

    mqtt_sn_packet_init(&res, MQTT_SN_GWINFO);
    res.v.gwinfo.gwid = G.gwid;
    return _gateway_broadcast(&res);
}

static int
mqtt_sn_on_connect(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    c->duration = req->v.connect.duration;
    c->clean_session = req->v.connect.flags.bits.clean_session;
    mqtt_str_copy(&c->client_id, &req->v.connect.client_id);

    if (c->state == MQTT_SN_STATE_ASLEEP || c->state == MQTT_SN_STATE_AWAKE) {
        mqtt_sn_packet_t res;

        mqtt_sn_packet_init(&res, MQTT_SN_CONNACK);
        res.v.connack.return_code = MQTT_SN_RC_ACCEPTED;
        return _gateway_unicast(c, &res);
    }

    if (req->v.connect.flags.bits.will) {
        mqtt_sn_packet_t res;

        mqtt_sn_packet_init(&res, MQTT_SN_WILLTOPICREQ);
        return _gateway_unicast(c, &res);
    }

    c->mc = mqtt_client_create(c);
    return _broker_connect(c->mc);
}

static int
mqtt_sn_on_willtopic(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_sn_packet_t res;

    c->lwt.retain = req->v.willtopic.flags.bits.retain;
    c->lwt.qos = req->v.willtopic.flags.bits.qos;
    mqtt_str_copy(&c->lwt.topic, &req->v.willtopic.topic_name);

    mqtt_sn_packet_init(&res, MQTT_SN_WILLMSGREQ);
    return _gateway_unicast(c, &res);
}

static int
mqtt_sn_on_willtopicupd(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_sn_packet_t res;

    c->lwt.retain = req->v.willtopicupd.flags.bits.retain;
    c->lwt.qos = req->v.willtopicupd.flags.bits.qos;

    mqtt_str_free(&c->lwt.topic);
    mqtt_str_copy(&c->lwt.topic, &req->v.willtopicupd.topic_name);

    mqtt_sn_packet_init(&res, MQTT_SN_WILLTOPICRESP);
    return _gateway_unicast(c, &res);
}

static int
mqtt_sn_on_willmsg(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_str_copy(&c->lwt.message, &req->v.willmsg.message);

    c->mc = mqtt_client_create(c);
    return _broker_connect(c->mc);
}

static int
mqtt_sn_on_willmsgupd(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_sn_packet_t res;

    mqtt_str_free(&c->lwt.message);
    mqtt_str_copy(&c->lwt.message, &req->v.willmsgupd.message);

    mqtt_sn_packet_init(&res, MQTT_SN_WILLMSGRESP);
    return _gateway_unicast(c, &res);
}

static int
mqtt_sn_on_register(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_sn_packet_t res;
    uint16_t topic_id;

    topic_id = _client_register_topic(c, &req->v.regist.topic_name);

    mqtt_sn_packet_init(&res, MQTT_SN_REGACK);
    res.v.regack.msg_id = req->v.regist.msg_id;
    res.v.regack.topic_id = topic_id;
    res.v.regack.return_code = MQTT_SN_RC_ACCEPTED;

    return _gateway_unicast(c, &res);
}

static int
mqtt_sn_on_publish(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_str_t topic_name = MQTT_STR_INITIALIZER, *topic;
    char short_name[3];
    mqtt_sn_topic_t t = MQTT_SN_TOPIC_INITIALIZER;
    mqtt_packet_t pkt;

    switch (req->v.publish.topic.type) {
    case MQTT_SN_TOPIC_ID_TYPE_PREDEFINED:
        topic = _client_find_topic_by_id(c, req->v.publish.topic.id);
        if (topic)
            mqtt_str_set(&topic_name, topic);
        break;
    case MQTT_SN_TOPIC_ID_TYPE_SHORT:
        short_name[0] = req->v.publish.topic.shor[0];
        short_name[1] = req->v.publish.topic.shor[1];
        short_name[2] = '\0';
        mqtt_str_from(&topic_name, short_name);
        break;
    default:
        break;
    }

    if (mqtt_str_empty(&topic_name)) {
        mqtt_sn_packet_t res;

        mqtt_sn_packet_init(&res, MQTT_SN_PUBACK);
        res.v.puback.msg_id = req->v.publish.msg_id;
        res.v.puback.topic.id = req->v.publish.topic.id;
        res.v.puback.return_code = MQTT_SN_RC_REJECTED_TOPIC_ID;

        return _gateway_unicast(c, &res);
    }

    if (req->v.publish.flags.bits.qos == MQTT_SN_QOS_1 || req->v.publish.flags.bits.qos == MQTT_SN_QOS_2) {
        mqtt_sn_topic_set(&t, &req->v.publish.topic);
        _client_add_padding(c, req->v.publish.msg_id, &t);
    }

    mqtt_packet_init(&pkt, G.broker.version, MQTT_PUBLISH);
    pkt.f.bits.dup = req->v.publish.flags.bits.dup;
    if (req->v.publish.flags.bits.qos == MQTT_SN_QOS_3)
        pkt.f.bits.qos = MQTT_QOS_0;
    else
        pkt.f.bits.qos = req->v.publish.flags.bits.qos;
    pkt.v.publish.packet_id = req->v.publish.msg_id;
    mqtt_str_set(&pkt.v.publish.topic_name, &topic_name);
    mqtt_str_set(&pkt.p.publish.message, &req->v.publish.data);

    return _broker_send(c->mc, &pkt);
}

static int
mqtt_sn_on_puback(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, G.broker.version, MQTT_PUBACK);
    pkt.v.puback.packet_id = req->v.puback.msg_id;

    return _broker_send(c->mc, &pkt);
}

static int
mqtt_sn_on_pubrec(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, G.broker.version, MQTT_PUBREC);
    pkt.v.pubrec.packet_id = req->v.pubrec.msg_id;

    return _broker_send(c->mc, &pkt);
}

static int
mqtt_sn_on_pubrel(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, G.broker.version, MQTT_PUBREL);
    pkt.v.pubrel.packet_id = req->v.pubrel.msg_id;

    return _broker_send(c->mc, &pkt);
}

static int
mqtt_sn_on_pubcomp(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, G.broker.version, MQTT_PUBCOMP);
    pkt.v.pubcomp.packet_id = req->v.pubcomp.msg_id;

    return _broker_send(c->mc, &pkt);
}

static int
mqtt_sn_on_subscribe(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_str_t topic_name = MQTT_STR_INITIALIZER, *topic;
    uint16_t topic_id;
    char short_name[3];
    mqtt_sn_topic_t t = MQTT_SN_TOPIC_INITIALIZER;
    mqtt_packet_t pkt;

    switch (req->v.subscribe.topic.type) {
    case MQTT_SN_TOPIC_ID_TYPE_NORMAL:
        mqtt_str_set(&topic_name, &req->v.subscribe.topic.name);
        topic_id = _client_find_topic_by_name(c, &req->v.subscribe.topic.name);
        break;
    case MQTT_SN_TOPIC_ID_TYPE_PREDEFINED:
        topic_id = req->v.subscribe.topic.id;
        topic = _client_find_topic_by_id(c, req->v.subscribe.topic.id);
        if (topic)
            mqtt_str_set(&topic_name, topic);
        break;
    case MQTT_SN_TOPIC_ID_TYPE_SHORT:
        short_name[0] = req->v.subscribe.topic.shor[0];
        short_name[1] = req->v.subscribe.topic.shor[1];
        short_name[2] = '\0';
        mqtt_str_from(&topic_name, short_name);
        topic_id = 0;
        break;
    default:
        topic_id = 0;
        break;
    }

    if (mqtt_str_empty(&topic_name)) {
        mqtt_sn_packet_t res;
        mqtt_sn_packet_init(&res, MQTT_SN_SUBACK);
        res.v.suback.msg_id = req->v.subscribe.msg_id;
        res.v.suback.topic_id = topic_id;
        res.v.suback.return_code = MQTT_SN_RC_REJECTED_TOPIC_ID;

        return _gateway_unicast(c, &res);
    }

    t.id = topic_id;
    t.type = MQTT_SN_TOPIC_ID_TYPE_PREDEFINED;
    _client_add_padding(c, req->v.subscribe.msg_id, &t);

    mqtt_packet_init(&pkt, G.broker.version, MQTT_SUBSCRIBE);
    pkt.v.subscribe.packet_id = req->v.subscribe.msg_id;
    mqtt_subscribe_generate(&pkt, 1);
    mqtt_str_set(&pkt.p.subscribe.topic_filters[0], &topic_name);
    pkt.p.subscribe.options[0].bits.qos = req->v.subscribe.flags.bits.qos;

    return _broker_send(c->mc, &pkt);
}

static int
mqtt_sn_on_unsubscribe(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_str_t topic_name = MQTT_STR_INITIALIZER, *topic;
    char short_name[3];
    mqtt_packet_t pkt;

    switch (req->v.unsubscribe.topic.type) {
    case MQTT_SN_TOPIC_ID_TYPE_NORMAL:
        mqtt_str_set(&topic_name, &req->v.unsubscribe.topic.name);
        break;
    case MQTT_SN_TOPIC_ID_TYPE_PREDEFINED:
        topic = _client_find_topic_by_id(c, req->v.unsubscribe.topic.id);
        if (topic)
            mqtt_str_set(&topic_name, topic);
        break;
    case MQTT_SN_TOPIC_ID_TYPE_SHORT:
        short_name[0] = req->v.unsubscribe.topic.shor[0];
        short_name[1] = req->v.unsubscribe.topic.shor[1];
        short_name[2] = '\0';
        mqtt_str_from(&topic_name, short_name);
        break;
    }

    if (mqtt_str_empty(&topic_name)) {
        mqtt_sn_packet_t res;
        mqtt_sn_packet_init(&res, MQTT_SN_UNSUBACK);
        res.v.unsuback.msg_id = req->v.unsubscribe.msg_id;

        return _gateway_unicast(c, &res);
    }

    mqtt_packet_init(&pkt, G.broker.version, MQTT_UNSUBSCRIBE);
    pkt.v.unsubscribe.packet_id = req->v.unsubscribe.msg_id;
    mqtt_unsubscribe_generate(&pkt, 1);
    mqtt_str_set(&pkt.p.unsubscribe.topic_filters[0], &topic_name);

    return _broker_send(c->mc, &pkt);
}

static int
mqtt_sn_on_pingreq(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_packet_t pkt;

    if (!mqtt_str_empty(&req->v.pingreq.client_id) && c->state == MQTT_SN_STATE_ASLEEP)
        c->state = MQTT_SN_STATE_AWAKE;

    mqtt_packet_init(&pkt, G.broker.version, MQTT_PINGREQ);

    return _broker_send(c->mc, &pkt);
}

static int
mqtt_sn_on_disconnect(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    mqtt_sn_packet_t res;

    if (req->v.disconnect.duration > 0) {
        c->state = MQTT_SN_STATE_ASLEEP;
    } else {
        mqtt_packet_t pkt;

        c->state = MQTT_SN_STATE_DISCONNECTED;
        mqtt_packet_init(&pkt, G.broker.version, MQTT_DISCONNECT);

        _broker_send(c->mc, &pkt);
    }

    mqtt_sn_packet_init(&res, MQTT_SN_DISCONNECT);

    return _gateway_unicast(c, &res);
}

static int
_gateway_handle(mqtt_sn_client_t *c, mqtt_sn_packet_t *req) {
    int rc;

    LOG_I("gateway recv: %s", mqtt_sn_packet_type_name(req->type));
    switch (req->type) {
    case MQTT_SN_SEARCHGW:
        rc = mqtt_sn_on_searchgw(c, req);
        break;
    case MQTT_SN_CONNECT:
        rc = mqtt_sn_on_connect(c, req);
        break;
    case MQTT_SN_WILLTOPIC:
        rc = mqtt_sn_on_willtopic(c, req);
        break;
    case MQTT_SN_WILLMSG:
        rc = mqtt_sn_on_willmsg(c, req);
        break;
    case MQTT_SN_REGISTER:
        rc = mqtt_sn_on_register(c, req);
        break;
    case MQTT_SN_PUBLISH:
        rc = mqtt_sn_on_publish(c, req);
        break;
    case MQTT_SN_PUBACK:
        rc = mqtt_sn_on_puback(c, req);
        break;
    case MQTT_SN_PUBREC:
        rc = mqtt_sn_on_pubrec(c, req);
        break;
    case MQTT_SN_PUBREL:
        rc = mqtt_sn_on_pubrel(c, req);
        break;
    case MQTT_SN_PUBCOMP:
        rc = mqtt_sn_on_pubcomp(c, req);
        break;
    case MQTT_SN_SUBSCRIBE:
        rc = mqtt_sn_on_subscribe(c, req);
        break;
    case MQTT_SN_UNSUBSCRIBE:
        rc = mqtt_sn_on_unsubscribe(c, req);
        break;
    case MQTT_SN_PINGREQ:
        rc = mqtt_sn_on_pingreq(c, req);
        break;
    case MQTT_SN_WILLTOPICUPD:
        rc = mqtt_sn_on_willtopicupd(c, req);
        break;
    case MQTT_SN_WILLMSGUPD:
        rc = mqtt_sn_on_willmsgupd(c, req);
        break;
    case MQTT_SN_DISCONNECT:
        rc = mqtt_sn_on_disconnect(c, req);
        break;
    case MQTT_SN_ENCAPSULATED:
        rc = -1;
        break;
    default:
        rc = -1;
        break;
    }
    return rc;
}

static void
_gateway_on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    mqtt_sn_client_t *c;
    mqtt_sn_packet_t req;
    mqtt_str_t b;
    int rc;

    if (nread <= 0) {
        return;
    }

    LOG_D("");
    LOG_DUMP(buf->base, nread);

    c = mqtt_sn_client_fetch(addr);

    mqtt_str_init(&b, buf->base, nread);
    while ((rc = mqtt_sn_parse(&c->parser, &b, &req)) > 0) {
        c->t_last = G.t.now;
        rc = _gateway_handle(c, &req);
        mqtt_sn_packet_unit(&req);
        if (rc) {
            break;
        }
    }
}

static void
_gateway_on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    if (G.buff.s && G.buff.n != suggested_size) {
        mqtt_str_free(&G.buff);
    }
    if (!G.buff.s) {
        G.buff.s = malloc(suggested_size);
        G.buff.n = suggested_size;
    }
    buf->base = G.buff.s;
    buf->len = G.buff.n;
}

static int
_gateway_config(void *ud, const char *section, const char *key, const char *value) {
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
            G.host = strdup(value);
        } else if (!strcmp(key, "port")) {
            G.port = atoi(value);
        }
    }

    return 0;
}

static void *
_client_key(map_node_t *node) {
    mqtt_sn_client_t *c;

    c = map_data(node, mqtt_sn_client_t, node);
    return &c->addr;
}

static int
_client_cmp(void *a, void *b) {
    struct sockaddr_in *addr1 = (struct sockaddr_in *)a;
    struct sockaddr_in *addr2 = (struct sockaddr_in *)b;

    return addr1->sin_addr.s_addr - addr2->sin_addr.s_addr || addr1->sin_port - addr2->sin_port;
}

static int
_gateway_init(uv_loop_t *loop, int argc, char *argv[]) {
    G.loop = loop;
    G.gwid = 1;
    G.transmission = MQTT_SN_GATEWAY_TRANSPARENT;
    G.t.now = 0;
    G.host = "0.0.0.0";
    G.port = 1884;
    G.broadcast.host = "225.1.1.1";
    G.broadcast.port = 1884;
    G.t_adv = MQTT_SN_T_ADV;

    G.broker.host = "127.0.0.1";
    G.broker.port = "1883";
    G.broker.version = MQTT_VERSION_4;

    map_init(&G.client_m, _client_key, _client_cmp);

    if (argc > 1 && ini_parse(argv[1], _gateway_config, 0)) {
        LOG_E("config file %s parse error", argv[1]);
        return -1;
    }

    snowflake_init(&G.snowflake, 0, 0);
    return 0;
}

int
main(int argc, char *argv[]) {
    uv_loop_t *loop;
    uv_udp_t udp;
    uv_timer_t timer;
    struct sockaddr_in addr;
    int rc;

    signal(SIGPIPE, SIG_IGN);

    loop = uv_default_loop();

    if (_gateway_init(loop, argc, argv)) {
        LOG_E("gateway init failed");
        return EXIT_FAILURE;
    }

    rc = uv_ip4_addr(G.host, G.port, &addr);
    if (rc) {
        LOG_E("ip4_addr %s:%d : %s", G.host, G.port, uv_strerror(rc));
        return EXIT_FAILURE;
    }
    rc = uv_udp_init(G.loop, &udp);
    if (rc) {
        LOG_E("udp init : %s", G.host, G.port, uv_strerror(rc));
        return EXIT_FAILURE;
    }
    rc = uv_udp_bind(&udp, (const struct sockaddr *)&addr, 0);
    if (rc) {
        LOG_E("bind %s:%d : %s", G.host, G.port, uv_strerror(rc));
        return EXIT_FAILURE;
    }
    // rc = uv_udp_set_broadcast(&udp, 1);
    // if (rc) {
    //     LOG_E("set broadcast %s:%d : %s", G.host, G.port, uv_strerror(rc));
    //     return EXIT_FAILURE;
    // }
    rc = uv_udp_set_membership(&udp, G.broadcast.host, 0, UV_JOIN_GROUP);
    if (rc) {
        LOG_E("set membership %s : %s", G.broadcast.host, uv_strerror(rc));
        return EXIT_FAILURE;
    }
    rc = uv_udp_set_multicast_loop(&udp, 0);
    if (rc) {
        LOG_E("set multicast_loop: %s", uv_strerror(rc));
        return EXIT_FAILURE;
    }
    rc = uv_udp_recv_start(&udp, _gateway_on_alloc, _gateway_on_read);
    if (rc) {
        LOG_E("recv start %s", uv_strerror(rc));
        return EXIT_FAILURE;
    }
    G.udp = &udp;

    uv_timer_init(G.loop, &timer);
    uv_timer_start(&timer, _gateway_on_timer, 1000, 1000);

    LOG_I("mqtt-sn gateway at %s:%d started", G.host, G.port);

    return uv_run(loop, UV_RUN_DEFAULT);
}