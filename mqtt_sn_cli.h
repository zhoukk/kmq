/*
 * mqtt_sn_cli.h -- mqtt-sn client library.
 *
 * Copyright (c) zhoukk <izhoukk@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _MQTT_SN_CLI_H_
#define _MQTT_SN_CLI_H_

#define MQTT_SN_CLI_DEFAULT_KEEPALIVE 30
#define MQTT_SN_CLI_PACKET_TIMEOUT 5
#define MQTT_SN_CLI_PACKET_TTL 3

#include "mqtt.h"

typedef enum {
    MQTT_SN_STATE_DISCONNECTED,
    MQTT_SN_STATE_SEARCHGW,
    MQTT_SN_STATE_CONNECTING,
    MQTT_SN_STATE_ACTIVE,
    MQTT_SN_STATE_ASLEEP,
    MQTT_SN_STATE_AWAKE,
    MQTT_SN_STATE_LOST,
} mqtt_sn_cli_state_t;

typedef struct mqtt_sn_cli_s mqtt_sn_cli_t;

typedef void (*mqtt_sn_cli_callback_pt)(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt);

typedef struct {
    const char *client_id;
    uint16_t duration;
    uint8_t clean_session;

    struct {
        uint8_t retain;
        const char *topic;
        mqtt_sn_qos_t qos;
        mqtt_str_t message;
    } lwt;

    struct {
        mqtt_sn_cli_callback_pt advertise;
        mqtt_sn_cli_callback_pt searchgw;
        mqtt_sn_cli_callback_pt gwinfo;
        mqtt_sn_cli_callback_pt connack;
        mqtt_sn_cli_callback_pt regist;
        mqtt_sn_cli_callback_pt regack;
        mqtt_sn_cli_callback_pt suback;
        mqtt_sn_cli_callback_pt unsuback;
        mqtt_sn_cli_callback_pt puback;
        mqtt_sn_cli_callback_pt publish;
        mqtt_sn_cli_callback_pt pingresp;
        mqtt_sn_cli_callback_pt disconnect;
    } cb;
    void *ud;
} mqtt_sn_cli_conf_t;

mqtt_sn_cli_t *mqtt_sn_cli_create(mqtt_sn_cli_conf_t *config);
void mqtt_sn_cli_destroy(mqtt_sn_cli_t *m);

mqtt_sn_cli_state_t mqtt_sn_cli_state(mqtt_sn_cli_t *m);

void mqtt_sn_cli_searchgw(mqtt_sn_cli_t *m, uint8_t radius);
void mqtt_sn_cli_connect(mqtt_sn_cli_t *m);
void mqtt_sn_cli_register(mqtt_sn_cli_t *m, const char *topic, uint16_t *packet_id);

void mqtt_sn_cli_publish(mqtt_sn_cli_t *m, int retain, mqtt_sn_topic_t *topic, mqtt_sn_qos_t qos, mqtt_str_t *message,
                         uint16_t *packet_id);
void mqtt_sn_cli_subscribe(mqtt_sn_cli_t *m, mqtt_sn_topic_t *topic, mqtt_sn_qos_t qos, uint16_t *packet_id);
void mqtt_sn_cli_unsubscribe(mqtt_sn_cli_t *m, mqtt_sn_topic_t *topic, uint16_t *packet_id);
void mqtt_sn_cli_pingreq(mqtt_sn_cli_t *m);
void mqtt_sn_cli_disconnect(mqtt_sn_cli_t *m, uint16_t duration);

int mqtt_sn_cli_outgoing(mqtt_sn_cli_t *m, mqtt_str_t *outgoing);
int mqtt_sn_cli_incoming(mqtt_sn_cli_t *m, mqtt_str_t *incoming);
int mqtt_sn_cli_elapsed(mqtt_sn_cli_t *m, uint64_t time);

#endif /* _MQTT_SN_CLI_H_ */

#ifdef MQTT_SN_CLI_IMPL

#define MQTT_IMPL
#include "mqtt.h"

typedef struct mqtt_sn_cli_packet_s {
    uint64_t t_send;
    int ttl;
    int wait_ack;
    mqtt_str_t b;
    mqtt_sn_packet_type_t type;
    uint16_t packet_id;
    struct mqtt_sn_cli_packet_s *next;
} mqtt_sn_cli_packet_t;

typedef struct mqtt_sn_cli_topic_s {
    char *topic;
    uint16_t id;
    uint16_t packet_id;
    struct mqtt_sn_cli_topic_s *next;
} mqtt_sn_cli_topic_t;

struct mqtt_sn_cli_s {
    mqtt_str_t client_id;
    uint16_t duration;
    uint8_t clean_session;

    struct {
        int retain;
        mqtt_str_t topic;
        mqtt_sn_qos_t qos;
        mqtt_str_t message;
    } lwt;

    struct {
        uint64_t now;
        uint64_t ping;
        uint64_t send;
        uint64_t asleep;
    } t;

    uint16_t packet_id;
    mqtt_sn_parser_t parser;
    mqtt_sn_cli_packet_t *padding;
    mqtt_sn_cli_topic_t *topics;
    mqtt_sn_cli_state_t state;
    uint16_t asleep_duration;

    struct {
        mqtt_sn_cli_callback_pt advertise;
        mqtt_sn_cli_callback_pt searchgw;
        mqtt_sn_cli_callback_pt gwinfo;
        mqtt_sn_cli_callback_pt connack;
        mqtt_sn_cli_callback_pt regist;
        mqtt_sn_cli_callback_pt regack;
        mqtt_sn_cli_callback_pt suback;
        mqtt_sn_cli_callback_pt unsuback;
        mqtt_sn_cli_callback_pt puback;
        mqtt_sn_cli_callback_pt publish;
        mqtt_sn_cli_callback_pt pingresp;
        mqtt_sn_cli_callback_pt disconnect;
    } cb;

    void *ud;
};

static uint16_t
_generate_packet_id(mqtt_sn_cli_t *m) {
    uint16_t id;

    id = ++m->packet_id;
    if (id == 0)
        id = ++m->packet_id;
    return id;
}

static void
_clear_padding(mqtt_sn_cli_t *m) {
    mqtt_sn_cli_packet_t *mp;

    mp = m->padding;
    while (mp) {
        mqtt_sn_cli_packet_t *next;

        next = mp->next;
        mqtt_str_free(&mp->b);
        MQTT_FREE(mp);
        mp = next;
    }
}

static int
_check_padding(mqtt_sn_cli_t *m) {
    mqtt_sn_cli_packet_t *mp;
    int rc;

    rc = 0;
    mp = m->padding;
    while (mp) {
        if (m->t.now - mp->t_send >= MQTT_SN_CLI_PACKET_TIMEOUT * 1000) {
            if (mp->ttl) {
                --mp->ttl;
                mp->wait_ack = 0;
            } else {
                rc = -1;
                break;
            }
        }
        mp = mp->next;
    }
    return rc;
}

static void
_check_keepalive(mqtt_sn_cli_t *m) {
    if (m->state == MQTT_SN_STATE_ACTIVE) {
        if (m->duration > 0) {
            if (m->t.ping > 0 && (m->t.now - m->t.ping) > (uint64_t)m->duration * 1000) {
                m->t.ping = 0;
                m->state = MQTT_SN_STATE_LOST;
            } else if (m->t.ping == 0 && (m->t.now - m->t.send) >= (uint64_t)m->duration * 1000) {
                mqtt_sn_cli_pingreq(m);
            }
        }
    }

    if (m->state == MQTT_SN_STATE_ASLEEP && (m->t.now - m->t.asleep) >= (uint64_t)m->asleep_duration * 1000) {
        mqtt_sn_cli_pingreq(m);
    }
}

static int
_erase_padding(mqtt_sn_cli_t *m, mqtt_sn_packet_type_t type, uint16_t packet_id) {
    mqtt_sn_cli_packet_t *mp, **pmp;

    pmp = &m->padding;
    while (*pmp) {
        mp = *pmp;
        if (mp->type == type && mp->packet_id == packet_id) {
            *pmp = mp->next;
            mqtt_str_free(&mp->b);
            MQTT_FREE(mp);
            return 0;
        }
        pmp = &mp->next;
    }
    return -1;
}

static void
_append_padding(mqtt_sn_cli_t *m, mqtt_sn_packet_t *pkt) {
    mqtt_str_t b = MQTT_STR_INITIALIZER;
    mqtt_sn_cli_packet_t *mp;

    mqtt_sn_serialize(pkt, &b);

    mp = (mqtt_sn_cli_packet_t *)MQTT_MALLOC(sizeof *mp);
    memset(mp, 0, sizeof *mp);
    mp->type = pkt->type;
    mqtt_str_set(&mp->b, &b);
    mp->t_send = m->t.now;
    mp->ttl = MQTT_SN_CLI_PACKET_TTL;
    switch (pkt->type) {
    case MQTT_SN_REGISTER:
        mp->packet_id = pkt->v.regist.msg_id;
        break;
    case MQTT_SN_SUBSCRIBE:
        mp->packet_id = pkt->v.subscribe.msg_id;
        break;
    case MQTT_SN_UNSUBSCRIBE:
        mp->packet_id = pkt->v.unsubscribe.msg_id;
        break;
    case MQTT_SN_PUBLISH:
        mp->packet_id = pkt->v.publish.msg_id;
        break;
    case MQTT_SN_PUBREC:
        mp->packet_id = pkt->v.pubrec.msg_id;
        break;
    case MQTT_SN_PUBREL:
        mp->packet_id = pkt->v.pubrel.msg_id;
        break;
    default:
        break;
    }

    if (!m->padding)
        m->padding = mp;
    else {
        mqtt_sn_cli_packet_t *p;

        p = m->padding;
        while (p->next) {
            p = p->next;
        }
        p->next = mp;
    }
    mqtt_sn_packet_unit(pkt);
}

static void
_send_puback(mqtt_sn_cli_t *m, mqtt_sn_packet_type_t type, uint16_t packet_id) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, type);
    switch (type) {
    case MQTT_SN_PUBACK:
        pkt.v.puback.msg_id = packet_id;
        break;
    case MQTT_SN_PUBREC:
        pkt.v.pubrec.msg_id = packet_id;
        break;
    case MQTT_SN_PUBREL:
        pkt.v.pubrel.msg_id = packet_id;
        break;
    case MQTT_SN_PUBCOMP:
        pkt.v.pubcomp.msg_id = packet_id;
        break;
    default:
        break;
    }

    _append_padding(m, &pkt);
}

static void
_regist_topic_id(mqtt_sn_cli_t *m, const char *topic, uint16_t id, uint16_t packet_id) {
    mqtt_sn_cli_topic_t *t;

    t = (mqtt_sn_cli_topic_t *)MQTT_MALLOC(sizeof *t);
    t->topic = MQTT_MALLOC(strlen(topic));
    memcpy(t->topic, topic, strlen(topic));
    t->packet_id = packet_id;
    t->next = 0;
    t->id = id;

    if (!m->topics)
        m->topics = t;
    else {
        mqtt_sn_cli_topic_t *p;

        p = m->topics;
        while (p->next) {
            p = p->next;
        }
        p->next = t;
    }
}

static uint16_t
_query_topic_id(mqtt_sn_cli_t *m, const char *topic) {
    mqtt_sn_cli_topic_t *t;

    t = m->topics;
    while (t) {
        if (!strcmp(t->topic, topic)) {
            return t->id;
        }
        t = t->next;
    }
    return 0;
}

static void
_update_topic_id(mqtt_sn_cli_t *m, uint16_t id, uint16_t packet_id) {
    mqtt_sn_cli_topic_t *t;

    t = m->topics;
    while (t) {
        if (t->packet_id == packet_id) {
            t->id = id;
            break;
        }
        t = t->next;
    }
}

static void
_send_willtopic(mqtt_sn_cli_t *m) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_WILLTOPIC);
    pkt.v.willtopic.flags.bits.qos = m->lwt.qos;
    pkt.v.willtopic.flags.bits.retain = m->lwt.retain;
    mqtt_str_set(&pkt.v.willtopic.topic_name, &m->lwt.topic);

    _append_padding(m, &pkt);
}

static void
_send_willmsg(mqtt_sn_cli_t *m) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_WILLMSG);
    mqtt_str_set(&pkt.v.willmsg.message, &m->lwt.message);

    _append_padding(m, &pkt);
}

static int
_handle_packet(mqtt_sn_cli_t *m, mqtt_sn_packet_t *pkt) {
    int rc;

    rc = 0;
    printf("recv: %s\n", mqtt_sn_packet_type_name(pkt->type));
    switch (pkt->type) {
    case MQTT_SN_ADVERTISE:
        if (m->cb.advertise) {
            m->cb.advertise(m, m->ud, pkt);
        }
        break;
    case MQTT_SN_SEARCHGW:
        if (m->cb.searchgw) {
            m->cb.searchgw(m, m->ud, pkt);
        }
        break;
    case MQTT_SN_GWINFO:
        _erase_padding(m, MQTT_SN_SEARCHGW, 0);
        if (m->cb.gwinfo) {
            m->cb.gwinfo(m, m->ud, pkt);
        }
        break;
    case MQTT_SN_CONNACK:
        if (mqtt_str_empty(&m->lwt.topic))
            rc = _erase_padding(m, MQTT_SN_CONNECT, 0);
        else
            rc = _erase_padding(m, MQTT_SN_WILLMSG, 0);
        m->state = MQTT_SN_STATE_ACTIVE;
        if (!rc) {
            if (m->cb.connack) {
                m->cb.connack(m, m->ud, pkt);
            }
        }
        break;
    case MQTT_SN_WILLTOPICREQ:
        if (!_erase_padding(m, MQTT_SN_CONNECT, 0))
            _send_willtopic(m);
        else
            rc = -1;
        break;
    case MQTT_SN_WILLMSGREQ:
        if (!_erase_padding(m, MQTT_SN_WILLTOPIC, 0))
            _send_willmsg(m);
        else
            rc = -1;
        break;
    case MQTT_SN_REGISTER:
        do {
            char topic[pkt->v.regist.topic_name.n + 1];
            strncpy(topic, pkt->v.regist.topic_name.s, pkt->v.regist.topic_name.n);
            _regist_topic_id(m, topic, pkt->v.regist.topic_id, pkt->v.regist.msg_id);
        } while (0);
        if (m->cb.regist) {
            m->cb.regist(m, m->ud, pkt);
        }
        break;
    case MQTT_SN_REGACK:
        if (!_erase_padding(m, MQTT_SN_REGISTER, pkt->v.regack.msg_id)) {
            if (pkt->v.regack.return_code == MQTT_SN_RC_ACCEPTED) {
                _update_topic_id(m, pkt->v.regack.topic_id, pkt->v.regack.msg_id);
            }
            if (m->cb.regack) {
                m->cb.regack(m, m->ud, pkt);
            }
        } else
            rc = -1;
        break;
    case MQTT_SN_PUBLISH:
        if (m->cb.publish) {
            m->cb.publish(m, m->ud, pkt);
        }
        switch (pkt->v.publish.flags.bits.qos) {
        case MQTT_SN_QOS_1:
            _send_puback(m, MQTT_SN_PUBACK, pkt->v.publish.msg_id);
            break;
        case MQTT_SN_QOS_2:
            _send_puback(m, MQTT_SN_PUBREC, pkt->v.publish.msg_id);
            break;
        default:
            break;
        }
        break;
    case MQTT_SN_PUBACK:
        if (!_erase_padding(m, MQTT_SN_PUBLISH, pkt->v.puback.msg_id)) {
            if (m->cb.puback) {
                m->cb.puback(m, m->ud, pkt);
            }
        } else {
            rc = -1;
        }
        break;
    case MQTT_SN_PUBREC:
        if (!_erase_padding(m, MQTT_SN_PUBLISH, pkt->v.pubrec.msg_id)) {
            _send_puback(m, MQTT_SN_PUBREL, pkt->v.pubrec.msg_id);
        } else {
            rc = -1;
        }
        break;
    case MQTT_SN_PUBREL:
        if (!_erase_padding(m, MQTT_SN_PUBREC, pkt->v.pubrel.msg_id)) {
            _send_puback(m, MQTT_SN_PUBCOMP, pkt->v.pubrel.msg_id);
        } else {
            rc = -1;
        }
        break;
    case MQTT_SN_PUBCOMP:
        if (!_erase_padding(m, MQTT_SN_PUBREL, pkt->v.pubcomp.msg_id)) {
            if (m->cb.puback) {
                m->cb.puback(m, m->ud, pkt);
            }
        } else {
            rc = -1;
        }
        break;
    case MQTT_SN_SUBACK:
        if (!_erase_padding(m, MQTT_SN_SUBSCRIBE, pkt->v.suback.msg_id)) {
            if (m->cb.suback) {
                m->cb.suback(m, m->ud, pkt);
            }
        } else {
            rc = -1;
        }
        break;
    case MQTT_SN_UNSUBACK:
        if (!_erase_padding(m, MQTT_SN_UNSUBSCRIBE, pkt->v.unsuback.msg_id)) {
            if (m->cb.unsuback) {
                m->cb.unsuback(m, m->ud, pkt);
            }
        } else {
            rc = -1;
        }
        break;
    case MQTT_SN_PINGRESP:
        m->t.ping = 0;
        if (m->state == MQTT_SN_STATE_AWAKE)
            m->state = MQTT_SN_STATE_ASLEEP;
        if (m->cb.pingresp) {
            m->cb.pingresp(m, m->ud, pkt);
        }
        break;
    case MQTT_SN_DISCONNECT:
        _erase_padding(m, MQTT_SN_DISCONNECT, 0);
        if (m->asleep_duration > 0) {
            m->t.asleep = m->t.now;
            m->state = MQTT_SN_STATE_ASLEEP;
        } else {
            m->state = MQTT_SN_STATE_DISCONNECTED;
        }
        if (m->cb.disconnect) {
            m->cb.disconnect(m, m->ud, pkt);
        }
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

mqtt_sn_cli_t *
mqtt_sn_cli_create(mqtt_sn_cli_conf_t *config) {
    mqtt_sn_cli_t *m;

    m = (mqtt_sn_cli_t *)MQTT_MALLOC(sizeof *m);
    memset(m, 0, sizeof *m);

    mqtt_str_dup(&m->client_id, config->client_id);
    m->clean_session = config->clean_session;
    m->duration = config->duration;

    if (config->lwt.topic) {
        m->lwt.retain = config->lwt.retain;
        m->lwt.qos = config->lwt.qos;
        mqtt_str_dup(&m->lwt.topic, config->lwt.topic);
        mqtt_str_copy(&m->lwt.message, &config->lwt.message);
    }

    m->cb.advertise = config->cb.advertise;
    m->cb.searchgw = config->cb.searchgw;
    m->cb.gwinfo = config->cb.gwinfo;
    m->cb.connack = config->cb.connack;
    m->cb.regist = config->cb.regist;
    m->cb.regack = config->cb.regack;
    m->cb.suback = config->cb.suback;
    m->cb.unsuback = config->cb.unsuback;
    m->cb.puback = config->cb.puback;
    m->cb.publish = config->cb.publish;
    m->cb.pingresp = config->cb.pingresp;
    m->cb.disconnect = config->cb.disconnect;

    m->ud = config->ud;

    mqtt_sn_parser_init(&m->parser);

    m->state = MQTT_SN_STATE_DISCONNECTED;

    return m;
}

void
mqtt_sn_cli_destroy(mqtt_sn_cli_t *m) {
    _clear_padding(m);
    mqtt_str_free(&m->client_id);
    mqtt_str_free(&m->lwt.topic);
    mqtt_str_free(&m->lwt.message);
    MQTT_FREE(m);
}

mqtt_sn_cli_state_t
mqtt_sn_cli_state(mqtt_sn_cli_t *m) {
    return m->state;
}

void
mqtt_sn_cli_searchgw(mqtt_sn_cli_t *m, uint8_t radius) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_SEARCHGW);
    pkt.v.searchgw.radius = radius;

    m->state = MQTT_SN_STATE_SEARCHGW;

    _append_padding(m, &pkt);
}

void
mqtt_sn_cli_connect(mqtt_sn_cli_t *m) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_CONNECT);
    mqtt_str_set(&pkt.v.connect.client_id, &m->client_id);
    pkt.v.connect.duration = m->duration;
    pkt.v.connect.flags.bits.clean_session = m->clean_session;
    if (!mqtt_str_empty(&m->lwt.topic))
        pkt.v.connect.flags.bits.will = 1;

    m->state = MQTT_SN_STATE_CONNECTING;

    _append_padding(m, &pkt);
}

void
mqtt_sn_cli_register(mqtt_sn_cli_t *m, const char *topic, uint16_t *packet_id) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_REGISTER);
    pkt.v.regist.msg_id = _generate_packet_id(m);
    mqtt_str_from(&pkt.v.regist.topic_name, topic);

    if (packet_id)
        *packet_id = pkt.v.regist.msg_id;

    _regist_topic_id(m, topic, 0, pkt.v.regist.msg_id);

    _append_padding(m, &pkt);
}

void
mqtt_sn_cli_publish(mqtt_sn_cli_t *m, int retain, mqtt_sn_topic_t *topic, mqtt_sn_qos_t qos, mqtt_str_t *message,
                    uint16_t *packet_id) {
    mqtt_sn_packet_t pkt;

    if (topic->type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        topic->id = _query_topic_id(m, topic->name.s);
        topic->type = MQTT_SN_TOPIC_ID_TYPE_PREDEFINED;
    }

    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBLISH);
    pkt.v.publish.flags.bits.retain = retain;
    pkt.v.publish.flags.bits.qos = qos;
    pkt.v.publish.flags.bits.topic_id_type = topic->type;
    mqtt_sn_topic_set(&pkt.v.publish.topic, topic);
    mqtt_str_set(&pkt.v.publish.data, message);

    if (qos == MQTT_SN_QOS_1 || qos == MQTT_SN_QOS_2)
        pkt.v.publish.msg_id = _generate_packet_id(m);

    if (packet_id)
        *packet_id = pkt.v.publish.msg_id;

    _append_padding(m, &pkt);
}

void
mqtt_sn_cli_subscribe(mqtt_sn_cli_t *m, mqtt_sn_topic_t *topic, mqtt_sn_qos_t qos, uint16_t *packet_id) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_SUBSCRIBE);
    pkt.v.subscribe.flags.bits.qos = qos;
    pkt.v.subscribe.flags.bits.topic_id_type = topic->type;
    pkt.v.subscribe.msg_id = _generate_packet_id(m);
    mqtt_sn_topic_set(&pkt.v.subscribe.topic, topic);

    if (packet_id)
        *packet_id = pkt.v.subscribe.msg_id;

    _append_padding(m, &pkt);
}

void
mqtt_sn_cli_unsubscribe(mqtt_sn_cli_t *m, mqtt_sn_topic_t *topic, uint16_t *packet_id) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_UNSUBSCRIBE);
    pkt.v.unsubscribe.flags.bits.topic_id_type = topic->type;
    pkt.v.unsubscribe.msg_id = _generate_packet_id(m);
    mqtt_sn_topic_set(&pkt.v.unsubscribe.topic, topic);

    if (packet_id)
        *packet_id = pkt.v.unsubscribe.msg_id;

    _append_padding(m, &pkt);
}

void
mqtt_sn_cli_pingreq(mqtt_sn_cli_t *m) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_PINGREQ);
    if (m->state == MQTT_SN_STATE_ASLEEP) {
        mqtt_str_set(&pkt.v.pingreq.client_id, &m->client_id);
        m->state = MQTT_SN_STATE_AWAKE;
    }
    m->t.ping = m->t.now;

    _append_padding(m, &pkt);
}

void
mqtt_sn_cli_disconnect(mqtt_sn_cli_t *m, uint16_t duration) {
    mqtt_sn_packet_t pkt;

    mqtt_sn_packet_init(&pkt, MQTT_SN_DISCONNECT);

    m->asleep_duration = duration;

    _append_padding(m, &pkt);
}

int
mqtt_sn_cli_outgoing(mqtt_sn_cli_t *m, mqtt_str_t *outgoing) {
    mqtt_sn_cli_packet_t *mp;

    mqtt_str_init(outgoing, 0, 0);
    mp = m->padding;
    while (mp) {
        if (mp->wait_ack == 0) {
            outgoing->n += mp->b.n;
        }
        mp = mp->next;
    }

    if (outgoing->n > 0) {
        mqtt_sn_cli_packet_t **pmp;
        outgoing->s = MQTT_MALLOC(outgoing->n);
        outgoing->n = 0;

        pmp = &m->padding;
        while (*pmp) {
            mp = *pmp;
            if (mp->wait_ack == 0) {
                mqtt_str_concat(outgoing, &mp->b);
                mp->wait_ack = 1;
                mp->t_send = m->t.now;
            }
            if (mp->type == MQTT_SN_PINGREQ || mp->type == MQTT_SN_PUBACK || mp->type == MQTT_SN_PUBCOMP ||
                (mp->type == MQTT_SN_PUBLISH && mp->packet_id == 0)) {
                *pmp = mp->next;
            } else {
                pmp = &mp->next;
            }
        }
        m->t.send = m->t.now;
    }

    return 0;
}

int
mqtt_sn_cli_incoming(mqtt_sn_cli_t *m, mqtt_str_t *incoming) {
    mqtt_sn_packet_t pkt;
    int rc;

    while ((rc = mqtt_sn_parse(&m->parser, incoming, &pkt)) > 0) {
        rc = _handle_packet(m, &pkt);
        mqtt_sn_packet_unit(&pkt);
        if (rc)
            break;
    }

    return rc;
}

int
mqtt_sn_cli_elapsed(mqtt_sn_cli_t *m, uint64_t time) {
    int rc;

    m->t.now += time;
    _check_keepalive(m);
    rc = _check_padding(m);
    return rc;
}

#endif /* MQTT_SN_CLI_IMPL */

#ifdef MQTT_SN_CLI_LINUX_PLATFORM

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define LINUX_UDP_BUFF_SIZE 1024

typedef struct {
    int fd;
    struct sockaddr to_addr;
    struct sockaddr from_addr;

    char buff[LINUX_UDP_BUFF_SIZE];
} linux_udp_network_t;

void *
linux_udp_open(const char *host, int port) {
    linux_udp_network_t *net;
    struct sockaddr_in addr;
    struct timeval timeout = {1, 0};
    int fd;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "socket e: %s\n", strerror(errno));
        return 0;
    }

    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        fprintf(stderr, "bind e: %s\n", strerror(errno));
        close(fd);
        return 0;
    }

    net = (linux_udp_network_t *)MQTT_MALLOC(sizeof *net);
    memset(net, 0, sizeof *net);

    net->fd = fd;

    return net;
}

int
linux_udp_set_broadcast(void *net, int port) {
    linux_udp_network_t *udp;
    struct sockaddr_in addr;
    int on;

    udp = (linux_udp_network_t *)net;

    on = 1;
    if (setsockopt(udp->fd, SOL_SOCKET, SO_BROADCAST, (char *)&on, sizeof(on)) == -1) {
        fprintf(stderr, "setsockopt SO_BROADCAST fd: %d, e: %s\n", udp->fd, strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    addr.sin_port = htons(port);
    memcpy(&udp->to_addr, &addr, sizeof(addr));

    return 0;
}

int
linux_udp_join_multicast(void *net, const char *host, int port) {
    linux_udp_network_t *udp;
    struct sockaddr_in addr;
    struct ip_mreq mreq;
    int on;

    udp = (linux_udp_network_t *)net;

    on = 0;
    if (setsockopt(udp->fd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&on, sizeof(on)) == -1) {
        fprintf(stderr, "setsockopt IP_MULTICAST_LOOP fd: %d, e: %s\n", udp->fd, strerror(errno));
        return -1;
    }

    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    mreq.imr_multiaddr.s_addr = inet_addr(host);
    if (setsockopt(udp->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
        fprintf(stderr, "setsockopt IP_ADD_MEMBERSHIP fd: %d, e: %s\n", udp->fd, strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);
    memcpy(&udp->to_addr, &addr, sizeof(addr));

    return 0;
}

void
linux_udp_set_unicast(void *net, struct sockaddr *addr) {
    linux_udp_network_t *udp;

    udp = (linux_udp_network_t *)net;
    memcpy(&udp->to_addr, addr, sizeof(struct sockaddr));
}

struct sockaddr *
linux_udp_from_address(void *net) {
    return &((linux_udp_network_t *)net)->from_addr;
}

ssize_t
linux_udp_send(void *net, const void *data, size_t size) {
    linux_udp_network_t *udp;
    struct sockaddr *addr;

    udp = (linux_udp_network_t *)net;
    addr = &udp->to_addr;

    return sendto(udp->fd, data, size, 0, addr, sizeof(struct sockaddr));
}

ssize_t
linux_udp_recv(void *net, void *data, size_t size) {
    linux_udp_network_t *udp;
    struct sockaddr *addr;
    socklen_t addrlen = sizeof(struct sockaddr);
    ssize_t nrecv;

    udp = (linux_udp_network_t *)net;
    addr = &udp->from_addr;

    nrecv = recvfrom(udp->fd, data, size, 0, addr, &addrlen);
    if (nrecv == -1 && errno == EAGAIN)
        nrecv = 0;
    return nrecv;
}

void
linux_udp_close(void *net) {
    int fd;

    fd = ((linux_udp_network_t *)net)->fd;

    close(fd);
    MQTT_FREE(net);
}

int
linux_udp_transfer(void *net, mqtt_str_t *outgoing, mqtt_str_t *incoming) {
    linux_udp_network_t *udp;
    char *buff;
    ssize_t nrecv;

    udp = (linux_udp_network_t *)net;

    if (!mqtt_str_empty(outgoing)) {
        ssize_t nsend;

        nsend = linux_udp_send(net, outgoing->s, outgoing->n);
        mqtt_str_free(outgoing);
        if (nsend < 0) {
            return -1;
        }
    }

    buff = udp->buff;
    nrecv = linux_udp_recv(net, buff, LINUX_UDP_BUFF_SIZE);
    if (nrecv < 0) {
        return -1;
    }
    mqtt_str_init(incoming, buff, nrecv);
    return 0;
}

uint64_t
linux_time_now() {
    struct timeval tv;

    gettimeofday(&tv, 0);
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

#endif /* MQTT_SN_CLI_LINUX_PLATFORM */