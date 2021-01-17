/*
 * mqtt_cli.h -- mqtt client library.
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

#ifndef _MQTT_CLI_H_
#define _MQTT_CLI_H_

#define MQTT_CLI_DEFAULT_KEEPALIVE 30
#define MQTT_CLI_PACKET_TIMEOUT 5
#define MQTT_CLI_PACKET_TTL 3

#include "mqtt.h"

typedef struct mqtt_cli_s mqtt_cli_t;

typedef void (*mqtt_cli_callback_pt)(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt);

typedef struct {
    const char *client_id;
    mqtt_version_t version;
    uint16_t keep_alive;
    uint8_t clean_session;

    struct {
        const char *username;
        const char *password;
    } auth;

    struct {
        uint8_t retain;
        const char *topic;
        mqtt_qos_t qos;
        mqtt_str_t message;
    } lwt;

    struct {
        mqtt_cli_callback_pt connack;
        mqtt_cli_callback_pt suback;
        mqtt_cli_callback_pt unsuback;
        mqtt_cli_callback_pt puback;
        mqtt_cli_callback_pt publish;
        mqtt_cli_callback_pt pingresp;
    } cb;

    void *ud;
} mqtt_cli_conf_t;

mqtt_cli_t *mqtt_cli_create(mqtt_cli_conf_t *config);
void mqtt_cli_destroy(mqtt_cli_t *m);

int mqtt_cli_connect(mqtt_cli_t *m);
int mqtt_cli_publish(mqtt_cli_t *m, int retain, const char *topic, mqtt_qos_t qos, mqtt_str_t *message,
                     uint16_t *packet_id);
int mqtt_cli_subscribe(mqtt_cli_t *m, int count, const char *topic[], mqtt_qos_t qos[], uint16_t *packet_id);
int mqtt_cli_unsubscribe(mqtt_cli_t *m, int count, const char *topic[], uint16_t *packet_id);
int mqtt_cli_pingreq(mqtt_cli_t *m);
int mqtt_cli_disconnect(mqtt_cli_t *m);

int mqtt_cli_outgoing(mqtt_cli_t *m, mqtt_str_t *outgoing);
int mqtt_cli_incoming(mqtt_cli_t *m, mqtt_str_t *incoming);
int mqtt_cli_elapsed(mqtt_cli_t *m, uint64_t time);

#endif /* _MQTT_CLI_H_ */

#ifdef MQTT_CLI_IMPL

#define MQTT_IMPL
#include "mqtt.h"

typedef struct mqtt_cli_packet_s {
    uint64_t t_send;
    int ttl;
    int wait_ack;
    mqtt_str_t b;
    mqtt_packet_type_t type;
    uint16_t packet_id;
    struct mqtt_cli_packet_s *next;
} mqtt_cli_packet_t;

struct mqtt_cli_s {
    mqtt_str_t client_id;
    mqtt_version_t version;
    uint8_t clean_session;
    uint16_t keep_alive;

    struct {
        mqtt_str_t username;
        mqtt_str_t password;
    } auth;

    struct {
        int retain;
        mqtt_str_t topic;
        mqtt_qos_t qos;
        mqtt_str_t message;
    } lwt;

    struct {
        uint64_t now;
        uint64_t ping;
        uint64_t send;
    } t;

    uint16_t packet_id;
    mqtt_parser_t parser;
    mqtt_cli_packet_t *padding;

    struct {
        mqtt_cli_callback_pt connack;
        mqtt_cli_callback_pt suback;
        mqtt_cli_callback_pt unsuback;
        mqtt_cli_callback_pt puback;
        mqtt_cli_callback_pt publish;
        mqtt_cli_callback_pt pingresp;
    } cb;

    void *ud;
};

static uint16_t
_generate_packet_id(mqtt_cli_t *m) {
    uint16_t id;

    id = ++m->packet_id;
    if (id == 0)
        id = ++m->packet_id;
    return id;
}

static void
_clear_padding(mqtt_cli_t *m) {
    mqtt_cli_packet_t *mp;

    mp = m->padding;
    while (mp) {
        mqtt_cli_packet_t *next;

        next = mp->next;
        mqtt_str_free(&mp->b);
        free(mp);
        mp = next;
    }
}

static int
_check_padding(mqtt_cli_t *m) {
    mqtt_cli_packet_t *mp;
    int rc;

    rc = 0;
    mp = m->padding;
    while (mp) {
        if (m->t.now - mp->t_send >= MQTT_CLI_PACKET_TIMEOUT * 1000) {
            if (mp->ttl) {
                --mp->ttl;
                mp->wait_ack = 0;
                if (mp->type == MQTT_PUBLISH) {
                    ((mqtt_fixed_header_t *)mp->b.s)->bits.dup = 1;
                }
            } else {
                rc = -1;
                break;
            }
        }
        mp = mp->next;
    }
    return rc;
}

static int
_check_keepalive(mqtt_cli_t *m) {
    if (m->keep_alive > 0) {
        if (m->t.ping > 0 && (m->t.now - m->t.ping) > (uint64_t)m->keep_alive * 1000) {
            m->t.ping = 0;
            return -1;
        }
        if (m->t.ping == 0 && (m->t.now - m->t.send) >= (uint64_t)m->keep_alive * 1000) {
            return mqtt_cli_pingreq(m);
        }
    }
    return 0;
}

static int
_erase_padding(mqtt_cli_t *m, mqtt_packet_type_t type, uint16_t packet_id) {
    mqtt_cli_packet_t *mp, **pmp;

    pmp = &m->padding;
    while (*pmp) {
        mp = *pmp;
        if (mp->type == type && mp->packet_id == packet_id) {
            *pmp = mp->next;
            mqtt_str_free(&mp->b);
            free(mp);
            return 0;
        }
        pmp = &mp->next;
    }
    return -1;
}

static int
_append_padding(mqtt_cli_t *m, mqtt_packet_t *pkt) {
    mqtt_str_t b = MQTT_STR_INITIALIZER;
    int rc;

    rc = mqtt_serialize(pkt, &b);
    if (!rc) {
        mqtt_cli_packet_t *mp;

        mp = (mqtt_cli_packet_t *)malloc(sizeof *mp);
        memset(mp, 0, sizeof *mp);
        mp->type = pkt->f.bits.type;
        mqtt_str_set(&mp->b, &b);
        mp->t_send = m->t.now;
        switch (pkt->f.bits.type) {
        case MQTT_PUBLISH:
            mp->packet_id = pkt->v.publish.packet_id;
            mp->ttl = MQTT_CLI_PACKET_TTL;
            break;
        case MQTT_PUBREL:
            mp->packet_id = pkt->v.pubrel.packet_id;
            mp->ttl = MQTT_CLI_PACKET_TTL;
            break;
        default:
            break;
        }

        if (!m->padding)
            m->padding = mp;
        else {
            mqtt_cli_packet_t *p;

            p = m->padding;
            while (p->next) {
                p = p->next;
            }
            p->next = mp;
        }
    } else {
        mqtt_str_free(&b);
    }
    mqtt_packet_unit(pkt);

    return rc;
}

static int
_send_puback(mqtt_cli_t *m, mqtt_packet_type_t type, uint16_t packet_id) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, m->version, type);
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
        break;
    }

    return _append_padding(m, &pkt);
}

static int
_handle_packet(mqtt_cli_t *m, mqtt_packet_t *pkt) {
    int rc;

    rc = 0;
    switch (pkt->f.bits.type) {
    case MQTT_CONNACK:
        if (m->cb.connack) {
            m->cb.connack(m, m->ud, pkt);
        }
        break;
    case MQTT_PUBLISH:
        if (m->cb.publish) {
            m->cb.publish(m, m->ud, pkt);
        }
        switch (pkt->f.bits.qos) {
        case MQTT_QOS_1:
            rc = _send_puback(m, MQTT_PUBACK, pkt->v.publish.packet_id);
            break;
        case MQTT_QOS_2:
            rc = _send_puback(m, MQTT_PUBREC, pkt->v.publish.packet_id);
            break;
        default:
            break;
        }
        break;
    case MQTT_PUBACK:
        if (!_erase_padding(m, MQTT_PUBLISH, pkt->v.puback.packet_id)) {
            if (m->cb.puback) {
                m->cb.puback(m, m->ud, pkt);
            }
        } else {
            rc = -1;
        }
        break;
    case MQTT_PUBREC:
        if (!_erase_padding(m, MQTT_PUBLISH, pkt->v.pubrec.packet_id)) {
            rc = _send_puback(m, MQTT_PUBREL, pkt->v.pubrec.packet_id);
        } else {
            rc = -1;
        }
        break;
    case MQTT_PUBREL:
        if (!_erase_padding(m, MQTT_PUBREC, pkt->v.pubrel.packet_id)) {
            rc = _send_puback(m, MQTT_PUBCOMP, pkt->v.pubrel.packet_id);
        } else {
            rc = -1;
        }
        break;
    case MQTT_PUBCOMP:
        if (!_erase_padding(m, MQTT_PUBREL, pkt->v.pubcomp.packet_id)) {
            if (m->cb.puback) {
                m->cb.puback(m, m->ud, pkt);
            }
        } else {
            rc = -1;
        }
        break;
    case MQTT_SUBACK:
        if (m->cb.suback) {
            m->cb.suback(m, m->ud, pkt);
        }
        break;
    case MQTT_UNSUBACK:
        if (m->cb.unsuback) {
            m->cb.unsuback(m, m->ud, pkt);
        }
        break;
    case MQTT_PINGRESP:
        m->t.ping = 0;
        if (m->cb.pingresp) {
            m->cb.pingresp(m, m->ud, pkt);
        }
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

mqtt_cli_t *
mqtt_cli_create(mqtt_cli_conf_t *config) {
    mqtt_cli_t *m;

    m = (mqtt_cli_t *)malloc(sizeof *m);
    memset(m, 0, sizeof *m);

    mqtt_str_dup(&m->client_id, config->client_id);
    m->version = config->version;
    m->clean_session = config->clean_session;
    m->keep_alive = config->keep_alive;

    if (config->auth.username) {
        mqtt_str_dup(&m->auth.username, config->auth.username);
        mqtt_str_dup(&m->auth.password, config->auth.password);
    }

    if (config->lwt.topic) {
        m->lwt.retain = config->lwt.retain;
        m->lwt.qos = config->lwt.qos;
        mqtt_str_dup(&m->lwt.topic, config->lwt.topic);
        mqtt_str_copy(&m->lwt.message, &config->lwt.message);
    }

    m->cb.connack = config->cb.connack;
    m->cb.suback = config->cb.suback;
    m->cb.unsuback = config->cb.unsuback;
    m->cb.puback = config->cb.puback;
    m->cb.publish = config->cb.publish;
    m->cb.pingresp = config->cb.pingresp;
    m->ud = config->ud;

    mqtt_parser_init(&m->parser);
    mqtt_parser_version(&m->parser, m->version);

    return m;
}

void
mqtt_cli_destroy(mqtt_cli_t *m) {
    _clear_padding(m);
    mqtt_str_free(&m->client_id);
    mqtt_str_free(&m->auth.username);
    mqtt_str_free(&m->auth.password);
    mqtt_str_free(&m->lwt.topic);
    mqtt_str_free(&m->lwt.message);
    free(m);
}

int
mqtt_cli_connect(mqtt_cli_t *m) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, m->version, MQTT_CONNECT);
    pkt.v.connect.connect_flags.bits.clean_session = m->clean_session;
    pkt.v.connect.keep_alive = m->keep_alive;
    mqtt_str_set(&pkt.p.connect.client_id, &m->client_id);
    if (!mqtt_str_empty(&m->auth.username)) {
        pkt.v.connect.connect_flags.bits.username_flag = 1;
        pkt.p.connect.username = m->auth.username;
    }
    if (!mqtt_str_empty(&m->auth.password)) {
        pkt.v.connect.connect_flags.bits.password_flag = 1;
        pkt.p.connect.password = m->auth.password;
    }
    if (!mqtt_str_empty(&m->lwt.topic)) {
        pkt.v.connect.connect_flags.bits.will_flag = 1;
        pkt.v.connect.connect_flags.bits.will_retain = m->lwt.retain;
        pkt.v.connect.connect_flags.bits.will_qos = m->lwt.qos;
        pkt.p.connect.will_topic = m->lwt.topic;
        pkt.p.connect.will_message = m->lwt.message;
    }

    return _append_padding(m, &pkt);
}

int
mqtt_cli_publish(mqtt_cli_t *m, int retain, const char *topic, mqtt_qos_t qos, mqtt_str_t *message,
                 uint16_t *packet_id) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, m->version, MQTT_PUBLISH);
    pkt.f.bits.retain = retain;
    pkt.f.bits.qos = qos;
    if (qos > MQTT_QOS_0) {
        pkt.v.publish.packet_id = _generate_packet_id(m);
    }
    mqtt_str_from(&pkt.v.publish.topic_name, topic);
    mqtt_str_set(&pkt.p.publish.message, message);
    if (packet_id) {
        *packet_id = pkt.v.publish.packet_id;
    }

    return _append_padding(m, &pkt);
}

int
mqtt_cli_subscribe(mqtt_cli_t *m, int count, const char *topic[], mqtt_qos_t qos[], uint16_t *packet_id) {
    mqtt_packet_t pkt;
    int i;

    mqtt_packet_init(&pkt, m->version, MQTT_SUBSCRIBE);
    pkt.v.subscribe.packet_id = _generate_packet_id(m);
    mqtt_subscribe_generate(&pkt, count);
    for (i = 0; i < count; i++) {
        mqtt_str_from(&pkt.p.subscribe.topic_filters[i], topic[i]);
        pkt.p.subscribe.options[i].bits.qos = qos[i];
    }
    if (packet_id) {
        *packet_id = pkt.v.subscribe.packet_id;
    }

    return _append_padding(m, &pkt);
}

int
mqtt_cli_unsubscribe(mqtt_cli_t *m, int count, const char *topic[], uint16_t *packet_id) {
    mqtt_packet_t pkt;
    int i;

    mqtt_packet_init(&pkt, m->version, MQTT_UNSUBSCRIBE);
    pkt.v.unsubscribe.packet_id = _generate_packet_id(m);
    mqtt_unsubscribe_generate(&pkt, count);
    for (i = 0; i < count; i++) {
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[i], topic[i]);
    }
    if (packet_id) {
        *packet_id = pkt.v.unsubscribe.packet_id;
    }

    return _append_padding(m, &pkt);
}

int
mqtt_cli_pingreq(mqtt_cli_t *m) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, m->version, MQTT_PINGREQ);
    m->t.ping = m->t.now;

    return _append_padding(m, &pkt);
}

int
mqtt_cli_disconnect(mqtt_cli_t *m) {
    mqtt_packet_t pkt;

    mqtt_packet_init(&pkt, m->version, MQTT_DISCONNECT);

    return _append_padding(m, &pkt);
}

int
mqtt_cli_outgoing(mqtt_cli_t *m, mqtt_str_t *outgoing) {
    mqtt_cli_packet_t *mp;

    mqtt_str_init(outgoing, 0, 0);
    mp = m->padding;
    while (mp) {
        if (mp->wait_ack == 0) {
            outgoing->n += mp->b.n;
        }
        mp = mp->next;
    }

    if (outgoing->n > 0) {
        mqtt_cli_packet_t **pmp;

        outgoing->s = malloc(outgoing->n);
        outgoing->n = 0;

        pmp = &m->padding;
        while (*pmp) {
            mp = *pmp;
            if (mp->wait_ack == 0) {
                mqtt_str_concat(outgoing, &mp->b);
                if (mp->ttl == 0) {
                    *pmp = mp->next;
                    mqtt_str_free(&mp->b);
                    free(mp);
                } else {
                    mp->wait_ack = 1;
                    mp->t_send = m->t.now;
                }
            }
            pmp = &mp->next;
        }
        m->t.send = m->t.now;
    }

    return 0;
}

int
mqtt_cli_incoming(mqtt_cli_t *m, mqtt_str_t *incoming) {
    mqtt_packet_t pkt;
    int rc;

    while ((rc = mqtt_parse(&m->parser, incoming, &pkt)) > 0) {
        rc = _handle_packet(m, &pkt);
        mqtt_packet_unit(&pkt);
        if (rc)
            break;
    }

    return rc;
}

int
mqtt_cli_elapsed(mqtt_cli_t *m, uint64_t time) {
    int rc;

    m->t.now += time;
    rc = _check_keepalive(m);
    if (!rc)
        rc = _check_padding(m);
    return rc;
}

#endif /* MQTT_CLI_IMPL */

#ifdef MQTT_CLI_LINUX_PLATFORM

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define LINUX_TCP_BUFF_SIZE 4096

typedef struct {
    int fd;
    char buff[LINUX_TCP_BUFF_SIZE];
} linux_tcp_network_t;

void *
linux_tcp_connect(const char *host, int port) {
    linux_tcp_network_t *net;
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
        return 0;
    }
    for (p = servinfo; p; p = p->ai_next) {
        struct timeval timeout = {1, 0};
        int on = 1;

        if ((rc = getnameinfo(p->ai_addr, p->ai_addrlen, ip, sizeof(ip), portstr, sizeof(portstr),
                              NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
            fprintf(stderr, "getnameinfo e: %s\n", gai_strerror(rc));
            continue;
        }
        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            fprintf(stderr, "socket e: %s\n", strerror(errno));
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            fprintf(stderr, "connect %s:%d e: %s\n", ip, port, strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    }
    freeaddrinfo(servinfo);

    if (fd == -1) {
        return 0;
    }

    net = (linux_tcp_network_t *)malloc(sizeof *net);
    memset(net, 0, sizeof *net);

    net->fd = fd;

    return net;
}

ssize_t
linux_tcp_send(void *net, const void *data, size_t size) {
    int fd;
    ssize_t nsend, totlen = 0;
    char *buf = (char *)data;

    fd = ((linux_tcp_network_t *)net)->fd;
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

ssize_t
linux_tcp_recv(void *net, void *data, size_t size) {
    int fd;
    ssize_t nrecv;

    fd = ((linux_tcp_network_t *)net)->fd;
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

int
linux_tcp_transfer(void *net, mqtt_str_t *outgoing, mqtt_str_t *incoming) {
    char *buff;
    ssize_t nrecv;

    if (!mqtt_str_empty(outgoing)) {
        ssize_t nsend;

        nsend = linux_tcp_send(net, outgoing->s, outgoing->n);
        mqtt_str_free(outgoing);
        if (nsend < 0) {
            return -1;
        }
    }

    buff = ((linux_tcp_network_t *)net)->buff;
    nrecv = linux_tcp_recv(net, buff, LINUX_TCP_BUFF_SIZE);
    if (nrecv < 0) {
        return -1;
    }
    mqtt_str_init(incoming, buff, nrecv);
    return 0;
}

void
linux_tcp_close(void *net) {
    int fd;

    fd = ((linux_tcp_network_t *)net)->fd;
    close(fd);
    free(net);
}

uint64_t
linux_time_now() {
    struct timeval tv;

    gettimeofday(&tv, 0);
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

#endif /* MQTT_CLI_LINUX_PLATFORM */