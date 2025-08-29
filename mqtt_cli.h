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

#if HAVE_C11_THREADS
#include <threads.h>
#else
#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION mqtt_cli_mutex_t;
#else
#include <pthread.h>
typedef pthread_mutex_t mqtt_cli_mutex_t;
#endif
#endif

#if HAVE_C11_THREADS
#define MQTT_CLI_LOCK_INIT(m) mtx_init(&(m), mtx_plain)
#define MQTT_CLI_LOCK_DESTROY(m) mtx_destroy(&(m))
#define MQTT_CLI_LOCK(m) mtx_lock(&(m))
#define MQTT_CLI_UNLOCK(m) mtx_unlock(&(m))
#else
#ifdef _WIN32
#define MQTT_CLI_LOCK_INIT(m) InitializeCriticalSection(&(m))
#define MQTT_CLI_LOCK_DESTROY(m) DeleteCriticalSection(&(m))
#define MQTT_CLI_LOCK(m) EnterCriticalSection(&(m))
#define MQTT_CLI_UNLOCK(m) LeaveCriticalSection(&(m))
#else
#define MQTT_CLI_LOCK_INIT(m) pthread_mutex_init(&(m), NULL)
#define MQTT_CLI_LOCK_DESTROY(m) pthread_mutex_destroy(&(m))
#define MQTT_CLI_LOCK(m) pthread_mutex_lock(&(m))
#define MQTT_CLI_UNLOCK(m) pthread_mutex_unlock(&(m))
#endif
#endif

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
#if HAVE_C11_THREADS
    mtx_t padding_lock;
#else
    mqtt_cli_mutex_t padding_lock;
#endif

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

    MQTT_CLI_LOCK(m->padding_lock);
    mp = m->padding;
    while (mp) {
        mqtt_cli_packet_t *next;

        next = mp->next;
        mqtt_str_free(&mp->b);
        MQTT_FREE(mp);
        mp = next;
    }
    MQTT_CLI_UNLOCK(m->padding_lock);
    m->padding = 0;
}

static int
_check_padding(mqtt_cli_t *m) {
    mqtt_cli_packet_t *mp;
    int rc;

    rc = 0;

    MQTT_CLI_LOCK(m->padding_lock);
    mp = m->padding;
    while (mp) {
        if (mp->ttl > 0 && m->t.now - mp->t_send >= MQTT_CLI_PACKET_TIMEOUT * 1000) {
            if (--mp->ttl > 0) {
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
    MQTT_CLI_UNLOCK(m->padding_lock);

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
    int ret;

    ret = -1;
    MQTT_CLI_LOCK(m->padding_lock);
    pmp = &m->padding;
    while (*pmp) {
        mp = *pmp;
        if (mp->type == type && mp->packet_id == packet_id) {
            *pmp = mp->next;
            mqtt_str_free(&mp->b);
            MQTT_FREE(mp);
            ret = 0;
            break;
        }
        pmp = &mp->next;
    }
    MQTT_CLI_UNLOCK(m->padding_lock);

    return ret;
}

static int
_append_padding(mqtt_cli_t *m, mqtt_packet_t *pkt) {
    mqtt_str_t b = MQTT_STR_INITIALIZER;
    int rc;

    rc = mqtt_serialize(pkt, &b);
    if (!rc) {
        mqtt_cli_packet_t *mp;

        mp = (mqtt_cli_packet_t *)MQTT_MALLOC(sizeof *mp);
        if (!mp) {
            mqtt_str_free(&b);
            return -1;
        }
        memset(mp, 0, sizeof *mp);
        mp->type = (mqtt_packet_type_t)pkt->f.bits.type;
        mqtt_str_set(&mp->b, &b);
        mp->t_send = m->t.now;
        switch (pkt->f.bits.type) {
        case MQTT_PUBLISH:
            mp->packet_id = pkt->v.publish.packet_id;
            if (pkt->f.bits.qos > MQTT_QOS_0)
                mp->ttl = MQTT_CLI_PACKET_TTL;
            break;
        case MQTT_PUBREL:
            mp->packet_id = pkt->v.pubrel.packet_id;
            mp->ttl = MQTT_CLI_PACKET_TTL;
            break;
        default:
            break;
        }

        MQTT_CLI_LOCK(m->padding_lock);
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
        MQTT_CLI_UNLOCK(m->padding_lock);
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
        rc = _send_puback(m, MQTT_PUBCOMP, pkt->v.pubrel.packet_id);
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

    m = (mqtt_cli_t *)MQTT_MALLOC(sizeof *m);
    if (!m) {
        return 0;
    }
    memset(m, 0, sizeof *m);

    MQTT_CLI_LOCK_INIT(m->padding_lock);

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
    MQTT_CLI_LOCK_DESTROY(m->padding_lock);
    MQTT_FREE(m);
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
    if (mqtt_subscribe_generate(&pkt, count))
        return -1;
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
    if (mqtt_unsubscribe_generate(&pkt, count))
        return -1;
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

    MQTT_CLI_LOCK(m->padding_lock);
    mp = m->padding;
    while (mp) {
        if (mp->wait_ack == 0) {
            outgoing->n += mp->b.n;
        }
        mp = mp->next;
    }

    if (outgoing->n > 0) {
        mqtt_cli_packet_t **pmp;

        outgoing->s = (char *)MQTT_MALLOC(outgoing->n);
        if (!outgoing->s) {
            MQTT_CLI_UNLOCK(m->padding_lock);
            return -1;
        }
        outgoing->i = 0;

        pmp = &m->padding;
        while (*pmp) {
            mp = *pmp;
            if (mp->wait_ack == 0) {
                mqtt_str_concat(outgoing, &mp->b);
                if (mp->ttl == 0) {
                    *pmp = mp->next;
                    mqtt_str_free(&mp->b);
                    MQTT_FREE(mp);
                    continue;
                }
                mp->wait_ack = 1;
                mp->t_send = m->t.now;
            }
            pmp = &mp->next;
        }
        m->t.send = m->t.now;
    }
    MQTT_CLI_UNLOCK(m->padding_lock);

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

#ifdef MQTT_CLI_NETWORK_IMPL

#define NETWORK_TCP_BUFF_SIZE 4096

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct {
    int fd;
    char buff[NETWORK_TCP_BUFF_SIZE];
} network_tcp_t;

void *
network_tcp_connect(const char *host, int port) {
    network_tcp_t *net;
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
            continue;
        }
        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            fd = -1;
            continue;
        }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    }
    freeaddrinfo(servinfo);

    if (fd == -1) {
        return 0;
    }

    net = (network_tcp_t *)MQTT_MALLOC(sizeof *net);
    if (!net) {
        close(fd);
        return 0;
    }
    memset(net, 0, sizeof *net);

    net->fd = fd;

    return net;
}

ssize_t
network_tcp_send(void *net, const void *data, size_t size) {
    int fd;
    ssize_t nsend, totlen = 0;
    char *buf = (char *)data;

    fd = ((network_tcp_t *)net)->fd;
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
network_tcp_recv(void *net, void *data, size_t size) {
    int fd;
    ssize_t nrecv;

    fd = ((network_tcp_t *)net)->fd;
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

void
network_tcp_close(void *net) {
    int fd;

    fd = ((network_tcp_t *)net)->fd;
    close(fd);
    MQTT_FREE(net);
}

uint64_t
network_time_now() {
    struct timeval tv;

    gettimeofday(&tv, 0);
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

#endif /* defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__linux__) */

#ifdef _WIN32

#include <BaseTsd.h>
#include <winsock2.h>
#include <ws2tcpip.h>

typedef SSIZE_T ssize_t;

typedef struct {
    SOCKET sock;
    char buff[NETWORK_TCP_BUFF_SIZE];
} network_tcp_t;

void *
network_tcp_connect(const char *host, int port) {
    network_tcp_t *net;
    struct addrinfo hints, *servinfo, *p;
    char portstr[6];
    SOCKET sock;
    int rc;

    WSADATA wsaData;
    rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (rc != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", rc);
        return 0;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    sock = INVALID_SOCKET;
    snprintf(portstr, sizeof(portstr), "%d", port);

    rc = getaddrinfo(host, portstr, &hints, &servinfo);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", rc);
        WSACleanup();
        return 0;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == INVALID_SOCKET) {
            fprintf(stderr, "socket failed: %ld\n", WSAGetLastError());
            continue;
        }

        rc = connect(sock, p->ai_addr, (int)p->ai_addrlen);
        if (rc == SOCKET_ERROR) {
            closesocket(sock);
            sock = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(servinfo);

    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Unable to connect to server!\n");
        WSACleanup();
        return 0;
    }

    u_long mode = 1;
    rc = ioctlsocket(sock, FIONBIO, &mode);
    if (rc == SOCKET_ERROR) {
        fprintf(stderr, "ioctlsocket failed: %ld\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    net = (network_tcp_t *)malloc(sizeof(network_tcp_t));
    if (!net) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }
    memset(net, 0, sizeof(network_tcp_t));

    net->sock = sock;

    return net;
}

ssize_t
network_tcp_send(void *net, const void *data, size_t size) {
    SOCKET sock;
    int nsend, totlen = 0;
    const char *buf = (const char *)data;

    sock = ((network_tcp_t *)net)->sock;
    while (totlen < (int)size) {
        nsend = send(sock, buf + totlen, (int)(size - totlen), 0);
        if (nsend == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                continue;
            }
            return -1;
        }
        if (nsend == 0)
            return -1;
        totlen += nsend;
    }
    return totlen;
}

ssize_t
network_tcp_recv(void *net, void *data, size_t size) {
    SOCKET sock;
    int nrecv;

    sock = ((network_tcp_t *)net)->sock;
    nrecv = recv(sock, (char *)data, (int)size, 0);
    if (nrecv == 0)
        return -1;
    if (nrecv == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    return nrecv;
}

void
network_tcp_close(void *net) {
    SOCKET sock;

    sock = ((network_tcp_t *)net)->sock;
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    MQTT_FREE(net);

    WSACleanup();
}

uint64_t
network_time_now() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;

    return ul.QuadPart / 10000;
}

#endif /* _WIN32 */

int
network_tcp_transfer(void *net, mqtt_str_t *outgoing, mqtt_str_t *incoming) {
    char *buff;
    ssize_t nrecv;

    if (!mqtt_str_empty(outgoing)) {
        ssize_t nsend;

        nsend = network_tcp_send(net, outgoing->s, outgoing->n);
        mqtt_str_free(outgoing);
        if (nsend < 0) {
            return -1;
        }
    }

    buff = ((network_tcp_t *)net)->buff;
    nrecv = network_tcp_recv(net, buff, NETWORK_TCP_BUFF_SIZE);
    if (nrecv < 0) {
        return -1;
    }
    mqtt_str_init(incoming, buff, nrecv);
    return 0;
}

#endif /* MQTT_CLI_NETWORK_IMPL */
