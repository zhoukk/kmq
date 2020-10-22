#include "uv.h"

#define WSHTTP
#define WEBSOCKET_IMPL
#include "websocket.h"

#define TLS_IMPL
#include "tls.h"

#define INI_IMPL
#include "ini.h"

#define LOG_IMPL
#include "log.h"

#include "map.h"
#include "queue.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    MQTT_PROXY_NET_TCP,
    MQTT_PROXY_NET_TLS,
    MQTT_PROXY_NET_WS,
    MQTT_PROXY_NET_WSS,
} mqtt_proxy_mode_t;

typedef struct mqtt_client_s mqtt_client_t;
typedef struct mqtt_upstream_s mqtt_upstream_t;
typedef struct mqtt_listener_s mqtt_listener_t;
typedef struct mqtt_proxy_s mqtt_proxy_t;

struct mqtt_client_s {
    struct {
        uv_tcp_t tcp;
        uv_shutdown_t shutdown;
        char ip[INET6_ADDRSTRLEN];
        char *buff;
        size_t size;
        int closed;
    } remote, upstream;
    mqtt_proxy_mode_t mode;
    mqtt_upstream_t *up;
    uv_connect_t connector;
    uv_getaddrinfo_t resolver;
    wshttp_t *wh;
    tls_t *tls;
};

struct mqtt_upstream_s {
    char *id;
    char *host;
    char *port;
    queue_t node;
};

struct mqtt_listener_s {
    uv_tcp_t server;
    char *id;
    char *host;
    int port;
    mqtt_proxy_mode_t mode;
    tls_ctx_t *tls_ctx;
    char *cert_file;
    char *key_file;
    map_node_t node;
};

struct mqtt_proxy_s {
    uv_loop_t *loop;
    uint64_t time;
    queue_t upstream_q;
    queue_t *up_node;
    map_t listener_m;
    int tls_on;
};

static mqtt_proxy_t P = {0};

int mqtt_upstream_data(mqtt_client_t *c, const char *data, int size);
int mqtt_remote_data(mqtt_client_t *c, const char *data, int size);

static const char *
mqtt_proxy_mode_name(mqtt_proxy_mode_t mode) {
    switch (mode) {
    case MQTT_PROXY_NET_TCP:
        return "TCP";
    case MQTT_PROXY_NET_TLS:
        return "TLS";
    case MQTT_PROXY_NET_WS:
        return "WS";
    case MQTT_PROXY_NET_WSS:
        return "WSS";
    default:
        return "UNKNOWN";
    }
}

static void
_proxy_on_write(uv_write_t *req, int status) {
    if (status) {
        LOG_W("write: %s", uv_strerror(status));
    }
    free(req->data);
    free(req);
}

static int
mqtt_remote_send(mqtt_client_t *c, const char *data, int size) {
    uv_write_t *req;
    uv_buf_t buf;
    char *p;
    int rc;

    p = malloc(size);
    memcpy(p, data, size);
    req = (uv_write_t *)malloc(sizeof *req);
    req->data = p;
    buf = uv_buf_init(p, size);
    rc = uv_write(req, (uv_stream_t *)&c->remote.tcp, &buf, 1, _proxy_on_write);
    if (rc) {
        LOG_W("write: %s", uv_strerror(rc));
    }
    return rc;
}

static int
mqtt_upstream_send(mqtt_client_t *c, const char *data, int size) {
    uv_write_t *req;
    uv_buf_t buf;
    char *p;
    int rc;

    p = malloc(size);
    memcpy(p, data, size);
    req = (uv_write_t *)malloc(sizeof *req);
    req->data = p;
    buf = uv_buf_init(p, size);
    rc = uv_write(req, (uv_stream_t *)&c->upstream.tcp, &buf, 1, _proxy_on_write);
    if (rc) {
        LOG_W("write: %s", uv_strerror(rc));
    }
    return rc;
}

static void
_proxy_on_shutdown(uv_shutdown_t *req, int status) {
    (void)req;

    if (status != 0) {
        LOG_W("shutdown: %s", uv_strerror(status));
    }
}

static void
mqtt_remote_shutdown(mqtt_client_t *c) {
    if (c->remote.closed) {
        return;
    }
    LOG_D("remote.%p.shutdown", c);
    uv_shutdown(&c->remote.shutdown, (uv_stream_t *)&c->remote.tcp, _proxy_on_shutdown);
}

static void
mqtt_upstream_shutdown(mqtt_client_t *c) {
    if (c->upstream.closed) {
        return;
    }
    LOG_D("upstream.%p.shutdown", c);
    uv_shutdown(&c->upstream.shutdown, (uv_stream_t *)&c->upstream.tcp, _proxy_on_shutdown);
}

static void
mqtt_client_destroy(mqtt_client_t *c) {
    LOG_D("client.%p.destroy", c);
    if (c->wh) {
        wshttp_destroy(c->wh);
    }
    if (c->tls) {
        tls_destroy(c->tls);
    }
    if (c->remote.buff) {
        free(c->remote.buff);
    }
    if (c->upstream.buff) {
        free(c->upstream.buff);
    }
    free(c);
}

static void
_proxy_on_remote_close(uv_handle_t *handle) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)handle->data;
    c->remote.closed = 1;

    if (c->upstream.closed) {
        mqtt_client_destroy(c);
    }
}

static void
mqtt_remote_close(mqtt_client_t *c) {
    LOG_D("remote.%p.close", c);
    mqtt_upstream_shutdown(c);
    uv_close((uv_handle_t *)&c->remote.tcp, _proxy_on_remote_close);
}

static void
_proxy_on_remote_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)stream->data;
    LOG_D("remote.%p.read %zd", c, nread);
    if (nread < 0) {
        if (nread != UV_EOF) {
            LOG_W("read %s : %s", c->remote.ip, uv_strerror(nread));
        }
        mqtt_remote_close(c);
        return;
    }
    if (mqtt_remote_data(c, buf->base, nread)) {
        mqtt_remote_shutdown(c);
    }
}

static void
_proxy_on_remote_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)handle->data;
    if (c->remote.buff && c->remote.size != suggested_size) {
        free(c->remote.buff);
        c->remote.buff = 0;
    }
    if (!c->remote.buff) {
        c->remote.buff = malloc(suggested_size);
        c->remote.size = suggested_size;
    }

    buf->base = c->remote.buff;
    buf->len = c->remote.size;
}

static void
mqtt_remote_start(mqtt_client_t *c) {
    uv_read_start((uv_stream_t *)&c->remote.tcp, _proxy_on_remote_alloc, _proxy_on_remote_read);
}

static void
mqtt_remote_stop(mqtt_client_t *c) {
    uv_read_stop((uv_stream_t *)&c->remote.tcp);
}

static void
_proxy_on_upstream_close(uv_handle_t *handle) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)handle->data;
    c->upstream.closed = 1;

    if (c->remote.closed) {
        mqtt_client_destroy(c);
    }
}

static void
mqtt_upstream_close(mqtt_client_t *c) {
    LOG_D("upstream.%p.close", c);
    mqtt_remote_shutdown(c);
    uv_close((uv_handle_t *)&c->upstream.tcp, _proxy_on_upstream_close);
}

static void
_proxy_on_upstream_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)stream->data;
    if (nread < 0) {
        if (nread != UV_EOF) {
            LOG_W("read %s : %s", c->upstream.ip, uv_strerror(nread));
        }
        mqtt_upstream_close(c);
        return;
    }
    if (mqtt_upstream_data(c, buf->base, nread)) {
        mqtt_upstream_shutdown(c);
    }
}

static void
_proxy_on_upstream_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)handle->data;
    if (c->upstream.buff && c->upstream.size != suggested_size) {
        free(c->upstream.buff);
        c->upstream.buff = 0;
    }
    if (!c->upstream.buff) {
        c->upstream.buff = malloc(suggested_size);
        c->upstream.size = suggested_size;
    }

    buf->base = c->upstream.buff;
    buf->len = c->upstream.size;
}

static void
mqtt_upstream_start(mqtt_client_t *c) {
    uv_read_start((uv_stream_t *)&c->upstream.tcp, _proxy_on_upstream_alloc, _proxy_on_upstream_read);
}

static void
_proxy_on_upstream_connect(uv_connect_t *req, int status) {
    mqtt_client_t *c;
    struct sockaddr addr;
    char ip[INET6_ADDRSTRLEN] = {0};
    int addrlen;

    c = (mqtt_client_t *)req->data;
    if (status != 0) {
        LOG_W("connect %s:%s : %s", c->up->host, c->up->port, uv_strerror(status));
        mqtt_remote_shutdown(c);
        return;
    }

    addrlen = sizeof(addr);
    uv_tcp_getpeername(&c->upstream.tcp, &addr, &addrlen);
    uv_ip4_name((struct sockaddr_in *)&addr, ip, sizeof(ip));
    strcpy(c->upstream.ip, ip);
    c->upstream.closed = 0;

    LOG_D("upstream.%p.connect", c);

    mqtt_upstream_start(c);
    mqtt_remote_start(c);

    LOG_I("proxy %s %s => %s", mqtt_proxy_mode_name(c->mode), c->remote.ip, c->upstream.ip);
}

static void
_proxy_on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
    mqtt_client_t *c;
    char ip[INET6_ADDRSTRLEN] = {0};
    int rc;

    c = (mqtt_client_t *)resolver->data;
    if (status < 0) {
        LOG_W("getaddrinfo %s: %s", c->up->host, uv_err_name(status));
        mqtt_remote_shutdown(c);
        return;
    }

    uv_ip4_name((struct sockaddr_in *)res->ai_addr, ip, sizeof(ip));
    uv_tcp_init(P.loop, &c->upstream.tcp);

    rc = uv_tcp_connect(&c->connector, &c->upstream.tcp, (const struct sockaddr *)res->ai_addr,
                        _proxy_on_upstream_connect);
    if (rc) {
        LOG_W("connect %s:%s : %s", ip, c->up->port, uv_strerror(rc));
        mqtt_remote_shutdown(c);
    }

    uv_freeaddrinfo(res);
}

static int
mqtt_upstream_connect(mqtt_client_t *c) {
    struct addrinfo hints;
    int rc;

    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    c->up = queue_data(P.up_node, mqtt_upstream_t, node);
    P.up_node = queue_next(P.up_node);
    if (P.up_node == &P.upstream_q) {
        P.up_node = queue_next(P.up_node);
    }

    LOG_D("upstream.%p.resolve id: %s, host: %s", c, c->up->id, c->up->host);

    rc = uv_getaddrinfo(P.loop, &c->resolver, _proxy_on_resolved, c->up->host, c->up->port, &hints);
    if (rc) {
        LOG_W("getaddrinfo %s: %s", c->up->host, uv_strerror(rc));
    }
    return rc;
}

static void
_proxy_ws_on_open(wshttp_t *wh, void *io, void *ud) {
    mqtt_client_t *c;
    (void)wh;
    (void)ud;

    c = (mqtt_client_t *)io;

    LOG_D("remote.%p.websocket.open", c);

    mqtt_remote_stop(c);
    if (mqtt_upstream_connect(c)) {
        wshttp_close(wh, WS_STATUS_NORMAL, "BYE");
    }
}

static void
_proxy_ws_on_data(wshttp_t *wh, void *io, void *ud, int opcode, websocket_binary_t payload) {
    mqtt_client_t *c;
    (void)ud;
    (void)opcode;

    c = (mqtt_client_t *)io;

    if (mqtt_upstream_send(c, payload.data, payload.length)) {
        wshttp_close(wh, WS_STATUS_NORMAL, "BYE");
    }
}

static void
_proxy_ws_on_close(wshttp_t *wh, void *io, void *ud, websocket_binary_t payload) {
    mqtt_client_t *c;
    (void)wh;
    (void)ud;
    (void)payload;

    c = (mqtt_client_t *)io;

    if (payload.length) {
        LOG_D("remote.%p.websocket.close status: %d, reason: %.*s", c, WS_CLOSE_STATUS(payload),
              WS_CLOSE_REASON_LEN(payload), WS_CLOSE_REASON(payload));
    } else {
        LOG_D("remote.%p.websocket.close", c);
    }

    if (c->mode == MQTT_PROXY_NET_WS) {
        mqtt_remote_shutdown(c);
    } else if (c->mode == MQTT_PROXY_NET_WSS) {
        tls_shutdown(c->tls);
    }
}

static int
_proxy_ws_write(wshttp_t *wh, void *io, void *ud, const char *data, int size) {
    mqtt_client_t *c;
    (void)wh;
    (void)ud;

    c = (mqtt_client_t *)io;

    if (c->mode == MQTT_PROXY_NET_WS) {
        return mqtt_remote_send(c, data, size);
    } else if (c->mode == MQTT_PROXY_NET_WSS) {
        return tls_write(c->tls, data, size);
    }
    return -1;
}

static void
_proxy_tls_on_open(tls_t *tls, void *io, void *ud) {
    mqtt_client_t *c;
    (void)tls;
    (void)ud;

    c = (mqtt_client_t *)io;

    LOG_D("remote.%p.tls open", c);

    if (c->mode == MQTT_PROXY_NET_TLS) {
        mqtt_remote_stop(c);
        if (mqtt_upstream_connect(c)) {
            tls_shutdown(tls);
        }
    }
}

static void
_proxy_tls_on_data(tls_t *tls, void *io, void *ud, const void *data, int size) {
    mqtt_client_t *c;
    (void)ud;

    c = (mqtt_client_t *)io;

    if (c->mode == MQTT_PROXY_NET_TLS) {
        if (mqtt_upstream_send(c, data, size)) {
            tls_shutdown(tls);
        }
    } else if (c->mode == MQTT_PROXY_NET_WSS) {
        websocket_binary_t wsb = {.data = (char *)data, .length = (uint64_t)size};
        if (wshttp_feed(c->wh, &wsb)) {
            wshttp_close(c->wh, WS_STATUS_PROTOCOL_ERROR, "BYE");
        }
    }
}

static void
_proxy_tls_on_close(tls_t *tls, void *io, void *ud) {
    mqtt_client_t *c;
    (void)tls;
    (void)ud;

    c = (mqtt_client_t *)io;

    LOG_D("remote.%p.tls close", c);
}

static int
_proxy_tls_write(tls_t *tls, void *io, void *ud, const void *data, int size) {
    mqtt_client_t *c;
    (void)tls;
    (void)ud;

    c = (mqtt_client_t *)io;
    return mqtt_remote_send(c, data, size);
}

int
mqtt_upstream_data(mqtt_client_t *c, const char *data, int size) {
    int rc;

    if (c->mode == MQTT_PROXY_NET_TCP) {
        rc = mqtt_remote_send(c, data, size);
    } else if (c->mode == MQTT_PROXY_NET_WS || c->mode == MQTT_PROXY_NET_WSS) {
        websocket_binary_t wsb = {.data = (char *)data, .length = (uint64_t)size};
        rc = wshttp_write(c->wh, WS_OPCODE_BINARY, &wsb);
    } else if (c->mode == MQTT_PROXY_NET_TLS) {
        rc = tls_write(c->tls, data, size);
    } else {
        rc = -1;
    }
    return rc;
}

int
mqtt_remote_data(mqtt_client_t *c, const char *data, int size) {
    int rc;

    if (c->mode == MQTT_PROXY_NET_TCP) {
        rc = mqtt_upstream_send(c, data, size);
    } else if (c->mode == MQTT_PROXY_NET_TLS || c->mode == MQTT_PROXY_NET_WSS) {
        rc = tls_feed(c->tls, data, size);
    } else if (c->mode == MQTT_PROXY_NET_WS) {
        websocket_binary_t wsb = {.data = (char *)data, .length = (uint64_t)size};
        rc = wshttp_feed(c->wh, &wsb);
    } else {
        rc = -1;
    }
    return rc;
}

static mqtt_client_t *
mqtt_client_create(mqtt_listener_t *ln) {
    mqtt_client_t *c;

    c = (mqtt_client_t *)malloc(sizeof *c);
    memset(c, 0, sizeof *c);

    c->remote.tcp.data = c;
    c->upstream.tcp.data = c;
    c->connector.data = c;
    c->resolver.data = c;
    c->mode = ln->mode;
    c->upstream.closed = 1;

    if (ln->mode == MQTT_PROXY_NET_WS || ln->mode == MQTT_PROXY_NET_WSS) {
        wshttp_config_t config = {
            .mode = WS_MODE_SERVER,
            .on_open = _proxy_ws_on_open,
            .on_data = _proxy_ws_on_data,
            .on_close = _proxy_ws_on_close,
            .write = _proxy_ws_write,
            .io = c,
        };
        c->wh = wshttp_create(&config);
    }

    if (ln->mode == MQTT_PROXY_NET_TLS || ln->mode == MQTT_PROXY_NET_WSS) {
        tls_config_t cfg = {
            .on_open = _proxy_tls_on_open,
            .on_data = _proxy_tls_on_data,
            .on_close = _proxy_tls_on_close,
            .write = _proxy_tls_write,
            .io = c,
        };
        c->tls = tls_create(ln->tls_ctx, &cfg);
    }

    uv_tcp_init(P.loop, &c->remote.tcp);

    LOG_D("client.%p.create", c);
    return c;
}

static void
_proxy_on_remote_connect(uv_stream_t *server, int status) {
    mqtt_client_t *c;
    mqtt_listener_t *ln;
    struct sockaddr addr;
    char ip[INET6_ADDRSTRLEN] = {0};
    int rc, addrlen;

    if (status != 0) {
        LOG_W("connect: %s", uv_strerror(status));
        return;
    }

    ln = (mqtt_listener_t *)server->data;
    c = mqtt_client_create(ln);
    rc = uv_accept(server, (uv_stream_t *)&c->remote.tcp);
    if (rc) {
        LOG_W("accept: %s", uv_strerror(rc));
        mqtt_remote_close(c);
        return;
    }

    addrlen = sizeof(addr);
    uv_tcp_getpeername(&c->remote.tcp, &addr, &addrlen);
    uv_ip4_name((struct sockaddr_in *)&addr, ip, sizeof(ip));
    strcpy(c->remote.ip, ip);

    if (ln->mode == MQTT_PROXY_NET_TCP) {
        if (mqtt_upstream_connect(c)) {
            mqtt_remote_shutdown(c);
        }
    } else {
        mqtt_remote_start(c);
    }
}

static mqtt_upstream_t *
mqtt_upstream_fetch(const char *id) {
    mqtt_upstream_t *up;
    queue_t *node;

    queue_foreach(node, &P.upstream_q) {
        up = queue_data(node, mqtt_upstream_t, node);
        if (!strcmp(up->id, id)) {
            return up;
        }
    }

    up = (mqtt_upstream_t *)malloc(sizeof *up);
    memset(up, 0, sizeof *up);

    up->id = strdup(id);
    queue_insert_tail(&P.upstream_q, &up->node);
    return up;
}

static mqtt_listener_t *
mqtt_listener_fetch(const char *id) {
    mqtt_listener_t *ln;
    map_node_t *node;

    node = map_find(&P.listener_m, (void *)id);
    if (!node) {
        ln = (mqtt_listener_t *)malloc(sizeof *ln);
        memset(ln, 0, sizeof *ln);
        ln->id = strdup(id);
        map_push(&P.listener_m, (void *)id, &ln->node);
    } else {
        ln = map_data(node, mqtt_listener_t, node);
    }
    return ln;
}

static int
mqtt_listener_start(uv_loop_t *loop, mqtt_listener_t *ln) {
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
    rc = uv_listen((uv_stream_t *)&ln->server, SOMAXCONN, _proxy_on_remote_connect);
    if (rc) {
        LOG_E("listen %s:%d %s", ln->host, ln->port, uv_strerror(rc));
        return -1;
    }

    if (ln->mode == MQTT_PROXY_NET_TLS || ln->mode == MQTT_PROXY_NET_WSS) {
        ln->tls_ctx = tls_server_ctx(ln->cert_file, ln->key_file);
        if (!ln->tls_ctx) {
            LOG_E("tls context init error");
            return -1;
        }
    }

    return 0;
}

static void
_proxy_on_timer(uv_timer_t *handle) {
    (void)handle;

    P.time++;
    LOG_UPDATE(P.time);
}

static int
_proxy_config(void *ud, const char *section, const char *key, const char *value) {
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

    if (!strncmp(section, "server-", 7)) {
        mqtt_listener_t *ln;
        const char *id;

        id = section + 7;
        ln = mqtt_listener_fetch(id);
        if (!strcmp(key, "host")) {
            ln->host = strdup(value);
        } else if (!strcmp(key, "port")) {
            ln->port = atoi(value);
        } else if (!strcmp(key, "cert")) {
            ln->cert_file = strdup(value);
        } else if (!strcmp(key, "key")) {
            ln->key_file = strdup(value);
        } else if (!strcmp(key, "mode")) {
            if (!strcmp(value, "tcp")) {
                ln->mode = MQTT_PROXY_NET_TCP;
            } else if (!strcmp(value, "tls")) {
                ln->mode = MQTT_PROXY_NET_TLS;
                P.tls_on = 1;
            } else if (!strcmp(value, "ws")) {
                ln->mode = MQTT_PROXY_NET_WS;
            } else if (!strcmp(value, "wss")) {
                ln->mode = MQTT_PROXY_NET_WSS;
                P.tls_on = 1;
            }
        }
    }

    if (!strncmp(section, "upstream-", 9)) {
        mqtt_upstream_t *up;
        const char *id;

        id = section + 9;
        up = mqtt_upstream_fetch(id);
        if (!strcmp(key, "host")) {
            up->host = strdup(value);
        } else if (!strcmp(key, "port")) {
            up->port = strdup(value);
        }
    }

    return 0;
}

static void *
_mqtt_listener_key_pt(map_node_t *node) {
    mqtt_listener_t *ln;

    ln = map_data(node, mqtt_listener_t, node);
    return ln->id;
}

static int
_mqtt_listener_cmp_pt(void *a, void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static int
mqtt_proxy_init(uv_loop_t *loop, int argc, char *argv[]) {
    P.loop = loop;

    map_init(&P.listener_m, _mqtt_listener_key_pt, _mqtt_listener_cmp_pt);
    queue_init(&P.upstream_q);

    if (argc > 1 && ini_parse(argv[1], _proxy_config, 0)) {
        LOG_E("config file %s parse error", argv[1]);
        return -1;
    }

    P.up_node = queue_head(&P.upstream_q);
    if (P.tls_on) {
        tls_init();
    }

    return 0;
}

int
main(int argc, char *argv[]) {
    uv_loop_t *loop;
    uv_timer_t timer;
    map_node_t *node;

    signal(SIGPIPE, SIG_IGN);
    loop = uv_default_loop();

    if (mqtt_proxy_init(loop, argc, argv)) {
        LOG_E("proxy init failed");
        return 1;
    }

    map_foreach(node, &P.listener_m) {
        mqtt_listener_t *ln;

        ln = map_data(node, mqtt_listener_t, node);
        if (mqtt_listener_start(loop, ln)) {
            LOG_E("start %3s proxy failed", mqtt_proxy_mode_name(ln->mode));
            return -1;
        } else {
            LOG_I("%3s proxy at %s:%d started", mqtt_proxy_mode_name(ln->mode), ln->host, ln->port);
        }
    }

    uv_timer_init(loop, &timer);
    uv_timer_start(&timer, _proxy_on_timer, 1000, 1000);

    LOG_I("mqtt proxy started");
    return uv_run(loop, UV_RUN_DEFAULT);
}
