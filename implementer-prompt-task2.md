You are implementing Task 2 of the MQTT Broker refactor plan.

## Context
Project: mqk — a lightweight MQTT broker library at /Users/zhoukk/k/kmq/
Current file: /Users/zhoukk/k/kmq/mqtt_broker.c (2052 lines, original implementation)
Current branch: master (already has mqtt_broker.h from Task 1)

## Task: Migrate from global singleton `static mqtt_broker_t B` to struct-based `mqtt_broker_t *broker` parameter

### Step 1: Update mqtt_broker.c includes and add struct definitions

In mqtt_broker.c, replace the first 28 lines (includes) to add mqtt_broker.h:

```c
#define MQTT_BROKER_IMPL
#include "mqtt_broker.h"
#define MQTT_IMPL
#include "mqtt.h"
#define SNOWFLAKE_IMPL
#include "snowflake.h"
#define INI_IMPL
#include "ini.h"
#define LOG_IMPL
#include "log.h"
#define HTTP_IMPL
#define BASE64_IMPL
#define URLCODE_IMPL
#include "http.h"
#include "map.h"
#include "queue.h"
#include "uv.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
```

Then in the struct definitions section (around line 125), replace the existing mqtt_broker_s:

FROM:
```c
struct mqtt_broker_s {
    uv_loop_t *loop;
    uv_tcp_t server;
    uv_idle_t idle;
    mqtt_trie_t *sub_root;
    char *host;
    int port;
    char *auth_type;
    char *auth_api;
    uint64_t t_now;
    snowflake_t snowflake;
    queue_t client_q;
    map_t session_m;
    queue_t msg_q;
    queue_t account_q;
};
```

TO:
```c
struct mqtt_broker_s {
    uv_loop_t *loop;
    uv_tcp_t server;
    uv_idle_t idle;
    uv_timer_t timer;
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
    int max_connections;
    int connections;
    size_t max_packet_size;
    int rate_limit;
    tls_ctx_t *tls_ctx;
    int shutdown_pending;
    int pending_clients;
    int trie_dump_enabled;
};
```

Remove `static mqtt_broker_t B = {0};` (line 142).

### Step 2: Replace all B.xxx references and update function signatures

You need to systematically replace every `B.xxx` with `b->xxx` and add `mqtt_broker_t *b` parameter to every function that references it.

Here is the complete list of replacements, grouped by function:

#### 2a: _broker_dump, broker_log_dump, broker_log_prop
No B references — no changes needed.

#### 2b: mqtt_topic_segment
No B references — no changes needed.

#### 2c: mqtt_message_create, mqtt_message_destroy, mqtt_message_add_ref, mqtt_lwt_create
No B references — no changes needed.

#### 2d: mqtt_publication_create (line ~284-300)
FROM:
```c
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
```
TO:
```c
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
```

#### 2e: mqtt_session_outgoing_update (line ~367-383)
FROM:
```c
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
```
TO:
```c
static int
mqtt_session_outgoing_update(mqtt_session_t *s, uint16_t packet_id, mqtt_publication_state_t state,
                             mqtt_publication_state_t new_state, mqtt_broker_t *b) {
    queue_t *node;
    queue_foreach(node, &s->outgoing) {
        mqtt_publication_t *pub;
        pub = queue_data(node, mqtt_publication_t, node);
        if (pub->packet_id == packet_id && pub->state == state) {
            pub->state = new_state;
            pub->t_send = b->t_now;
            return 0;
        }
    }
    return -1;
}
```

#### 2f: _client_update (line ~1816-1825)
FROM:
```c
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
```
TO:
```c
static int
mqtt_client_update(mqtt_client_t *c, mqtt_broker_t *b) {
    if (c->keep_alive > 0) {
        uint64_t expired = c->keep_alive * 1.5;
        if (b->t_now - c->t_last > expired) {
            return -1;
        }
    }
    return 0;
}
```

#### 2g: _mqtt_on_idle (line ~948-968)
FROM:
```c
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
```
TO:
```c
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
    mqtt_trie_dispatch(b->sub_root, msg->topic_name, msg);
    mqtt_message_destroy(msg);
}
```

#### 2h: mqtt_broker_dispatch (line ~970-979)
FROM:
```c
static void
mqtt_broker_dispatch(mqtt_message_t *msg) {
    int empty;
    empty = queue_empty(&B.msg_q);
    queue_insert_tail(&B.msg_q, &msg->node);
    if (empty) {
        uv_idle_start(&B.idle, _mqtt_on_idle);
    }
}
```
TO:
```c
static void
mqtt_broker_dispatch(mqtt_broker_t *b, mqtt_message_t *msg) {
    int empty;
    empty = queue_empty(&b->msg_q);
    queue_insert_tail(&b->msg_q, &msg->node);
    if (empty) {
        uv_idle_start(&b->idle, _mqtt_on_idle);
    }
}
```

#### 2i: _broker_on_timer (line ~1911-1927)
FROM:
```c
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
```
TO:
```c
static void
_broker_on_timer(uv_timer_t *handle) {
    mqtt_broker_t *b = handle->data;
    queue_t *node;
    (void)handle;
    b->t_now++;
    LOG_UPDATE(b->t_now);
    queue_foreach(node, &b->client_q) {
        mqtt_client_t *c;
        c = queue_data(node, mqtt_client_t, node);
        if (!c->closed && mqtt_client_update(c, b) == 0) {
            continue;
        }
        if (!c->closed) {
            LOG_D("client.%p.timeout", c);
            mqtt_client_shutdown(c);
        }
    }
}
```

#### 2j: _broker_config (line ~1929-1987)
FROM:
```c
static int
_broker_config(void *ud, const char *section, const char *key, const char *value) {
    LOG_D("[%s] %s = %s", section, key, value);
    if (!value) return 0;
    if (!strcmp(section, "log")) { ... }
    if (!strcmp(section, "net")) {
        if (!strcmp(key, "host")) { B.host = strdup(value); }
        else if (!strcmp(key, "port")) { B.port = atoi(value); }
    }
    if (!strcmp(section, "auth")) {
        if (!strcmp(key, "type")) { B.auth_type = strdup(value); }
        else if (!strcmp(key, "api")) { B.auth_api = strdup(value); }
    }
    if (!strcmp(section, "user")) { ... queue_insert_tail(&B.account_q, &acc->node); }
    return 0;
}
```
TO:
```c
static int
_broker_config(void *ud, const char *section, const char *key, const char *value) {
    mqtt_broker_t *b = (mqtt_broker_t *)ud;
    (void)value;
    if (!value) return 0;
    LOG_D("[%s] %s = %s", section, key, value);
    if (!strcmp(section, "log")) { ... }
    if (!strcmp(section, "net")) {
        if (!strcmp(key, "host")) { b->host = strdup(value); }
        else if (!strcmp(key, "port")) { b->port = atoi(value); }
        else if (!strcmp(key, "max_connections")) { b->max_connections = atoi(value); }
        else if (!strcmp(key, "max_packet_size")) { b->max_packet_size = (size_t)atoi(value); }
        else if (!strcmp(key, "cert_file")) { b->cert_file = strdup(value); }
        else if (!strcmp(key, "key_file")) { b->key_file = strdup(value); }
    }
    if (!strcmp(section, "rate")) {
        if (!strcmp(key, "limit")) { b->rate_limit = atoi(value); }
    }
    if (!strcmp(section, "auth")) { ... }
    if (!strcmp(section, "user")) { ... queue_insert_tail(&b->account_q, &acc->node); }
    return 0;
}
```

#### 2k: mqtt_broker_init → mqtt_broker_create (line ~1989-2009)
FROM:
```c
static int
mqtt_broker_init(uv_loop_t *loop, int argc, char *argv[]) {
    B.loop = loop;
    B.t_now = 0;
    B.host = "0.0.0.0";
    B.port = 1883;
    queue_init(&B.client_q);
    queue_init(&B.msg_q);
    queue_init(&B.account_q);
    map_init(&B.session_m, _mqtt_session_client_id_key, _mqtt_session_client_id_cmp);
    B.sub_root = mqtt_trie_create(0, 0);
    if (argc > 1 && ini_parse(argv[1], _broker_config, 0)) {
        LOG_E("config file %s parse error", argv[1]);
        return -1;
    }
    snowflake_init(&B.snowflake, 0, 0);
    return 0;
}
```
TO:
```c
static mqtt_broker_t *
mqtt_broker_create(const mqtt_broker_config_t *config, uv_loop_t *loop) {
    mqtt_broker_t *b;
    b = (mqtt_broker_t *)calloc(1, sizeof(*b));
    b->loop = loop;
    b->t_now = 0;
    b->host = config->host ? strdup(config->host) : "0.0.0.0";
    b->port = config->port;
    b->max_connections = config->max_connections;
    b->max_packet_size = config->max_packet_size;
    b->rate_limit = config->rate_limit;
    b->auth_type = config->auth_type ? strdup(config->auth_type) : NULL;
    b->auth_api = config->auth_api ? strdup(config->auth_api) : NULL;
    b->auth_callback = NULL;
    b->auth_ud = config->ud;
    if (config->tls_enabled && config->cert_file && config->key_file) {
        b->tls_ctx = tls_server_ctx(config->cert_file, config->key_file);
    }
    queue_init(&b->client_q);
    queue_init(&b->msg_q);
    queue_init(&b->account_q);
    map_init(&b->session_m, _mqtt_session_client_id_key, _mqtt_session_client_id_cmp);
    b->sub_root = mqtt_trie_create(0, 0);
    b->connections = 0;
    b->shutdown_pending = 0;
    b->pending_clients = 0;
    b->trie_dump_enabled = 0;
    snowflake_init(&b->snowflake, 0, 0);
    if (config->users && config->user_count > 0) {
        int i;
        for (i = 0; i < config->user_count; i++) {
            mqtt_account_t *acc = (mqtt_account_t *)malloc(sizeof(*acc));
            mqtt_str_dup(&acc->username, &config->users[i].user[0]);
            mqtt_str_dup(&acc->password, &config->users[i].pass[0]);
            mqtt_str_dup(&acc->client_id, &config->users[i].client_id[0]);
            queue_insert_tail(&b->account_q, &acc->node);
        }
    }
    (void)ini_parse; (void)_broker_config;  /* Will be implemented in config module */
    return b;
}
```

And add mqtt_broker_destroy:
```c
static void
mqtt_broker_destroy_internal(mqtt_broker_t *b) {
    map_node_t *node, *next;
    queue_t *qnode, *qnext;
    int i;
    if (!b) return;
    /* Free sessions */
    map_foreach_safe(node, next, &b->session_m) {
        mqtt_session_t *s = map_data(node, mqtt_session_t, node);
        mqtt_broker_remove_session(s);  /* We'll fix this separately */
        mqtt_session_destroy(s);
    }
    map_destroy(&b->session_m);  /* Using map.h destroy */
    /* Free clients */
    queue_foreach_safe(qnode, qnext, &b->client_q) {
        mqtt_client_t *c = queue_data(qnode, mqtt_client_t, node);
        mqtt_broker_remove_client(c);
        mqtt_client_destroy(c);
    }
    /* Free accounts */
    queue_foreach_safe(qnode, qnext, &b->account_q) {
        mqtt_account_t *acc = queue_data(qnode, mqtt_account_t, node);
        mqtt_str_free(&acc->username);
        mqtt_str_free(&acc->password);
        mqtt_str_free(&acc->client_id);
        free(acc);
    }
    /* Free trie */
    /* ... complex — will be handled in pubsub module */
    mqtt_trie_destroy(b->sub_root);
    /* Free strings */
    free(b->host);
    free(b->auth_type);
    free(b->auth_api);
    if (b->tls_ctx) tls_ctx_destroy(b->tls_ctx);
    free(b);
}
```

NOTE: The destroy function is complex. For now, just make sure it compiles. The full destroy will be done in a later task.

#### 2l: main() — rewrite to use new API
FROM:
```c
int main(int argc, char *argv[]) {
    uv_loop_t *loop;
    uv_tcp_t server;
    uv_timer_t timer;
    struct sockaddr_in addr;
    int rc;
    signal(SIGPIPE, SIG_IGN);
    loop = uv_default_loop();
    if (mqtt_broker_init(loop, argc, argv)) { ... return EXIT_FAILURE; }
    uv_tcp_init(loop, &server);
    ...
    return uv_run(loop, UV_RUN_DEFAULT);
}
```
TO:
```c
int main(int argc, char *argv[]) {
    uv_loop_t *loop;
    mqtt_broker_config_t config;
    mqtt_broker_t *b;
    int rc;

    signal(SIGPIPE, SIG_IGN);
    loop = uv_default_loop();

    mqtt_broker_config_init(&config);
    if (argc > 1) {
        /* TODO: parse config file — will be implemented in config module */
        (void)argv[1];
    }
    b = mqtt_broker_create(&config, loop);
    if (!b) {
        fprintf(stderr, "mqtt_broker_create failed\n");
        return EXIT_FAILURE;
    }

    rc = mqtt_broker_start(b);
    if (rc) {
        fprintf(stderr, "mqtt_broker_start failed\n");
        mqtt_broker_destroy(b);
        return EXIT_FAILURE;
    }

    LOG_I("mqtt broker at %s:%d started", config.host, config.port);
    mqtt_broker_run(b);
    mqtt_broker_stop(b);
    mqtt_broker_destroy(b);
    return EXIT_SUCCESS;
}
```

IMPORTANT: Add these new forward declarations before main:
```c
/* mqtt_broker.c — lifecycle */
int mqtt_broker_start(mqtt_broker_t *b);
void mqtt_broker_stop(mqtt_broker_t *b);
int mqtt_broker_run(mqtt_broker_t *b);
void mqtt_broker_destroy(mqtt_broker_t *b);
```

### Step 3: All remaining B.xxx replacements

For every function you haven't touched yet, simply do a find-and-replace:
- `B.xxx` → `b->xxx`
- Add `mqtt_broker_t *b` to function signature if needed

Here is the FULL list of `B.xxx` references you need to handle:

| Line | Original | Replacement |
|------|----------|-------------|
| 297 | `B.t_now` | Add `b` param to function, use `b->t_now` |
| 378 | `B.t_now` | See 2e above |
| 597 | `B.sub_root` | Add `b` param, use `b->sub_root` |
| 634, 655, 667, 674, 683 | (dispatch calls) | See 2g/2h |
| 697 | `B.sub_root` | See 2g/2h |
| 704 | `B.sub_root` | See 2g/2h |
| 709, 714 | `B.sub_root` | See 2g/2h |
| 789 | `B.client_q` | Add `b` param, use `b->client_q` |
| 799 | `B.session_m` | Add `b` param, use `b->session_m` |
| 809 | `B.session_m` | Add `b` param, use `b->session_m` |
| 827 | `B.sub_root` | Add `b` param, use `b->sub_root` |
| 880 | `B.sub_root` | Add `b` param, use `b->sub_root` |
| 924 | `B.sub_root` | Add `b` param, use `b->sub_root` |
| 954, 959, 960, 966 | `B.msg_q`, `B.idle` | See 2g above |
| 974, 975, 977 | `B.msg_q`, `B.idle` | See 2h above |
| 1007 | `snowflake_id(&B.snowflake)` | See 2k above |
| 1070 | `B.account_q` | See 2j above |
| 1186 | `B.auth_api` | See 2j above |
| 1219 | `B.auth_type` | Add `b` param to mqtt_client_authenticate |
| 1222-1224 | `B.auth_type` | See 2j above |
| 1623 | `res->p.unsuback.v5.n` | No change (already fixed) |
| 1820 | `B.t_now` | See 2f above |
| 1916-1926 | `B.t_now`, `B.client_q` | See 2i above |
| 1931, 1958, 1960, 1968, 1978, 1983 | `B.xxx` | See 2j above |
| 1991 | `B.loop` | See 2k above |
| 1992-2001 | `B.xxx` | See 2k above |
| 2012-2052 (main) | `B.xxx` | See 2l above |

### Step 4: Compilation verification

After all changes, compile:
```bash
cd /Users/zhoukk/k/kmq/build && cmake .. >/dev/null 2>&1 && make mqtt_broker 2>&1
```

Fix any compilation errors. Key patterns:
- Missing function parameters
- Undefined `b` in a function
- `mqtt_broker_destroy` vs `mqtt_broker_destroy_internal` naming
- Map/queue iteration syntax

### Step 5: Commit

```bash
cd /Users/zhoukk/k/kmq
git add mqtt_broker.c
git commit -m "refactor: remove global singleton, migrate to mqtt_broker_t * parameter"
```

### Important Notes
- This is a MASSIVE refactoring of a 2052-line file. Be thorough.
- For functions that call other functions, make sure the `b` parameter is threaded through correctly.
- If a function doesn't reference B, it doesn't need changes.
- Keep the same function logic — only change B.xxx → b->xxx and add parameters.
- The destroy function is complex; make sure it at least compiles, full implementation can come later.
- Add `#include "tls.h"` and `#include <stdlib.h>` if needed (calloc).

### Status
Report your status as: DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, or BLOCKED.
