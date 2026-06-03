You are a C implementation subagent. Your goal is to implement ONE specific task from the plan.

## Context
Project: mqk — a lightweight MQTT broker library and toolset.
Working directory: /Users/zhoukk/k/kmq/

## Task Instructions
Read the plan below carefully. Implement ONLY the task described. Do NOT implement other tasks.

<plan>
# MQTT Broker 生产级重构 Implementation Plan

## Task 1: 创建 `mqtt_broker.h` 公共头文件

**Files:**
- Create: `mqtt_broker.h`

**Step 1: 编写头文件**

```c
/*
 * mqtt_broker.h — 生产级 MQTT Broker 公共接口
 * 基于 libuv 异步 I/O，支持 MQTT 5.0 / 3.1.1
 */

#ifndef _MQTT_BROKER_H_
#define _MQTT_BROKER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "mqtt.h"       /* 已有：协议栈类型 mqtt_str_t, mqtt_packet_t, mqtt_qos_t 等 */
#include "snowflake.h"  /* 已有：雪花ID生成 */
#include "uv.h"         /* libuv */
#include <stdint.h>
#include <stddef.h>

/* ================================================================== */
/* 配置                                                               */
/* ================================================================== */

#define MQTT_BROKER_DEFAULT_PORT             1883
#define MQTT_BROKER_DEFAULT_MAX_CONN         4096
#define MQTT_BROKER_DEFAULT_MAX_PACKET_SIZE  (64 * 1024)   /* 64 KB */
#define MQTT_BROKER_DEFAULT_RATE_LIMIT       0             /* 0 = 不限制 */
#define MQTT_BROKER_DEFAULT_HEARTBEAT_MS     1000

typedef struct {
    /* 网络 */
    const char *host;           /* 默认 "0.0.0.0" */
    int port;                   /* 默认 MQTT_BROKER_DEFAULT_PORT */
    int max_connections;        /* 默认 MQTT_BROKER_DEFAULT_MAX_CONN */
    size_t max_packet_size;     /* 默认 MQTT_BROKER_DEFAULT_MAX_PACKET_SIZE */
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
} mqtt_broker_config_t;

static inline void mqtt_broker_config_init(mqtt_broker_config_t *c) {
    memset(c, 0, sizeof(*c));
    c->host = "0.0.0.0";
    c->port = MQTT_BROKER_DEFAULT_PORT;
    c->max_connections = MQTT_BROKER_DEFAULT_MAX_CONN;
    c->max_packet_size = MQTT_BROKER_DEFAULT_MAX_PACKET_SIZE;
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
mqtt_broker_t *mqtt_broker_create(const mqtt_broker_config_t *config, uv_loop_t *loop);
int            mqtt_broker_start(mqtt_broker_t *b);
void           mqtt_broker_stop(mqtt_broker_t *b);
void           mqtt_broker_destroy(mqtt_broker_t *b);
int            mqtt_broker_run(mqtt_broker_t *b);

/* 事件注册 */
void mqtt_broker_set_auth_callback(mqtt_broker_t *b, mqtt_broker_auth_callback_t cb, void *ud);

#ifdef __cplusplus
}
#endif

#endif /* _MQTT_BROKER_H_ */
```

- [ ]

**Step 2: 创建桩实现确保编译通过**

`mqtt_broker.c`（桩）：

```c
#define MQTT_BROKER_IMPL
#include "mqtt_broker.h"

mqtt_broker_t *mqtt_broker_create(const mqtt_broker_config_t *config, uv_loop_t *loop) {
    (void)config; (void)loop;
    return NULL;
}
int mqtt_broker_start(mqtt_broker_t *b) { (void)b; return -1; }
void mqtt_broker_stop(mqtt_broker_t *b)  { (void)b; }
void mqtt_broker_destroy(mqtt_broker_t *b){ (void)b; }
int  mqtt_broker_run(mqtt_broker_t *b)    { (void)b; return 0; }
void mqtt_broker_set_auth_callback(mqtt_broker_t *b, mqtt_broker_auth_callback_t cb, void *ud) {
    (void)b; (void)cb; (void)ud;
}
```

- [ ]

**Step 3: 编译验证**

```bash
cd build && cmake .. && make mqtt_broker 2>&1 | grep -i error || echo "OK"
```

- [ ]

**Step 4: Commit**

```bash
git add mqtt_broker.h mqtt_broker.c
git commit -m "init: add mqtt_broker.h public API with stub implementations"
```

- [ ]

</plan>

## Implementation Rules
1. Use TDD approach — write the implementation first, then verify with compilation
2. For C projects: verify with `cd build && cmake .. && make mqtt_broker`
3. If compilation fails, fix the errors before completing
4. Commit your work with a descriptive commit message
5. Report status as: DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, or BLOCKED
6. If you need additional context about the codebase, ASK QUESTIONS before implementing

## Questions You Can Ask
- What does a specific function do?
- How is a certain struct used?
- What's the project's coding style?
- Any existing patterns I should follow?

## Your Deliverable
1. Complete implementation per the task specification
2. Compilation verification (pass)
3. Git commit
4. Self-review notes (any concerns, improvements made)

Now implement this task.
