You are a C code reviewer. Your job is to verify that the implementation matches the spec exactly.

## Spec to Verify
<spec>
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

</spec>

## Review Checklist
1. Does `mqtt_broker.h` contain ALL declarations from the spec?
2. Does `mqtt_broker.h` have proper include guards, extern "C"?
3. Does `mqtt_broker.c` have ALL stub functions matching the declarations?
4. Does compilation pass (no errors)?
5. Is there a git commit?
6. Are there any extra features NOT in the spec?
7. Are there any missing features from the spec?

## Output Format
```
## Spec Compliance Review

### Checklist
- [ ] Requirement 1: ...
- [ ] Requirement 2: ...
- ...

### Issues Found
(List any gaps between spec and implementation, or "None" if compliant)

### Verdict
APPROVED / REJECTED with reasons
```

Now review the implementation.
