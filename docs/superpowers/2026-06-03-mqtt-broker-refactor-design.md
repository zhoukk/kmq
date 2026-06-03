# MQTT Broker 生产级重构设计

## 目标

将现有 2052 行 `mqtt_broker.c` 重构为适合 5000+ 连接生产环境的架构。

## 改造清单

| 问题 | 改造方案 |
|------|----------|
| 全局单例 `static mqtt_broker_t B` | 改为 `mqtt_broker_t` struct，所有操作取 `broker` 参数 |
| 2052 行单文件 | 拆分为 8 个模块 |
| 无 TLS 支持 | 集成已有 `tls.h`，transport 层抽象 |
| 同步阻塞 HTTP 认证 | 改为 callback + async 模型 |
| `mqtt_trie_dump` 热路径 | 配置开关，默认关闭 |
| 无连接数限制 | 配置 `max_connections`，超限拒绝 |
| 无速率限制 | 每客户端消息速率限制 |
| 无包大小限制 | 限制最大包大小，防止内存攻击 |
| 无优雅关闭 | uv_close + pending count 机制 |
| auth_api 路径依赖 http_parser | 提取 auth 为 callback 接口 |
| 硬编码 ini 配置 | 支持 ini + CLI 参数 |

## 模块划分

### 文件结构

```
mqtt_broker.h        — 公共头文件，所有公开 API
mqtt_broker.c        — Broker 生命周期管理 (init/start/stop/事件循环)
mqtt_tls.c           — TLS 传输层集成 (基于已有 tls.h)
mqtt_session.c       — Session 管理 (创建/销毁/incoming/outgoing publications)
mqtt_client.c        — 客户端管理 (创建/销毁/读写/auth)
mqtt_pubsub.c        — 主题树 + 发布/订阅/消息分发
mqtt_auth.c          — 认证抽象 (config 认证 / HTTP 回调)
mqtt_config.c        — 配置解析 (ini + CLI)
mqtt_broker_main.c   — main() 入口
```

### 模块依赖关系

```
mqtt_broker.h (核心类型定义)
    ↑
mqtt_broker.c ──→ mqtt_tls.c
               ├──→ mqtt_session.c
               ├──→ mqtt_client.c
               ├──→ mqtt_pubsub.c
               ├──→ mqtt_auth.c
               ├──→ mqtt_config.c
               └──→ mqtt_broker_main.c
```

### 公共 API 设计

```c
// === 配置 ===
typedef struct {
    char *host;
    int port;
    int max_connections;
    int max_packet_size;       // 最大包大小 (字节)
    char *cert_file;           // TLS cert
    char *key_file;            // TLS key
    int tls_enabled;

    // Auth config
    char *auth_type;           // "config" or "api"
    char *auth_api;
    char *auth_callback;       // 通用 callback 函数指针

    // 日志
    int log_level;
    char *log_file;

    // 每客户端速率限制 (msgs/sec, 0 = 不限制)
    int rate_limit;

    // 用户表 (config 认证用)
    struct { char *user; char *pass; char *client_id; } users[];
    int user_count;

    void *auth_ud;             // auth callback 用户数据
} mqtt_broker_config_t;

// === 回调接口 ===
typedef int (*mqtt_auth_callback_pt)(mqtt_broker_t *broker, const char *client_id,
                                     const char *username, const char *password,
                                     void *ud);

// === 生命周期 ===
mqtt_broker_t *mqtt_broker_create(const mqtt_broker_config_t *config, uv_loop_t *loop);
int mqtt_broker_start(mqtt_broker_t *broker);
void mqtt_broker_stop(mqtt_broker_t *broker);
void mqtt_broker_destroy(mqtt_broker_t *broker);

// === 事件循环 (由 main 调用) ===
int mqtt_broker_run(mqtt_broker_t *broker);

// === 事件回调注册 ===
void mqtt_broker_set_auth_callback(mqtt_broker_t *broker, mqtt_auth_callback_pt cb, void *ud);
```

### mqtt_broker_t 核心结构

```c
struct mqtt_broker_s {
    uv_loop_t *loop;
    uv_tcp_t server;           // TCP/TLS 监听
    uv_idle_t idle;            // 消息分发 idle
    uv_timer_t timer;          // keepalive 定时器

    // 配置
    int max_connections;
    int max_packet_size;
    int tls_enabled;
    char *cert_file;
    char *key_file;
    int rate_limit;

    // 认证
    char *auth_type;
    char *auth_api;
    mqtt_auth_callback_pt auth_callback;
    void *auth_ud;

    // 用户表 (config 认证)
    queue_t account_q;

    // 核心数据
    mqtt_trie_t *sub_root;     // 主题订阅树
    map_t session_m;           // client_id → session
    queue_t client_q;          // 所有客户端列表
    queue_t msg_q;             // 待分发消息队列
    snowflake_t snowflake;     // 自动生成 client_id

    // 连接控制
    int connections;           // 当前连接数
    uint64_t t_now;            // 当前时间 (秒)

    // TLS
    tls_ctx_t *tls_ctx;
};
```

### Transport 抽象

利用已有 `tls.h`，统一 `uv_stream_t` 接口：

- 非 TLS: 直接用 `uv_tcp_t` 的 read/write/close
- TLS: `uv_tcp_t` 接收数据 → `tls_feed()` 解密 → 交给 MQTT parser；
        MQTT packet → `tls_write()` 加密 → `uv_tcp_t` 发送

客户端结构新增 `tls_t *tls` 字段，根据连接时 TLS 状态选择处理路径。

### 认证重构

现有 `_authenticate_from_httpapi()` 是同步阻塞的（手动 TCP + send/recv），在 uv 事件循环中会阻塞所有客户端。

改为 callback 模型：

```c
// 内部认证入口
static int broker_auth_client(mqtt_broker_t *b, mqtt_client_t *c, mqtt_p_connect_t *connect) {
    if (b->auth_type == NULL) return 0;

    if (!strcmp(b->auth_type, "config")) {
        return _auth_config(b, connect);
    }

    // 所有其他方式走 callback（包括 HTTP API）
    if (b->auth_callback) {
        return b->auth_callback(b, connect, b->auth_ud);
    }

    return -1; // 未配置认证方式
}
```

外部使用者可以传入自己的 HTTP 认证 callback：

```c
static int my_auth(mqtt_broker_t *broker, mqtt_p_connect_t *conn, void *ud) {
    // 自己的异步 HTTP 请求逻辑
    // 可以直接返回 (同步) 或存队列后回调 (异步)
    return 0; // 或 -1
}

mqtt_broker_set_auth_callback(broker, my_auth, my_context);
```

### 限制机制

1. **连接数限制**: `mqtt_broker_on_connection()` 中检查 `broker->connections >= broker->max_connections`，超限直接 `uv_close`
2. **包大小限制**: `mqtt_client_data()` 中检查接收 buffer 不超过 `max_packet_size`
3. **速率限制**: `mqtt_client_t` 新增令牌桶字段，每个客户端独立计数

### 消息分发

保持现有 `msg_q` + idle 分发模型不变，该设计良好。

### 配置

支持 ini 文件 + CLI 参数两种方式，ini 优先。

```
# broker.ini
[log]
level=info
file=/var/log/mqtt_broker.log

[net]
host=0.0.0.0
port=1883
max_connections=10000
max_packet_size=65536
cert_file=broker.crt
key_file=broker.key

[auth]
type=api
api=http://127.0.0.1:8080/api/auth

[rate]
limit=100  # msgs/sec per client
```
