# AGENTS.md

kmq: C11 MQTT 3.1.1/5.0 broker + MQTT-SN gateway + sample clients, derived from
[zhoukk/mqtt](https://github.com/zhoukk/mqtt). Single flat directory, CMake build,
libuv + OpenSSL. No test framework — the `*_test` binaries are standalone executables.

## Build

```sh
cmake -B build && cmake --build build
```

- Requires `libuv` (found via pkg-config) and OpenSSL dev headers. On Ubuntu:
  `sudo apt install libuv1-dev libssl-dev`.
- Compiles with `-Wall -Werror -Wextra` — any new warning breaks the build.
- Prebuilt binaries in `build/` may be from another machine (e.g. linked against
  `libssl.so.1.1`) and fail to run here; rebuild before running.
- `Dockerfile` is stale: it references autotools (`autogen.sh`/`configure`) and the
  removed `mqtt_proxy` target. CMakeLists.txt is the source of truth.

## Binaries

| binary | purpose |
|---|---|
| `mqtt_broker <ini>` | libuv broker; TCP/TLS/WS/WSS, MQTT 3.1.1 + 5.0 |
| `mqtt_sn_gateway <ini>` | UDP:1884 MQTT-SN gateway, joins multicast 225.1.1.1:1884, bridges to broker at 127.0.0.1:1883 (upstream hardcoded; ini only supports `[log]` and `[net]`) |
| `mqtt_pub` / `mqtt_sub` | MQTT clients (`--help` for flags; default host 127.0.0.1:1883) |
| `mqtt_sn_pub` / `mqtt_sn_sub` | MQTT-SN clients (UDP) |
| `mqtt_test` | offline parser fuzz: 2x10k random MQTT + MQTT-SN parses + mempool leak check. No network, safe to run anytime |
| `mqtt_cli_test` | needs a running broker on 127.0.0.1:1883; connect→sub→pub→unsub→disconnect |
| `mqtt_sn_cli_test` | needs a running `mqtt_sn_gateway`; full MQTT-SN advertise/search/gwinfo flow |

### broker.ini sections

- `[log]` level, file
- `[net]` host, port — default TCP listener
- `[auth]` type=`config`|`api`, api=`<url>` (HTTP auth endpoint)
- `[user]` key=username, value=`password,client_id` (`*` = any client id). Password
  may be plaintext or `sha256:<hex>` (case-insensitive hex) for hashed storage.
- `[acl]` key=username (`*` = all users), value=`topic,access` (access=`pub|sub|rw|deny`).
  Split on the LAST comma. Empty section = ACL disabled (allow all). A matching `deny`
  rule overrides any allow; no matching rule for an action = allow. Enforced on
  PUBLISH (topic name) and SUBSCRIBE (topic filter); denial disconnects (v3.x) or
  returns reason 0x87 NOT_AUTHORIZED (v5).
- `[listener-<id>]` mode=`tcp`|`tls`|`ws`|`wss`, host, port, cert, key, auth, api —
  multiple listeners per broker (this replaced the removed `mqtt_proxy`). `auth`/`api`
  override the global `[auth]` for that listener.
- `[limit]` max_connections, max_packet_size (bytes, parser-enforced),
  rate_limit (PUBLISH msg/s per client, 0 = off; violation disconnects the client),
  max_write_pending (per-client socket write-queue bytes before backpressure, 0 = off)
- `[debug]` trie_dump=1 — dump the subscription trie on sub/unsub/retain
- `[sys]` interval (seconds, 0 = off) — publish `$SYS/broker/*` stats topics
- `[persist]` file=`<path>` — persist retained messages, sessions (expiry),
  subscriptions, wills, and offline queues to a hex-encoded text file (magic
  `KMQLP1`). Loaded at startup, written atomically (`.tmp`+rename) when dirty
  (on the 1s timer tick and at clean shutdown). Omit the section to disable.

Broker behavior notes:
- In-flight QoS1/2 publications are retransmitted (dup=1) after `keep_alive`
  seconds without an ack; SIGTERM/SIGINT drain clients (v5 gets DISCONNECT 0x8B)
  and exit, will messages are NOT published on server shutdown.
- MQTT 5 features: v5 PUBLISH properties are passed through to subscribers;
  Topic Alias (both directions); Session Expiry (persistent sessions keep
  subscriptions + an offline message queue, delivered on reconnect); Will Delay;
  Subscription Identifier; `$share/group/filter` shared subscriptions (round-robin
  across group members); CONNACK advertises server capabilities (receive maximum,
  max packet size, max QoS, retained/wildcard/shared/sub-id available, topic alias max).
- Backpressure: when a client's pending socket writes exceed `max_write_pending`,
  new PUBLISHes are buffered in its offline queue and retried on the next tick.
- MQTT 5 AUTH packet: with no `auth_callback` it is a no-op that replies
  AUTH reason 0x00; with a callback it is dispatched as `cb(client_id, method,
  data)` (method/data from the Auth Method/Data properties) and a non-zero
  result disconnects with 0x87 NOT_AUTHORIZED.
- Fixed-header / options bitfields MUST match the wire format: PUBLISH byte is
  bit0=RETAIN, bits1-2=QoS, bit3=DUP, bits4-7=type (MQTT 3.1.1 §2.2.2/§3.3.1); SUBSCRIBE options byte is
  bits2-3=QoS, bit4=No Local, bit5=RAP, bits6-7=Retain Handling (bits0-1
  reserved). `__mqtt_packet_free` NULLs the array pointers it frees so a parse
  failure after allocation cannot double-free on `mqtt_parser_unit`.

### Running the test clients

`broker.ini` in the repo has `[auth] type=config` with users `test_user`/`test_pass`
and `test_kmq`/`pwd@test_kmq`, but `mqtt_cli_test` hardcodes `mqtt_cli`/`123456` and
will be rejected. Run the broker with an ini that omits `[auth]` (or matching users):

```sh
./build/mqtt_broker my.ini &        # no [auth] section
./build/mqtt_cli_test               # expect: connack, suback, publish, puback, unsuback
./build/mqtt_pub -t demo/hello -m "hi" -q 1
./build/mqtt_sub -t demo/hello
```

## Architecture

- Header-impl pattern: each `.h` contains its implementation, enabled by defining an
  `*_IMPL` macro before including (`MQTT_IMPL`, `MQTT_CLI_IMPL`,
  `MQTT_CLI_NETWORK_IMPL`, `MQTT_SN_CLI_IMPL`, `MQTT_MEMPOOL_IMPL`, `INI_IMPL`,
  `LOG_IMPL`, `TLS_IMPL`, `WEBSOCKET_IMPL`, `HTTP_IMPL`, `SNOWFLAKE_IMPL`, ...).
  A `.c` file picks which implementations it compiles in.
- `mqtt.h` (~4900 lines) is the monolith: all MQTT + MQTT-SN packet types, parsers,
  encode/decode. `mqtt_cli.h` / `mqtt_sn_cli.h` are the client state machines.
- `mqtt_broker.c` is fully self-contained (single file: config/listener types,
  API, full broker impl, `main`): topic trie for subscriptions, session map keyed
  by client id, snowflake ids.
- Hot-path allocations (mqtt.h strings, packet buffers, properties) go through the
  `mqtt_mempool` slab allocator: `main()` calls `mqtt_set_allocator` with pool
  adapters before config parsing, so `MQTT_MALLOC`/`MQTT_FREE` are pool-backed.
  Consequence: any buffer freed via `mqtt_str_free`/`MQTT_FREE` MUST be allocated
  with `MQTT_MALLOC` (a plain `malloc` there leaks, since the pool free can't find
  it). Fixed-size broker structs (client/session/message, etc.) still use `malloc`.
- `rbtree.c`, `http_parser.c` (nginx-derived) are vendored support code;
  `http_parser` is used for WebSocket upgrade and the HTTP auth API.

## Conventions

- `.clang-format`: 4-space indent, 120 cols, braces attached, pointer alignment right
  (`char *s`).
- Commit style: conventional (`fix:`, `refactor:`, `chore:`, `docs:`).
- `build/` is gitignored.
