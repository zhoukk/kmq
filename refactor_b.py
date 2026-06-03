#!/usr/bin/env python3
"""
Refactor mqtt_broker.c from global singleton B to struct-based broker parameter.
This script does mechanical replacements only; manual adjustments needed for call sites.
"""
import re
import sys

with open('/Users/zhoukk/k/kmq/mqtt_broker.c', 'r') as f:
    lines = f.readlines()

output = []
i = 0
while i < len(lines):
    line = lines[i]

    # 1. Add mqtt_broker.h include after #define MQTT_BROKER_IMPL
    if line.strip() == '#define MQTT_BROKER_IMPL' and i + 1 < len(lines) and 'mqtt.h' in lines[i+1]:
        output.append(line)
        output.append('#include "mqtt_broker.h"\n')
        i += 1
        continue

    # 2. Replace struct mqtt_broker_s definition
    if re.match(r'struct mqtt_broker_s\s*{\s*$', line):
        # Write new struct definition
        output.append('struct mqtt_broker_s {\n')
        output.append('    uv_loop_t *loop;\n')
        output.append('    uv_tcp_t server;\n')
        output.append('    uv_idle_t idle;\n')
        output.append('    uv_timer_t timer;\n')
        output.append('    mqtt_trie_t *sub_root;\n')
        output.append('    char *host;\n')
        output.append('    int port;\n')
        output.append('    char *auth_type;\n')
        output.append('    char *auth_api;\n')
        output.append('    mqtt_broker_auth_callback_t auth_callback;\n')
        output.append('    void *auth_ud;\n')
        output.append('    int t_now;\n')
        output.append('    snowflake_t snowflake;\n')
        output.append('    queue_t client_q;\n')
        output.append('    map_t session_m;\n')
        output.append('    queue_t msg_q;\n')
        output.append('    queue_t account_q;\n')
        output.append('    int max_connections;\n')
        output.append('    int connections;\n')
        output.append('    size_t max_packet_size;\n')
        output.append('    int rate_limit;\n')
        output.append('    tls_ctx_t *tls_ctx;\n')
        output.append('    int shutdown_pending;\n')
        output.append('    int pending_clients;\n')
        output.append('    int trie_dump_enabled;\n')
        output.append('};\n')
        # Skip old struct definition
        brace_count = 1
        i += 1
        while i < len(lines) and brace_count > 0:
            brace_count += lines[i].count('{')
            brace_count -= lines[i].count('}')
            i += 1
        continue

    # 3. Remove static mqtt_broker_t B = {0};
    if 'static mqtt_broker_t B = {0}' in line:
        i += 1
        continue

    # 4. Replace B.t_now in assignments
    if 'B.t_now' in line and '=' in line and 'B.t_now' not in line.split('#')[0]:
        line = line.replace('B.t_now', 'b->t_now')

    # 5. Replace B.xxx in function definitions and calls
    # We need to add mqtt_broker_t *b to function signatures where needed

    output.append(line)
    i += 1

with open('/Users/zhoukk/k/kmq/mqtt_broker.c', 'w') as f:
    f.writelines(output)

print(f"Processed {len(lines)} lines -> {len(output)} lines")
print("Done with mechanical replacements. Manual review needed.")
