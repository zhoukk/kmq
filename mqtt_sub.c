/*
 * mqtt_sub.c -- sample mqtt client subscribe topic.
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

#define MQTT_CLI_NETWORK_IMPL
#define MQTT_CLI_IMPL
#include "mqtt_cli.h"

static char *host = 0;
static int port = MQTT_TCP_PORT;
static int debug = 0;
static int quiet = 0;
static int verbose = 0;
static int msg_count = 0;
static int msg_cnt = 0;
static int no_retain = 0;
static int eol = 1;

static char *client_id = 0;
static char *client_id_prefix = 0;
static char *username = 0;
static char *password = 0;
static int proto_ver = MQTT_VERSION_4;
static int keepalive = 60;
static int clean_session = 1;

static int qos = MQTT_QOS_0;
static int topic_count = 0;
static char **topics = 0;

static int will_qos = 0;
static int will_retain = 0;
static char *will_topic = 0;
static char *will_message = 0;
static int will_length = 0;

static void
usage(void) {
    printf(
        "mqtt_sub is a simple mqtt client that will subscribe to a single topic and print all messages it receives.\n");
    printf("Usage: mqtt_sub [-c] [-h host] [-k keepalive] [-p port] [-q qos] [-R] -t topic ...\n");
    printf("                     [-C msg_count] [-T filter_out]\n");
    printf("                     [-i id] [-I id_prefix]\n");
    printf("                     [-d] [-N] [--quiet] [-v]\n");
    printf("                     [-u username [-P password]]\n");
    printf("                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]\n");
    printf("       mqtt_sub --help\n\n");
    printf(" -c : disable 'clean session' (store subscription and pending messages when client disconnects).\n");
    printf(" -C : disconnect and exit after receiving the 'msg_count' messages.\n");
    printf(" -d : enable debug messages.\n");
    printf(" -h : mqtt host to connect to. Defaults to localhost.\n");
    printf(" -i : id to use for this client. Defaults to mqtt_sub_ appended with the process id.\n");
    printf(" -I : define the client id as id_prefix appended with the process id. Useful for when the\n");
    printf("      broker is using the clientid_prefixes option.\n");
    printf(" -k : keep alive in seconds for this client. Defaults to 60.\n");
    printf(" -N : do not add an end of line character when printing the payload.\n");
    printf(" -p : network port to connect to. Defaults to 1883.\n");
    printf(" -P : provide a password (requires MQTT broker)\n");
    printf(" -q : quality of service level to use for the subscription. Defaults to 0.\n");
    printf(" -R : do not print stale messages (those with retain set).\n");
    printf(" -t : mqtt topic to subscribe to. May be repeated multiple times.\n");
    printf(" -T : topic string to filter out of results. May be repeated.\n");
    printf(" -u : provide a username (requires MQTT broker)\n");
    printf(" -v : print published messages verbosely.\n");
    printf(" -V : specify the version of the MQTT protocol to use when connecting.\n");
    printf("      Can be mqttv31, mqttv311 or mqttv50. Defaults to mqttv311.\n");
    printf(" --help : display this message.\n");
    printf(" --quiet : don't print error messages.\n");
    printf(" --will-payload : payload for the client Will, which is sent by the broker in case of\n");
    printf("                  unexpected disconnection. If not given and will-topic is set, a zero\n");
    printf("                  length message will be sent.\n");
    printf(" --will-qos : QoS level for the client Will.\n");
    printf(" --will-retain : if given, make the client Will retained.\n");
    printf(" --will-topic : the topic on which to publish the client Will.\n");
    printf("\nSee https://github.com/zhoukk/mqtt for more information.\n\n");
    exit(0);
}

static void
config(int argc, char *argv[]) {
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -p argument given but no port specified.\n\n");
                goto e;
            } else {
                port = atoi(argv[i + 1]);
                if (port < 1 || port > 65535) {
                    fprintf(stderr, "Error: Invalid port given: %d\n", port);
                    goto e;
                }
            }
            i++;
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
            debug = 1;
        } else if (!strcmp(argv[i], "-C")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -C argument given but no count specified.\n\n");
                goto e;
            } else {
                msg_count = atoi(argv[i + 1]);
                if (msg_count < 1) {
                    fprintf(stderr, "Error: Invalid message count \"%d\".\n\n", msg_count);
                    goto e;
                }
            }
            i++;
        } else if (!strcmp(argv[i], "--help")) {
            usage();
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--host")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -h argument given but no host specified.\n\n");
                goto e;
            } else {
                host = strdup(argv[i + 1]);
            }
            i++;
        } else if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--id")) {
            if (client_id_prefix) {
                fprintf(stderr, "Error: -i and -I argument cannot be used together.\n\n");
                goto e;
            }
            if (i == argc - 1) {
                fprintf(stderr, "Error: -i argument given but no id specified.\n\n");
                goto e;
            } else {
                client_id = strdup(argv[i + 1]);
            }
            i++;
        } else if (!strcmp(argv[i], "-I") || !strcmp(argv[i], "--id-prefix")) {
            if (client_id) {
                fprintf(stderr, "Error: -i and -I argument cannot be used together.\n\n");
                goto e;
            }
            if (i == argc - 1) {
                fprintf(stderr, "Error: -I argument given but no id prefix specified.\n\n");
                goto e;
            } else {
                client_id_prefix = strdup(argv[i + 1]);
            }
            i++;
        } else if (!strcmp(argv[i], "-k") || !strcmp(argv[i], "--keepalive")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -k argument given but no keepalive specified.\n\n");
                goto e;
            } else {
                keepalive = atoi(argv[i + 1]);
                if (keepalive > 65535) {
                    fprintf(stderr, "Error: Invalid keepalive given: %d\n", keepalive);
                    goto e;
                }
            }
            i++;
        } else if (!strcmp(argv[i], "-V") || !strcmp(argv[i], "--protocol-version")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: --protocol-version argument given but no version specified.\n\n");
                goto e;
            } else {
                if (!strcmp(argv[i + 1], "mqttv31")) {
                    proto_ver = MQTT_VERSION_3;
                } else if (!strcmp(argv[i + 1], "mqttv311")) {
                    proto_ver = MQTT_VERSION_4;
                } else if (!strcmp(argv[i + 1], "mqttv50")) {
                    proto_ver = MQTT_VERSION_5;
                } else {
                    fprintf(stderr, "Error: Invalid protocol version argument given.\n\n");
                    goto e;
                }
                i++;
            }
        } else if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--qos")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -q argument given but no QoS specified.\n\n");
                goto e;
            } else {
                qos = atoi(argv[i + 1]);
                if (qos < 0 || qos > 2) {
                    fprintf(stderr, "Error: Invalid QoS given: %d\n", qos);
                    goto e;
                }
            }
            i++;
        } else if (!strcmp(argv[i], "--quiet")) {
            quiet = 1;
        } else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--topic")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -t argument given but no topic specified.\n\n");
                goto e;
            } else {
                topic_count++;
                topics = realloc(topics, topic_count * sizeof(char *));
                if (!topics)
                    goto e;
                topics[topic_count - 1] = strdup(argv[i + 1]);
                i++;
            }
        } else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--username")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -u argument given but no username specified.\n\n");
                goto e;
            } else {
                username = strdup(argv[i + 1]);
            }
            i++;
        } else if (!strcmp(argv[i], "-P") || !strcmp(argv[i], "--pw")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -P argument given but no password specified.\n\n");
                goto e;
            } else {
                password = strdup(argv[i + 1]);
            }
            i++;
        } else if (!strcmp(argv[i], "--will-payload")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: --will-payload argument given but no will payload specified.\n\n");
                goto e;
            } else {
                will_message = strdup(argv[i + 1]);
                will_length = strlen(will_message);
            }
            i++;
        } else if (!strcmp(argv[i], "--will-qos")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: --will-qos argument given but no will QoS specified.\n\n");
                goto e;
            } else {
                will_qos = atoi(argv[i + 1]);
                if (will_qos < 0 || will_qos > 2) {
                    fprintf(stderr, "Error: Invalid will QoS %d.\n\n", will_qos);
                    goto e;
                }
            }
            i++;
        } else if (!strcmp(argv[i], "--will-retain")) {
            will_retain = 1;
        } else if (!strcmp(argv[i], "--will-topic")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: --will-topic argument given but no will topic specified.\n\n");
                goto e;
            } else {
                will_topic = strdup(argv[i + 1]);
            }
            i++;
        } else if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--disable-clean-session")) {
            clean_session = 0;
        } else if (!strcmp(argv[i], "-N")) {
            eol = 0;
        } else if (!strcmp(argv[i], "-R")) {
            no_retain = 1;
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            verbose = 1;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'.\n", argv[i]);
            goto e;
        }
    }
    return;

e:
    fprintf(stderr, "\nUse 'mqtt_sub --help' to see usage.\n");
    exit(0);
}

static void
_unsuback(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    (void)ud;
    (void)pkt;

    mqtt_cli_disconnect(m);
}

static void
_publish(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    (void)ud;

    if (pkt->f.bits.retain == 1 && no_retain == 1)
        return;
    if (verbose) {
        if (pkt->p.publish.message.n) {
            printf("%.*s ", MQTT_STR_PRINT(pkt->v.publish.topic_name));
            fwrite(pkt->p.publish.message.s, 1, pkt->p.publish.message.n, stdout);
            if (eol) {
                printf("\n");
            }
        } else {
            if (eol) {
                printf("%.*s (null)\n", MQTT_STR_PRINT(pkt->v.publish.topic_name));
            }
        }
        fflush(stdout);
    } else {
        if (pkt->p.publish.message.n) {
            fwrite(pkt->p.publish.message.s, 1, pkt->p.publish.message.n, stdout);
            if (eol) {
                printf("\n");
            }
            fflush(stdout);
        }
    }

    if (msg_count > 0) {
        msg_cnt++;
        if (msg_cnt == msg_count) {
            mqtt_cli_unsubscribe(m, topic_count, (const char **)topics, 0);
        }
    }
}

static void
_suback(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    (void)m;
    (void)ud;
    (void)pkt;

    if (!quiet)
        printf("Subscribed, topic:%s qos:%d\n", topics[0], qos);
}

static void
_connack(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    mqtt_qos_t qoss[128];
    int i;
    (void)ud;

    if (proto_ver == MQTT_VERSION_3) {
        if (pkt->v.connack.v3.return_code != MQTT_CRC_ACCEPTED) {
            if (!quiet)
                printf("Connack, %s\n", mqtt_crc_name(pkt->v.connack.v3.return_code));
            return;
        }
    } else if (proto_ver == MQTT_VERSION_4) {
        if (pkt->v.connack.v4.return_code != MQTT_CRC_ACCEPTED) {
            if (!quiet)
                printf("Connack, %s\n", mqtt_crc_name(pkt->v.connack.v4.return_code));
            return;
        }
    }

    for (i = 0; i < topic_count; i++) {
        qoss[i] = qos;
    }

    mqtt_cli_subscribe(m, topic_count, (const char **)topics, qoss, 0);
}

int
main(int argc, char *argv[]) {
    int i;
    mqtt_cli_t *m;
    void *net;

    config(argc, argv);
    if (!host) {
        host = strdup("127.0.0.1");
    }

    if (clean_session == 0 && (client_id_prefix || !client_id)) {
        if (!quiet)
            fprintf(stderr, "Error: You must provide a client id if you are using the -c option.\n");
        return 0;
    }
    if (topic_count == 0) {
        if (!quiet)
            fprintf(stderr, "Error: You must specify a topic to subscribe to.\n");
        return 0;
    }

    if (!client_id) {
        if (!client_id_prefix) {
            client_id_prefix = strdup("mqtt_sub_");
        }
        client_id = malloc(strlen(client_id_prefix) + 10);
        if (!client_id) {
            if (!quiet)
                fprintf(stderr, "out of memory\n");
            return 0;
        }
        snprintf(client_id, strlen(client_id_prefix) + 10, "%s%d", client_id_prefix, getpid());
    }

    mqtt_cli_conf_t config = {
        .client_id = client_id,
        .version = proto_ver,
        .keep_alive = keepalive,
        .clean_session = clean_session,
        .auth =
            {
                .username = username,
                .password = password,
            },
        .lwt =
            {
                .retain = will_retain,
                .topic = will_topic,
                .qos = will_qos,
                .message = {.s = will_message, .n = will_length},
            },
        .cb =
            {
                .connack = _connack,
                .suback = _suback,
                .unsuback = _unsuback,
                .publish = _publish,
            },
        .ud = 0,
    };

    net = network_tcp_connect(host, port);
    if (!net) {
        if (!quiet)
            fprintf(stderr, "mqtt broker connect error\n");
        return EXIT_FAILURE;
    }

    m = mqtt_cli_create(&config);
    mqtt_cli_connect(m);
    while (1) {
        mqtt_str_t outgoing, incoming;
        uint64_t t1, t2;

        t1 = network_time_now();
        mqtt_cli_outgoing(m, &outgoing);
        if (network_tcp_transfer(net, &outgoing, &incoming)) {
            break;
        }
        if (mqtt_cli_incoming(m, &incoming)) {
            break;
        }
        t2 = network_time_now();
        if (mqtt_cli_elapsed(m, t2 - t1)) {
            break;
        }
    }
    mqtt_cli_destroy(m);

    network_tcp_close(net);

    free(host);
    if (client_id)
        free(client_id);
    if (client_id_prefix)
        free(client_id_prefix);
    if (username)
        free(username);
    if (password)
        free(password);
    if (will_topic)
        free(will_topic);
    if (will_message)
        free(will_message);
    for (i = 0; i < topic_count; i++)
        free(topics[i]);
    free(topics);

    return 0;
}
