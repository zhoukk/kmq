/*
 * mqtt_sn_sub.c -- sample mqtt-sn client subscribe topic.
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

#define MQTT_SN_CLI_LINUX_PLATFORM
#define MQTT_SN_CLI_IMPL
#include "mqtt_sn_cli.h"

static char *host = 0;
static int port = MQTT_SN_UDP_PORT;
static int uport = 0;
static int debug = 0;
static int quiet = 0;
static int verbose = 0;
static int msg_count = 0;
static int msg_cnt = 0;
static int no_retain = 0;
static int eol = 1;

static char *client_id = 0;
static char *client_id_prefix = 0;
static int keepalive = 60;
static int clean_session = 1;
static int radius = 0;

static int qos = MQTT_SN_QOS_0;
static int topic_count = 0;
static char **topics = 0;

static int will_qos = 0;
static int will_retain = 0;
static char *will_topic = 0;
static char *will_payload = 0;
static int will_length = 0;

static void
usage(void) {
    printf("mqtt_sn_sub is a simple mqtt-sn client that will subscribe to a single topic and print all messages it "
           "receives.\n");
    printf("Usage: mqtt_sn_sub [-c] [-h host] [-k keepalive] [-p port] [-q qos] [-R] -t topic ...\n");
    printf("                     [-C msg_count] [-r radius]\n");
    printf("                     [-i id] [-I id_prefix]\n");
    printf("                     [-d] [-N] [--quiet] [-v]\n");
    printf("                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]\n");
    printf("       mqtt_sn_sub --help\n\n");
    printf(" -c : disable 'clean session' (store subscription and pending messages when client disconnects).\n");
    printf(" -C : disconnect and exit after receiving the 'msg_count' messages.\n");
    printf(" -d : enable debug messages.\n");
    printf(" -h : mqtt-sn multicast host. Defaults to 225.1.1.1.\n");
    printf(" -i : id to use for this client. Defaults to mqtt_sn_sub_ appended with the process id.\n");
    printf(" -I : define the client id as id_prefix appended with the process id. Useful for when the\n");
    printf("      broker is using the clientid_prefixes param.\n");
    printf(" -k : keep alive in seconds for this client. Defaults to 60.\n");
    printf(" -N : do not add an end of line character when printing the payload.\n");
    printf(" -p : network port to send to. Defaults to 1884.\n");
    printf(" -P : local port to bind. Defaults to 0.\n");
    printf(" -q : quality of service level to use for the subscription. Defaults to 0.\n");
    printf(" -R : do not print stale messages (those with retain set).\n");
    printf(" -r : radius for search gateway. Defaults to 0.\n");
    printf(" -t : mqtt-sn topic to subscribe to. May be repeated multiple times.\n");
    printf(" -v : print published messages verbosely.\n");
    printf(" --help : display this message.\n");
    printf(" --quiet : don't print error messages.\n");
    printf(" --will-payload : payload for the client Will, which is sent by the broker in case of\n");
    printf("                  unexpected disconnection. If not given and will-topic is set, a zero\n");
    printf("                  length message will be sent.\n");
    printf(" --will-qos : QoS level for the client Will.\n");
    printf(" --will-retain : if given, make the client Will retained.\n");
    printf(" --will-topic : the topic on which to publish the client Will.\n");
    printf("\nSee https://github.com/zhoukk/libmqtt for more information.\n\n");
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
        } else if (!strcmp(argv[i], "-P") || !strcmp(argv[i], "--uport")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -P argument given but no udp bind port specified.\n\n");
                goto e;
            } else {
                uport = atoi(argv[i + 1]);
                if (uport < 0 || uport > 65535) {
                    fprintf(stderr, "Error: Invalid udp bind port given: %d\n", port);
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
        } else if (!strcmp(argv[i], "--will-payload")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: --will-payload argument given but no will payload specified.\n\n");
                goto e;
            } else {
                will_payload = strdup(argv[i + 1]);
                will_length = strlen(will_payload);
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
        } else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--radius")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -r argument given but no radius specified.\n\n");
                goto e;
            } else {
                radius = atoi(argv[i + 1]);
                if (radius > 255) {
                    fprintf(stderr, "Error: Invalid radius given: %d\n", radius);
                    goto e;
                }
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
            fprintf(stderr, "Error: Unknown param '%s'.\n", argv[i]);
            goto e;
        }
    }
    return;

e:
    fprintf(stderr, "\nUse 'mqtt_sn_sub --help' to see usage.\n");
    exit(0);
}

static void
_publish(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    if (pkt->v.publish.flags.bits.retain == 1 && no_retain == 1)
        return;
    if (verbose) {
        if (pkt->v.publish.data.n) {
            if (pkt->v.publish.topic.type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED)
                printf("%d ", pkt->v.publish.topic.id);
            else
                printf("%.*s ", 2, pkt->v.publish.topic.shor);
            fwrite(pkt->v.publish.data.s, 1, pkt->v.publish.data.n, stdout);
            if (eol) {
                printf("\n");
            }
        } else {
            if (eol) {
                if (pkt->v.publish.topic.type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED)
                    printf("%d (null)\n", pkt->v.publish.topic.id);
                else
                    printf("%.*s (null)\n", 2, pkt->v.publish.topic.shor);
            }
        }
        fflush(stdout);
    } else {
        if (pkt->v.publish.data.n) {
            fwrite(pkt->v.publish.data.s, 1, pkt->v.publish.data.n, stdout);
            if (eol) {
                printf("\n");
            }
            fflush(stdout);
        }
    }

    if (msg_count > 0) {
        msg_cnt++;
        if (msg_cnt == msg_count) {
            mqtt_sn_cli_disconnect(m, 0);
        }
    }
}

static void
_suback(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {

    if (!quiet)
        printf("Subscribed (topic_id: %d, qos: %d, return_code: %d %s)\n", pkt->v.suback.topic_id,
               pkt->v.suback.flags.bits.qos, pkt->v.suback.return_code, MQTT_SN_RC_NAMES[pkt->v.suback.return_code]);
}

static void
_connack(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    int i;

    if (pkt->v.connack.return_code != MQTT_SN_RC_ACCEPTED) {
        printf("connect %s\n", mqtt_sn_rc_name(pkt->v.connack.return_code));
        return;
    }
    for (i = 0; i < topic_count; i++) {
        mqtt_sn_topic_t t;

        t.type = MQTT_SN_TOPIC_ID_TYPE_NORMAL;
        mqtt_str_from(&t.name, topics[i]);
        mqtt_sn_cli_subscribe(m, &t, qos, 0);
    }
}

static void
_gwinfo(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    mqtt_sn_cli_state_t state;

    state = mqtt_sn_cli_state(m);
    if (MQTT_SN_STATE_DISCONNECTED == state || MQTT_SN_STATE_SEARCHGW == state) {
        linux_udp_set_unicast(ud, linux_udp_from_address(ud));
        mqtt_sn_cli_connect(m);
    }
}

int
main(int argc, char *argv[]) {
    int i;
    void *net;
    mqtt_sn_cli_t *m;

    config(argc, argv);
    if (!host) {
        host = strdup("225.1.1.1");
    }

    if (clean_session == 0 && (client_id_prefix || !client_id)) {
        if (!quiet)
            fprintf(stderr, "Error: You must provide a client id if you are using the -c param.\n");
        return 0;
    }
    if (topic_count == 0) {
        if (!quiet)
            fprintf(stderr, "Error: You must specify a topic to subscribe to.\n");
        return 0;
    }

    if (!client_id) {
        if (!client_id_prefix) {
            client_id_prefix = strdup("mqtt_sn_sub_");
        }
        client_id = malloc(strlen(client_id_prefix) + 10);
        if (!client_id) {
            if (!quiet)
                fprintf(stderr, "out of memory\n");
            return 0;
        }
        snprintf(client_id, strlen(client_id_prefix) + 10, "%s%d", client_id_prefix, getpid());
    }

    mqtt_sn_cli_conf_t config = {
        .client_id = client_id,
        .duration = keepalive,
        .clean_session = clean_session,
        .lwt =
            {
                .retain = will_retain,
                .topic = will_topic,
                .qos = will_qos,
                .message = {.s = will_payload, .n = will_length},
            },
        .cb =
            {
                .gwinfo = _gwinfo,
                .connack = _connack,
                .suback = _suback,
                .publish = _publish,
            },
        .ud = 0,
    };

    net = linux_udp_open("0.0.0.0", port);
    if (!net) {
        if (!quiet)
            fprintf(stderr, "udp open error\n");
        return EXIT_FAILURE;
    }
    config.ud = net;

    m = mqtt_sn_cli_create(&config);

    linux_udp_join_multicast(net, host, port);
    mqtt_sn_cli_searchgw(m, radius);

    while (1) {
        mqtt_str_t outgoing, incoming;
        uint64_t t1, t2;

        t1 = linux_time_now();
        mqtt_sn_cli_outgoing(m, &outgoing);
        if (linux_udp_transfer(net, &outgoing, &incoming)) {
            break;
        }
        if (mqtt_sn_cli_incoming(m, &incoming)) {
            break;
        }
        t2 = linux_time_now();
        if (mqtt_sn_cli_elapsed(m, t2 - t1)) {
            break;
        }
    }

    mqtt_sn_cli_destroy(m);

    linux_udp_close(net);

    free(host);
    if (client_id)
        free(client_id);
    if (client_id_prefix)
        free(client_id_prefix);
    if (will_topic)
        free(will_topic);
    if (will_payload)
        free(will_payload);
    for (i = 0; i < topic_count; i++)
        free(topics[i]);
    free(topics);

    return 0;
}
