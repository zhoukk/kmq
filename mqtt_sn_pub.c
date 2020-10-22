/*
 * mqtt_sn_pub.c -- sample mqtt-sn client publish message.
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

enum {
    MSGMODE_NONE,
    MSGMODE_FILE,
    MSGMODE_STDIN_LINE,
    MSGMODE_CMD,
    MSGMODE_NULL,
    MSGMODE_STDIN_FILE,
};

static char *host = 0;
static int port = MQTT_SN_UDP_PORT;
static int uport = 0;
static int debug = 0;
static int quiet = 0;
static int pub_mode = MSGMODE_NONE;

static char *client_id = 0;
static char *client_id_prefix = 0;
static int keepalive = 60;
static int clean_session = 1;
static int radius = 0;

static int qos = MQTT_SN_QOS_0;
static int retain = 0;
static char *topic = 0;
static char *payload = 0;
static int length = 0;
static char *file_input = 0;

static int will_qos = 0;
static int will_retain = 0;
static char *will_topic = 0;
static char *will_payload = 0;
static int will_length = 0;

static void
usage(void) {
    printf("mqtt_sn_pub is a simple mqtt-sn client that will publish a message on a single topic and exit.\n");
    printf("Usage: mqtt_sn_pub [-h host] [-k keepalive] [-p port] [-q qos] [-R] {-f file | -l | -n | -m message} -t "
           "topic\n");
    printf("                     [-i id] [-I id_prefix] [-r radius]\n");
    printf("                     [-d] [--quiet]\n");
    printf("                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]\n");
    printf("       mqtt_sn_pub --help\n\n");
    printf(" -d : enable debug messages.\n");
    printf(" -f : send the contents of a file as the message.\n");
    printf(" -h : mqtt-sn multicast host or host for qos -1 to sendto. Defaults to 225.1.1.1.\n");
    printf(" -i : id to use for this client. Defaults to mqtt_sn_pub_ appended with the process id.\n");
    printf(" -I : define the client id as id_prefix appended with the process id. Useful for when the\n");
    printf("      broker is using the clientid_prefixes param.\n");
    printf(" -k : keep alive in seconds for this client. Defaults to 60.\n");
    printf(" -l : read messages from stdin, sending a separate message for each line.\n");
    printf(" -m : message payload to send.\n");
    printf(" -n : send a null (zero length) message.\n");
    printf(" -p : network port to send to. Defaults to 1884.\n");
    printf(" -P : local port to bind. Defaults to 0.\n");
    printf(" -q : quality of service level to use for all messages. Defaults to 0.\n");
    printf(" -R : message should be retained.\n");
    printf(" -r : radius for search gateway. Defaults to 0.\n");
    printf(" -s : read message from stdin, sending the entire input as a message.\n");
    printf(" -t : mqtt-sn topic to publish to.\n");
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
        } else if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
            if (pub_mode != MSGMODE_NONE) {
                fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
                goto e;
            } else if (i == argc - 1) {
                fprintf(stderr, "Error: -f argument given but no file specified.\n\n");
                goto e;
            } else {
                pub_mode = MSGMODE_FILE;
                file_input = strdup(argv[i + 1]);
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
        } else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--stdin-line")) {
            if (pub_mode != MSGMODE_NONE) {
                fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
                goto e;
            } else {
                pub_mode = MSGMODE_STDIN_LINE;
            }
        } else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--message")) {
            if (pub_mode != MSGMODE_NONE) {
                fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
                goto e;
            } else if (i == argc - 1) {
                fprintf(stderr, "Error: -m argument given but no message specified.\n\n");
                goto e;
            } else {
                payload = strdup(argv[i + 1]);
                length = strlen(payload);
                pub_mode = MSGMODE_CMD;
            }
            i++;
        } else if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--null-message")) {
            if (pub_mode != MSGMODE_NONE) {
                fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
                goto e;
            } else {
                pub_mode = MSGMODE_NULL;
            }
        } else if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--qos")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -q argument given but no QoS specified.\n\n");
                goto e;
            } else {
                qos = atoi(argv[i + 1]);
                if (qos < -1 || qos > 2) {
                    fprintf(stderr, "Error: Invalid QoS given: %d\n", qos);
                    goto e;
                }
            }
            i++;
        } else if (!strcmp(argv[i], "--quiet")) {
            quiet = 1;
        } else if (!strcmp(argv[i], "-R") || !strcmp(argv[i], "--retain")) {
            retain = 1;
        } else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--stdin-file")) {
            if (pub_mode != MSGMODE_NONE) {
                fprintf(stderr, "Error: Only one type of message can be sent at once.\n\n");
                goto e;
            } else {
                pub_mode = MSGMODE_STDIN_FILE;
            }
        } else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--topic")) {
            if (i == argc - 1) {
                fprintf(stderr, "Error: -t argument given but no topic specified.\n\n");
                goto e;
            } else {
                topic = strdup(argv[i + 1]);
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
        } else {
            fprintf(stderr, "Error: Unknown param '%s'.\n", argv[i]);
            goto e;
        }
    }
    return;

e:
    fprintf(stderr, "\nUse 'mqtt_sn_pub --help' to see usage.\n");
    exit(0);
}

static int
load_stdin_line(void) {
    char buff[1024];
    if (!fgets(buff, 1024, stdin))
        return -1;

    length = strlen(buff);
    if (buff[length - 1] == '\n')
        buff[length - 1] = '\0';
    length -= 1;
    payload = strdup(buff);
    return 0;
}

static int
load_stdin(void) {
    long pos = 0;
    char buf[1024];
    char *aux_message = 0;

    while (!feof(stdin)) {
        long rlen;
        rlen = fread(buf, 1, 1024, stdin);
        aux_message = realloc(payload, pos + rlen);
        if (!aux_message) {
            if (!quiet)
                fprintf(stderr, "Error: Out of memory.\n");
            free(payload);
            payload = 0;
            return 1;
        } else {
            payload = aux_message;
        }
        memcpy(&(payload[pos]), buf, rlen);
        pos += rlen;
    }
    length = pos;

    if (!length) {
        if (!quiet)
            fprintf(stderr, "Error: Zero length input.\n");
        return 1;
    }
    return 0;
}

static int
load_file(void) {
    long pos;
    FILE *fptr = 0;

    fptr = fopen(file_input, "rb");
    if (!fptr) {
        if (!quiet)
            fprintf(stderr, "Error: Unable to open file \"%s\".\n", file_input);
        return 1;
    }
    fseek(fptr, 0, SEEK_END);
    length = ftell(fptr);
    if (length > 268435455) {
        fclose(fptr);
        if (!quiet)
            fprintf(stderr, "Error: File \"%s\" is too large (>268,435,455 bytes).\n", file_input);
        return 1;
    } else if (length == 0) {
        fclose(fptr);
        if (!quiet)
            fprintf(stderr, "Error: File \"%s\" is empty.\n", file_input);
        return 1;
    } else if (length < 0) {
        fclose(fptr);
        if (!quiet)
            fprintf(stderr, "Error: Unable to determine size of file \"%s\".\n", file_input);
        return 1;
    }
    fseek(fptr, 0, SEEK_SET);
    payload = malloc(length);
    if (!payload) {
        fclose(fptr);
        if (!quiet)
            fprintf(stderr, "Error: Out of memory.\n");
        return 1;
    }
    pos = 0;
    while (pos < length) {
        long rlen;
        rlen = fread(&(payload[pos]), sizeof(char), length - pos, fptr);
        pos += rlen;
    }
    fclose(fptr);
    return 0;
}

static void do_publish(mqtt_sn_cli_t *m, void *ud);

static void
_puback(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    if (!quiet)
        printf("Published (topic_id: %d, return_code: %d %s)\n", pkt->v.puback.topic.id, pkt->v.puback.return_code,
               MQTT_SN_RC_NAMES[pkt->v.puback.return_code]);

    if (pub_mode == MSGMODE_STDIN_LINE) {
        if (load_stdin_line()) {
            if (!quiet)
                fprintf(stderr, "Error loading input line from stdin.\n");
            mqtt_sn_cli_disconnect(m, 0);
            return;
        }
        do_publish(m, ud);
    } else {
        mqtt_sn_cli_disconnect(m, 0);
    }
}

static void
do_publish(mqtt_sn_cli_t *m, void *ud) {
    mqtt_str_t message = {.s = payload, .n = length};
    mqtt_sn_topic_t t;

    t.type = MQTT_SN_TOPIC_ID_TYPE_NORMAL;
    mqtt_str_from(&t.name, topic);

    mqtt_sn_cli_publish(m, retain, &t, qos, &message, 0);
    if (qos == -1) {
        mqtt_sn_cli_disconnect(m, 0);
        return;
    }
    if (qos == MQTT_SN_QOS_0) {
        if (pub_mode == MSGMODE_STDIN_LINE) {
            if (load_stdin_line()) {
                fprintf(stderr, "Error loading input line from stdin.\n");
                mqtt_sn_cli_disconnect(m, 0);
                return;
            }
            do_publish(m, ud);
        }
    }
}

static void
_regack(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    if (MQTT_SN_RC_ACCEPTED != pkt->v.regack.return_code) {
        if (!quiet)
            fprintf(stderr, "register %s\n", MQTT_SN_RC_NAMES[pkt->v.regack.return_code]);
        return;
    }
    if (!quiet)
        printf("register %d => %s\n", pkt->v.regack.topic_id, topic);
    do_publish(m, ud);
}

static void
_connack(mqtt_sn_cli_t *m, void *ud, const mqtt_sn_packet_t *pkt) {
    if (pkt->v.connack.return_code != MQTT_SN_RC_ACCEPTED) {
        printf("connect %s\n", mqtt_sn_rc_name(pkt->v.connack.return_code));
        return;
    }
    if (qos == -1) {
        do_publish(m, ud);
    } else {
        mqtt_sn_cli_register(m, topic, 0);
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
    void *net;
    mqtt_sn_cli_t *m;

    config(argc, argv);
    if (!host) {
        host = strdup("225.1.1.1");
    }
    if (!client_id_prefix) {
        client_id_prefix = strdup("mqtt_sn_pub_");
    }

    if (pub_mode == MSGMODE_STDIN_LINE) {
        if (load_stdin_line()) {
            if (!quiet)
                fprintf(stderr, "Error loading input line from stdin.\n");
            return 0;
        }
    } else if (pub_mode == MSGMODE_STDIN_FILE) {
        if (load_stdin()) {
            if (!quiet)
                fprintf(stderr, "Error loading input from stdin.\n");
            return 0;
        }
    } else if (pub_mode == MSGMODE_FILE && file_input) {
        if (load_file()) {
            if (!quiet)
                fprintf(stderr, "Error loading input file \"%s\".\n", file_input);
            return 0;
        }
    }

    if (!topic || pub_mode == MSGMODE_NONE) {
        if (!quiet)
            fprintf(stderr, "Error: Both topic and message must be supplied.\n");
        usage();
    }

    if (client_id_prefix) {
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
                .regack = _regack,
                .puback = _puback,
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
    free(topic);
    if (client_id)
        free(client_id);
    if (client_id_prefix)
        free(client_id_prefix);
    if (payload)
        free(payload);
    if (will_topic)
        free(will_topic);
    if (will_payload)
        free(will_payload);

    return 0;
}
