/*
 * mqtt_pub.c -- sample mqtt client publish message.
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

enum {
    MSGMODE_NONE,
    MSGMODE_FILE,
    MSGMODE_STDIN_LINE,
    MSGMODE_CMD,
    MSGMODE_NULL,
    MSGMODE_STDIN_FILE,
};

static char *host = 0;
static int port = MQTT_TCP_PORT;
static int debug = 0;
static int quiet = 0;
static int pub_mode = MSGMODE_NONE;

static char *client_id = 0;
static char *client_id_prefix = 0;
static char *username = 0;
static char *password = 0;
static int proto_ver = MQTT_VERSION_4;
static int keepalive = 60;
static int clean_session = 1;

static int qos = MQTT_QOS_0;
static int retain = 0;
static char *topic = 0;
static char *payload = 0;
static int length = 0;
static char *file_input = 0;

static int will_qos = 0;
static int will_retain = 0;
static char *will_topic = 0;
static char *will_message = 0;
static int will_length = 0;

static void
usage(void) {
    printf("mqtt_pub is a simple mqtt client that will publish a message on a single topic and exit.\n");
    printf(
        "Usage: mqtt_pub [-h host] [-k keepalive] [-p port] [-q qos] [-r] {-f file | -l | -n | -m message} -t topic\n");
    printf("                     [-i id] [-I id_prefix]\n");
    printf("                     [-d] [--quiet]\n");
    printf("                     [-u username [-P password]]\n");
    printf("                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]\n");
    printf("       mqtt_pub --help\n\n");
    printf(" -d : enable debug messages.\n");
    printf(" -f : send the contents of a file as the message.\n");
    printf(" -h : mqtt host to connect to. Defaults to localhost.\n");
    printf(" -i : id to use for this client. Defaults to mqtt_pub_ appended with the process id.\n");
    printf(" -I : define the client id as id_prefix appended with the process id. Useful for when the\n");
    printf("      broker is using the clientid_prefixes option.\n");
    printf(" -k : keep alive in seconds for this client. Defaults to 60.\n");
    printf(" -l : read messages from stdin, sending a separate message for each line.\n");
    printf(" -m : message payload to send.\n");
    printf(" -n : send a null (zero length) message.\n");
    printf(" -p : network port to connect to. Defaults to 1883.\n");
    printf(" -P : provide a password (requires MQTT broker)\n");
    printf(" -q : quality of service level to use for all messages. Defaults to 0.\n");
    printf(" -r : message should be retained.\n");
    printf(" -s : read message from stdin, sending the entire input as a message.\n");
    printf(" -t : mqtt topic to publish to.\n");
    printf(" -u : provide a username (requires MQTT broker)\n");
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
        } else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--retain")) {
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
        } else {
            fprintf(stderr, "Error: Unknown option '%s'.\n", argv[i]);
            goto e;
        }
    }
    return;

e:
    fprintf(stderr, "\nUse 'mqtt_pub --help' to see usage.\n");
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

static void
do_publish(mqtt_cli_t *m) {
    mqtt_str_t message;
    int rc;

    message.s = payload;
    message.n = length;
    rc = mqtt_cli_publish(m, retain, topic, qos, &message, 0);
    if (rc) {
        mqtt_cli_disconnect(m);
        return;
    }
    if (qos == MQTT_QOS_0) {
        if (pub_mode == MSGMODE_STDIN_LINE) {
            if (load_stdin_line()) {
                fprintf(stderr, "Error loading input line from stdin.\n");
                mqtt_cli_disconnect(m);
                return;
            }
            do_publish(m);
        } else {
            mqtt_cli_disconnect(m);
        }
    }
}

static void
_puback(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
    (void)ud;
    (void)pkt;
    if (pub_mode == MSGMODE_STDIN_LINE) {
        if (load_stdin_line()) {
            if (!quiet)
                fprintf(stderr, "Error loading input line from stdin.\n");
            mqtt_cli_disconnect(m);
            return;
        }
        do_publish(m);
    } else {
        mqtt_cli_disconnect(m);
    }
}

static void
_connack(mqtt_cli_t *m, void *ud, const mqtt_packet_t *pkt) {
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

    do_publish(m);
}

int
main(int argc, char *argv[]) {
    void *net;
    mqtt_cli_t *m;

    config(argc, argv);
    if (!host) {
        host = strdup("127.0.0.1");
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

    if (!client_id) {
        if (!client_id_prefix) {
            client_id_prefix = strdup("mqtt_pub_");
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
                .puback = _puback,
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
    free(topic);
    if (client_id)
        free(client_id);
    if (client_id_prefix)
        free(client_id_prefix);
    if (username)
        free(username);
    if (password)
        free(password);
    if (payload)
        free(payload);
    if (will_topic)
        free(will_topic);
    if (will_message)
        free(will_message);

    return 0;
}
