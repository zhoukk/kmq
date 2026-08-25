/*
 * mqtt.h -- mqtt and mqtt-sn defines, structures and utils.
 *
 * https://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html
 * https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
 * https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html
 * http://mqtt.org/new/wp-content/uploads/2009/06/MQTT-SN_spec_v1.2.pdf
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

#ifndef _MQTT_H_
#define _MQTT_H_

/* generic includes. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ownership & lifetime rules:
 *  - strings produced by parsing (pkt->p.*, pkt->v.*, properties) borrow
 *    memory from pkt->b; release them only via mqtt_packet_cleanup /
 *    mqtt_sn_packet_cleanup, never mqtt_str_free them individually.
 *  - buffers produced by mqtt_str_dup/copy or serialize are owned by the
 *    caller; release them with mqtt_str_free.
 *  - serialize supports two modes: if b->s is preset (non-NULL), write in
 *    place with b->n as capacity and fail on overflow; otherwise allocate
 *    a new buffer owned by the caller.
 *
 * thread safety:
 *  - the only global mutable state is the allocator hook set by
 *    mqtt_set_allocator; call it once before any allocation.
 *  - parser/packet objects are not thread safe.
 */

/* mqtt broker port */
#define MQTT_TCP_PORT   1883
#define MQTT_TLS_PORT   8883
#define MQTT_WS_PORT    8083
#define MQTT_WSS_PORT   8084

/* mqtt-sn gateway port */
#define MQTT_SN_UDP_PORT    1884

/* seconds between gateway broadcast advertise */
#define MQTT_SN_T_ADV       900

/* times not recv advertise before broadcast searchgw */
#define MQTT_SN_N_ADV       3

/* max seconds delay before broadcast searchgw */
#define MQTT_SN_T_SEARCHGW  5

/* seconds wait for gwinfo from gateway */
#define MQTT_SN_T_GWINFO    5

/* seconds wait mqtt-sn packet */
#define MQTT_SN_T_WAIT      300

/* seconds after retry mqtt-sn packet */
#define MQTT_SN_T_RETRY     10

/* times mqtt-sn packet retry */
#define MQTT_SN_N_RETRY     5

/* mqtt protocol version */
typedef enum {
    MQTT_VERSION_3 = 0x03, /* mqttv3.1 */
    MQTT_VERSION_4 = 0x04, /* mqttv3.1.1 */
    MQTT_VERSION_5 = 0x05  /* mqttv5.0 */
} mqtt_version_t;

static inline int
mqtt_is_valid_version(mqtt_version_t version) {
    switch (version) {
    case MQTT_VERSION_3:
    case MQTT_VERSION_4:
    case MQTT_VERSION_5:
        return 1;
    default:
        return 0;
    }
}

static inline const char *
mqtt_protocol_name(mqtt_version_t version) {
    switch (version) {
    case MQTT_VERSION_3:
        return "MQIsdp";
    case MQTT_VERSION_4:
    case MQTT_VERSION_5:
        return "MQTT";
    default:
        return "";
    }
}

static inline const char *
mqtt_version_name(mqtt_version_t version) {
    switch (version) {
    case MQTT_VERSION_3:
        return "mqttv3.1";
    case MQTT_VERSION_4:
        return "mqttv3.1.1";
    case MQTT_VERSION_5:
        return "mqttv5.0";
    default:
        return "";
    }
}

/* mqtt-sn protocol version */
#define MQTT_SN_PROTOCOL_VERSION 0x01

/* mqtt qos */
typedef enum {
    MQTT_QOS_0 = 0x00,
    MQTT_QOS_1 = 0x01,
    MQTT_QOS_2 = 0x02
} mqtt_qos_t;

#define MQTT_IS_QOS(q) ((q) >= MQTT_QOS_0 && (q) <= MQTT_QOS_2)

/* mqtt-sn qos */
typedef enum {
    MQTT_SN_QOS_0 = 0x00,
    MQTT_SN_QOS_1 = 0x01,
    MQTT_SN_QOS_2 = 0x02,
    MQTT_SN_QOS_3 = 0x03
} mqtt_sn_qos_t;

#define MQTT_SN_IS_QOS(q) ((q) >= MQTT_SN_QOS_0 && (q) <= MQTT_SN_QOS_3)

/* mqtt control packet type */
typedef enum {
    MQTT_RESERVED    = 0x00,
    MQTT_CONNECT     = 0x01,
    MQTT_CONNACK     = 0x02,
    MQTT_PUBLISH     = 0x03,
    MQTT_PUBACK      = 0x04,
    MQTT_PUBREC      = 0x05,
    MQTT_PUBREL      = 0x06,
    MQTT_PUBCOMP     = 0x07,
    MQTT_SUBSCRIBE   = 0x08,
    MQTT_SUBACK      = 0x09,
    MQTT_UNSUBSCRIBE = 0x0A,
    MQTT_UNSUBACK    = 0x0B,
    MQTT_PINGREQ     = 0x0C,
    MQTT_PINGRESP    = 0x0D,
    MQTT_DISCONNECT  = 0x0E,
    MQTT_AUTH        = 0x0F
} mqtt_packet_type_t;

#define MQTT_IS_PACKET_TYPE(t) ((t) >= MQTT_CONNECT && (t) <= MQTT_AUTH)

static inline const char *
mqtt_packet_type_name(mqtt_packet_type_t type) {
    switch (type) {
    case MQTT_RESERVED:
        return "RESERVED";
    case MQTT_CONNECT:
        return "CONNECT";
    case MQTT_CONNACK:
        return "CONNACK";
    case MQTT_PUBLISH:
        return "PUBLISH";
    case MQTT_PUBACK:
        return "PUBACK";
    case MQTT_PUBREC:
        return "PUBREC";
    case MQTT_PUBREL:
        return "PUBREL";
    case MQTT_PUBCOMP:
        return "PUBCOMP";
    case MQTT_SUBSCRIBE:
        return "SUBSCRIBE";
    case MQTT_SUBACK:
        return "SUBACK";
    case MQTT_UNSUBSCRIBE:
        return "UNSUBSCRIBE";
    case MQTT_UNSUBACK:
        return "UNSUBACK";
    case MQTT_PINGREQ:
        return "PINGREQ";
    case MQTT_PINGRESP:
        return "PINGRESP";
    case MQTT_DISCONNECT:
        return "DISCONNECT";
    case MQTT_AUTH:
        return "AUTH";
    default:
        return "";
    }
}

/* mqtt-sn control packet type */
typedef enum {
    MQTT_SN_ADVERTISE       = 0x00,
    MQTT_SN_SEARCHGW        = 0x01,
    MQTT_SN_GWINFO          = 0x02,
    MQTT_SN_CONNECT         = 0x04,
    MQTT_SN_CONNACK         = 0x05,
    MQTT_SN_WILLTOPICREQ    = 0x06,
    MQTT_SN_WILLTOPIC       = 0x07,
    MQTT_SN_WILLMSGREQ      = 0x08,
    MQTT_SN_WILLMSG         = 0x09,
    MQTT_SN_REGISTER        = 0x0A,
    MQTT_SN_REGACK          = 0x0B,
    MQTT_SN_PUBLISH         = 0x0C,
    MQTT_SN_PUBACK          = 0x0D,
    MQTT_SN_PUBCOMP         = 0x0E,
    MQTT_SN_PUBREC          = 0x0F,
    MQTT_SN_PUBREL          = 0x10,
    MQTT_SN_SUBSCRIBE       = 0x12,
    MQTT_SN_SUBACK          = 0x13,
    MQTT_SN_UNSUBSCRIBE     = 0x14,
    MQTT_SN_UNSUBACK        = 0x15,
    MQTT_SN_PINGREQ         = 0x16,
    MQTT_SN_PINGRESP        = 0x17,
    MQTT_SN_DISCONNECT      = 0x18,
    MQTT_SN_WILLTOPICUPD    = 0x1A,
    MQTT_SN_WILLTOPICRESP   = 0x1B,
    MQTT_SN_WILLMSGUPD      = 0x1C,
    MQTT_SN_WILLMSGRESP     = 0x1D,
    MQTT_SN_ENCAPSULATED    = 0xFE,
    MQTT_SN_RESERVED        = 0xFF
} mqtt_sn_packet_type_t;

#define MQTT_SN_IS_PACKET_TYPE(t) \
    (((t) >= MQTT_SN_ADVERTISE && (t) <= MQTT_SN_WILLMSGRESP) || (t) == MQTT_SN_ENCAPSULATED)

static inline const char *
mqtt_sn_packet_type_name(mqtt_sn_packet_type_t type) {
    switch (type) {
    case MQTT_SN_ADVERTISE:
        return "ADVERTISE";
    case MQTT_SN_SEARCHGW:
        return "SEARCHGW";
    case MQTT_SN_GWINFO:
        return "GWINFO";
    case MQTT_SN_CONNECT:
        return "CONNECT";
    case MQTT_SN_CONNACK:
        return "CONNACK";
    case MQTT_SN_WILLTOPICREQ:
        return "WILLTOPICREQ";
    case MQTT_SN_WILLTOPIC:
        return "WILLTOPIC";
    case MQTT_SN_WILLMSGREQ:
        return "WILLMSGREQ";
    case MQTT_SN_WILLMSG:
        return "WILLMSG";
    case MQTT_SN_REGISTER:
        return "REGISTER";
    case MQTT_SN_REGACK:
        return "REGACK";
    case MQTT_SN_PUBLISH:
        return "PUBLISH";
    case MQTT_SN_PUBACK:
        return "PUBACK";
    case MQTT_SN_PUBCOMP:
        return "PUBCOMP";
    case MQTT_SN_PUBREC:
        return "PUBREC";
    case MQTT_SN_PUBREL:
        return "PUBREL";
    case MQTT_SN_SUBSCRIBE:
        return "SUBSCRIBE";
    case MQTT_SN_SUBACK:
        return "SUBACK";
    case MQTT_SN_UNSUBSCRIBE:
        return "UNSUBSCRIBE";
    case MQTT_SN_UNSUBACK:
        return "UNSUBACK";
    case MQTT_SN_PINGREQ:
        return "PINGREQ";
    case MQTT_SN_PINGRESP:
        return "PINGRESP";
    case MQTT_SN_DISCONNECT:
        return "DISCONNECT";
    case MQTT_SN_WILLTOPICUPD:
        return "WILLTOPICUPD";
    case MQTT_SN_WILLTOPICRESP:
        return "WILLTOPICRESP";
    case MQTT_SN_WILLMSGUPD:
        return "WILLMSGUPD";
    case MQTT_SN_WILLMSGRESP:
        return "WILLMSGRESP";
    case MQTT_SN_ENCAPSULATED:
        return "ENCAPSULATED";
    case MQTT_SN_RESERVED:
        return "RESERVED";
    }
    return "";
}

/* mqtt connect return code for mqttv3.1 and mqttv3.1.1 */
typedef enum {
    MQTT_CRC_ACCEPTED                        = 0x00,
    MQTT_CRC_REFUSED_PROTOCOL_VERSION        = 0x01,
    MQTT_CRC_REFUSED_IDENTIFIER_REJECTED     = 0x02,
    MQTT_CRC_REFUSED_SERVER_UNAVAILABLE      = 0x03,
    MQTT_CRC_REFUSED_BAD_USERNAME_PASSWORD   = 0x04,
    MQTT_CRC_REFUSED_NOT_AUTHORIZED          = 0x05
} mqtt_crc_t;

#define MQTT_IS_CRC(c) ((c) >= MQTT_CRC_ACCEPTED && (c) <= MQTT_CRC_REFUSED_NOT_AUTHORIZED)

static inline const char *
mqtt_crc_name(mqtt_crc_t crc) {
    switch (crc) {
    case MQTT_CRC_ACCEPTED:
        return "ACCEPTED";
    case MQTT_CRC_REFUSED_PROTOCOL_VERSION:
        return "REFUSED_PROTOCOL_VERSION";
    case MQTT_CRC_REFUSED_IDENTIFIER_REJECTED:
        return "REFUSED_IDENTIFIER_REJECTED";
    case MQTT_CRC_REFUSED_SERVER_UNAVAILABLE:
        return "REFUSED_SERVER_UNAVAILABLE";
    case MQTT_CRC_REFUSED_BAD_USERNAME_PASSWORD:
        return "REFUSED_BAD_USERNAME_PASSWORD";
    case MQTT_CRC_REFUSED_NOT_AUTHORIZED:
        return "REFUSED_NOT_AUTHORIZED";
    default:
        return "";
    }
}

/* mqtt subscribe return code for mqttv3.1.1 */
typedef enum {
    MQTT_SRC_QOS_0      = 0x00,
    MQTT_SRC_QOS_1      = 0x01,
    MQTT_SRC_QOS_2      = 0x02,
    MQTT_SRC_QOS_F      = 0x80
} mqtt_src_t;

#define MQTT_IS_SRC(c) (((c) >= MQTT_SRC_QOS_0 && (c) <= MQTT_SRC_QOS_2) || (c) == MQTT_SRC_QOS_F)

static inline const char *
mqtt_src_name(mqtt_src_t src) {
    switch (src) {
    case MQTT_SRC_QOS_0:
        return "Success - Maximum QoS 0";
    case MQTT_SRC_QOS_1:
        return "Success - Maximum QoS 1";
    case MQTT_SRC_QOS_2:
        return "Success - Maximum QoS 2";
    case MQTT_SRC_QOS_F:
        return "Failure";
    }
    return "";
}

static inline mqtt_src_t
mqtt_src_from_qos(mqtt_qos_t qos) {
    switch (qos) {
    case MQTT_QOS_0:
        return MQTT_SRC_QOS_0;
    case MQTT_QOS_1:
        return MQTT_SRC_QOS_1;
    case MQTT_QOS_2:
        return MQTT_SRC_QOS_2;
    }
    return MQTT_SRC_QOS_F;
}

/* mqtt reason code for mqttv5.0 */
typedef enum {
    MQTT_RC_SUCCESS                                 = 0x00,
    MQTT_RC_NORMAL_DISCONNECTION                    = 0x00,
    MQTT_RC_GRANTED_QOS_0                           = 0x00,
    MQTT_RC_GRANTED_QOS_1                           = 0x01,
    MQTT_RC_GRANTED_QOS_2                           = 0x02,
    MQTT_RC_DISCONNECT_WITH_WILL_MESSAGE            = 0x04,
    MQTT_RC_NO_MATCHING_SUBSCRIBERS                 = 0x10,
    MQTT_RC_NO_SUBSCRIPTION_EXISTED                 = 0x11,
    MQTT_RC_CONTINUE_AUTHENTICATION                 = 0x18,
    MQTT_RC_RE_AUTHENTICATE                         = 0x19,
    MQTT_RC_UNSPECIFIED_ERROR                       = 0x80,
    MQTT_RC_MALFORMED_PACKET                        = 0x81,
    MQTT_RC_PROTOCOL_ERROR                          = 0x82,
    MQTT_RC_IMPLEMENTATION_SPECIFIC_ERROR           = 0x83,
    MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION            = 0x84,
    MQTT_RC_CLIENT_IDENTIFIER_NOT_VALID             = 0x85,
    MQTT_RC_BAD_USERNAME_OR_PASSWORD                = 0x86,
    MQTT_RC_NOT_AUTHORIZED                          = 0x87,
    MQTT_RC_SERVER_UNAVAILABLE                      = 0x88,
    MQTT_RC_SERVER_BUSY                             = 0x89,
    MQTT_RC_BANNED                                  = 0x8A,
    MQTT_RC_SERVER_SHUTTING_DOWN                    = 0x8B,
    MQTT_RC_BAD_AUTHENTICATION_METHOD               = 0x8C,
    MQTT_RC_KEEP_ALIVE_TIMEOUT                      = 0x8D,
    MQTT_RC_SESSION_TAKEN_OVER                      = 0x8E,
    MQTT_RC_TOPIC_FILTER_INVALID                    = 0x8F,
    MQTT_RC_TOPIC_NAME_INVALID                      = 0x90,
    MQTT_RC_PACKET_IDENTIFIER_IN_USE                = 0x91,
    MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND             = 0x92,
    MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED                = 0x93,
    MQTT_RC_TOPIC_ALIAS_INVALID                     = 0x94,
    MQTT_RC_PACKET_TOO_LARGE                        = 0x95,
    MQTT_RC_MESSAGE_RATE_TOO_HIGH                   = 0x96,
    MQTT_RC_QUOTA_EXCEEDED                          = 0x97,
    MQTT_RC_ADMINISTRATIVE_ACTION                   = 0x98,
    MQTT_RC_PAYLOAD_FORMAT_INVALID                  = 0x99,
    MQTT_RC_RETAIN_NOT_SUPPORTED                    = 0x9A,
    MQTT_RC_QOS_NOT_SUPPORTED                       = 0x9B,
    MQTT_RC_USE_ANOTHER_SERVER                      = 0x9C,
    MQTT_RC_SERVER_MOVED                            = 0x9D,
    MQTT_RC_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED      = 0x9E,
    MQTT_RC_CONNECTION_RATE_EXCEEDED                = 0x9F,
    MQTT_RC_MAXIMUM_CONNECT_TIME                    = 0xA0,
    MQTT_RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED  = 0xA1,
    MQTT_RC_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED    = 0xA2
} mqtt_rc_t;

#define MQTT_IS_RC(rc) ((rc) >= MQTT_RC_SUCCESS && (rc) <= MQTT_RC_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED)

typedef struct {
    mqtt_rc_t rc;
    const char *name;
    mqtt_packet_type_t types[MQTT_AUTH];
} mqtt_rc_def_t;

extern const mqtt_rc_def_t MQTT_RC_DEFS[];
extern const int MQTT_RC_DEFS_COUNT;

#define MQTT_RC_DEFS_BY_RC_SIZE (MQTT_RC_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED + 1)
extern const mqtt_rc_def_t *const MQTT_RC_DEFS_BY_RC[MQTT_RC_DEFS_BY_RC_SIZE];

static inline mqtt_rc_t
mqtt_rc_from_qos(mqtt_qos_t qos) {
    switch (qos) {
    case MQTT_QOS_0:
        return MQTT_RC_GRANTED_QOS_0;
    case MQTT_QOS_1:
        return MQTT_RC_GRANTED_QOS_1;
    case MQTT_QOS_2:
        return MQTT_RC_GRANTED_QOS_2;
    }
    return MQTT_RC_UNSPECIFIED_ERROR;
}

static inline const char *
mqtt_rc_name(mqtt_rc_t rc) {
    const mqtt_rc_def_t *def;
    if ((int)rc < 0 || (int)rc >= MQTT_RC_DEFS_BY_RC_SIZE)
        return "";
    def = MQTT_RC_DEFS_BY_RC[rc];
    return def ? def->name : "";
}

static inline int
mqtt_rc_valid(mqtt_rc_t rc, mqtt_packet_type_t type) {
    int i, j;
    if ((int)rc < 0 || (int)rc >= MQTT_RC_DEFS_BY_RC_SIZE)
        return 0;
    /* rc 0x00 has aliases (Normal disconnection, Granted QoS 0), scan all defs. */
    for (i = 0; i < MQTT_RC_DEFS_COUNT; i++) {
        const mqtt_rc_def_t *def = &MQTT_RC_DEFS[i];
        if (def->rc != rc)
            continue;
        for (j = 0; j < MQTT_AUTH && def->types[j] != MQTT_RESERVED; j++) {
            if (def->types[j] == type)
                return 1;
        }
    }
    return 0;
}

/* mqtt-sn return code */
typedef enum {
    MQTT_SN_RC_ACCEPTED                        = 0x00,
    MQTT_SN_RC_REJECTED_CONGESTION             = 0x01,
    MQTT_SN_RC_REJECTED_TOPIC_ID               = 0x02,
    MQTT_SN_RC_REJECTED_NOT_SUPPORTED          = 0x03
} mqtt_sn_rc_t;

#define MQTT_SN_IS_RC(c) ((c) >= MQTT_SN_RC_ACCEPTED && (c) <= MQTT_SN_RC_REJECTED_NOT_SUPPORTED)

static inline const char *
mqtt_sn_rc_name(mqtt_sn_rc_t rc) {
    switch (rc) {
    case MQTT_SN_RC_ACCEPTED:
        return "ACCEPTED";
    case MQTT_SN_RC_REJECTED_CONGESTION:
        return "REJECTED_CONGESTION";
    case MQTT_SN_RC_REJECTED_TOPIC_ID:
        return "REJECTED_TOPIC_ID";
    case MQTT_SN_RC_REJECTED_NOT_SUPPORTED:
        return "REJECTED_NOT_SUPPORTED";
    }
    return "";
}

/* mqtt property code for mqttv5.0 */
typedef enum {
    MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR              = 0x01,
    MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL               = 0x02,
    MQTT_PROPERTY_CONTENT_TYPE                          = 0x03,
    MQTT_PROPERTY_RESPONSE_TOPIC                        = 0x08,
    MQTT_PROPERTY_CORRELATION_DATA                      = 0x09,
    MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER               = 0x0B,
    MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL               = 0x11,
    MQTT_PROPERTY_ASSIGNED_CLIENT_IDENTIFIER            = 0x12,
    MQTT_PROPERTY_SERVER_KEEP_ALIVE                     = 0x13,
    MQTT_PROPERTY_AUTHENTICATION_METHOD                 = 0x15,
    MQTT_PROPERTY_AUTHENTICATION_DATA                   = 0x16,
    MQTT_PROPERTY_REQUEST_PROBLEM_INFORMATION           = 0x17,
    MQTT_PROPERTY_WILL_DELAY_INTERVAL                   = 0x18,
    MQTT_PROPERTY_REQUEST_RESPONSE_INFORMATION          = 0x19,
    MQTT_PROPERTY_RESPONSE_INFORMATION                  = 0x1A,
    MQTT_PROPERTY_SERVER_REFERENCE                      = 0x1C,
    MQTT_PROPERTY_REASON_STRING                         = 0x1F,
    MQTT_PROPERTY_RECEIVE_MAXIMUM                       = 0x21,
    MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM                   = 0x22,
    MQTT_PROPERTY_TOPIC_ALIAS                           = 0x23,
    MQTT_PROPERTY_MAXIMUM_QOS                           = 0x24,
    MQTT_PROPERTY_RETAIN_AVAILABLE                      = 0x25,
    MQTT_PROPERTY_USER_PROPERTY                         = 0x26,
    MQTT_PROPERTY_MAXIMUM_PACKET_SIZE                   = 0x27,
    MQTT_PROPERTY_WILDCARD_SUBSCRIPTION_AVAILABLE       = 0x28,
    MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIERS_AVAILABLE    = 0x29,
    MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE         = 0x2A
} mqtt_property_code_t;

#define MQTT_IS_PROPERTY(p) \
    ((p) >= MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR && (p) <= MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE)

/* define type of mqtt property for mqttv5.0 */
typedef enum {
    MQTT_PROPERTY_TYPE_BYTE,
    MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER,
    MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER,
    MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER,
    MQTT_PROPERTY_TYPE_BINARY_DATA,
    MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING,
    MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR
} mqtt_property_type_t;

typedef struct {
    mqtt_property_code_t code;
    const char *name;
    mqtt_property_type_t type;
    mqtt_packet_type_t types[MQTT_AUTH];
    int will;
} mqtt_property_def_t;

extern const mqtt_property_def_t MQTT_PROPERTY_DEFS[];
extern const int MQTT_PROPERTY_DEFS_COUNT;

#define MQTT_PROPERTY_DEFS_BY_CODE_SIZE (MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE + 1)
extern const mqtt_property_def_t *const MQTT_PROPERTY_DEFS_BY_CODE[MQTT_PROPERTY_DEFS_BY_CODE_SIZE];

static inline mqtt_property_type_t
mqtt_property_type(mqtt_property_code_t code) {
    const mqtt_property_def_t *def;
    if ((int)code < 0 || (int)code >= MQTT_PROPERTY_DEFS_BY_CODE_SIZE)
        return MQTT_PROPERTY_TYPE_BYTE;
    def = MQTT_PROPERTY_DEFS_BY_CODE[code];
    return def ? def->type : MQTT_PROPERTY_TYPE_BYTE;
}

typedef enum {
    MQTT_SN_TOPIC_ID_TYPE_NORMAL = 0b00,
    MQTT_SN_TOPIC_ID_TYPE_PREDEFINED = 0b01,
    MQTT_SN_TOPIC_ID_TYPE_SHORT = 0b10,
    MQTT_SN_TOPIC_ID_TYPE_RESERVED = 0b11
} mqtt_sn_topic_id_type_t;

#define MQTT_P_PINGREQ            {0xc0, 0x00}
#define MQTT_P_PINGRESP           {0xd0, 0x00}
#define MQTT_P_DISCONNECT         {0xe0, 0x00}
#define MQTT_P_PUBACK(id)         {0x40, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff)}
#define MQTT_P_PUBREC(id)         {0x50, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff)}
#define MQTT_P_PUBREL(id)         {0x62, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff)}
#define MQTT_P_PUBREL_RC(id, rc)  {0x62, 0x04, (((id)&0xff00)>>8), ((id)&0x00ff), ((rc)&0xff), 0x00}
#define MQTT_P_PUBCOMP(id)        {0x70, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff)}
#define MQTT_P_PUBCOMP_RC(id, rc) {0x70, 0x04, (((id)&0xff00)>>8), ((id)&0x00ff), ((rc)&0xff), 0x00}
#define MQTT_P_UNSUBACK(id)       {0xb0, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff)}
#define MQTT_P_CONNACK(caf, crc)  {0x20, 0x02, caf, crc}

#define MQTT_SN_P_ADVERTISE(gwid, duration)         {0x05, 0x00, gwid, (((duration)&0xff00)>>8), ((duration)&0x00ff)}
#define MQTT_SN_P_SEARCHGW(radius)                  {0x03, 0x01, radius}
#define MQTT_SN_P_CONNACK(rc)                       {0x03, 0x05, rc}
#define MQTT_SN_P_WILLTOPICREQ                      {0x02, 0x06}
#define MQTT_SN_P_REGACK(tid, mid, rc)              {0x07, 0x0B, (((tid)&0xff00)>>8), ((tid)&0x00ff), (((mid)&0xff00)>>8), ((mid)&0x00ff), rc}
#define MQTT_SN_P_PUBACK(tid, mid, rc)              {0x07, 0x0D, (((tid)&0xff00)>>8), ((tid)&0x00ff), (((mid)&0xff00)>>8), ((mid)&0x00ff), rc}
#define MQTT_SN_P_PUBREC(mid)                       {0x05, 0x0F, (((mid)&0xff00)>>8), ((mid)&0x00ff)}
#define MQTT_SN_P_PUBREL(mid)                       {0x04, 0x10, (((mid)&0xff00)>>8), ((mid)&0x00ff)}
#define MQTT_SN_P_PUBCOMP(mid)                      {0x04, 0x0E, (((mid)&0xff00)>>8), ((mid)&0x00ff)}
#define MQTT_SN_P_SUBACK(qos, tid, mid, rc)         {0x08, 0x13, ((qos)<<5), (((tid)&0xff00)>>8), ((tid)&0x00ff), (((mid)&0xff00)>>8), ((mid)&0x00ff), rc}
#define MQTT_SN_P_UNSUBACK(mid)                     {0x04, 0x15, (((mid)&0xff00)>>8), ((mid)&0x00ff)}
#define MQTT_SN_P_PINGREQ                           {0x02, 0x16}
#define MQTT_SN_P_PINGRESP                          {0x02, 0x17}
#define MQTT_SN_P_WILLTOPICRESP(rc)                 {0x03, 0x1B, rc}
#define MQTT_SN_P_WILLMSGRESP(rc)                   {0x03, 0x1D, rc}

#define MQTT_STR_INITIALIZER {0, 0, 0}

#define MQTT_STR_PRINT(str) (int)(str).n, (str).s

/*
 * mqtt string/buffer.
 * s - buffer pointer, i - write index, n - capacity (for owned/borrowed data)
 * or total length (for parsed strings).
 */
typedef struct {
    char *s;
    size_t i;
    size_t n;
} mqtt_str_t;

/* parser error codes, report via mqtt_strerror(). */
typedef enum {
    MQTT_OK = 0,
    MQTT_ERR_NOMEM,
    MQTT_ERR_MALFORMED,
    MQTT_ERR_PROTOCOL,
    MQTT_ERR_TOO_LARGE,
    MQTT_ERR_UNSUPPORTED,
    MQTT_ERR_INVALID_ARG,
} mqtt_error_t;

const char *mqtt_strerror(mqtt_error_t err);

typedef struct mqtt_property_s {
    mqtt_property_code_t code;
    union {
        uint8_t b1;
        uint16_t b2;
        uint32_t b4;
        uint32_t bv;
        mqtt_str_t str;
        mqtt_str_t data;
        struct {
            mqtt_str_t name;
            mqtt_str_t value;
        } pair;
    };
    struct mqtt_property_s *next;
} mqtt_property_t;

#define MQTT_PROPERTIES_INITIALIZER {0, 0}

typedef struct {
    mqtt_property_t *head;
    size_t length;
} mqtt_properties_t;

/* fixed header flags: bit0 retain, bit1-2 qos, bit3 dup, bit4-7 type
 * (MQTT 3.1.1 §2.2). */
#define MQTT_FH_TYPE(f)            (((f) >> 4) & 0x0F)
#define MQTT_FH_DUP(f)             (((f) >> 3) & 0x01)
#define MQTT_FH_QOS(f)             (((f) >> 1) & 0x03)
#define MQTT_FH_RETAIN(f)          ((f) & 0x01)
#define MQTT_FH_BUILD(t, d, q, r)  ((((t) & 0x0F) << 4) | (((d) & 0x01) << 3) | (((q) & 0x03) << 1) | ((r) & 0x01))

typedef struct {
    uint8_t flags;
} mqtt_fixed_header_t;

typedef struct {
    uint32_t will_delay_interval;
    uint8_t payload_format_indicator;
    uint32_t message_expiry_interval;
    mqtt_str_t content_type;
    mqtt_str_t response_topic;
    mqtt_str_t correlation_data;
    struct {
        mqtt_str_t name;
        mqtt_str_t value;
    } user_property;
} mqtt_will_prop_t;

typedef struct {
    uint32_t session_expiry_interval;
    uint16_t receive_maximum;
    uint32_t maximum_packet_size;
    uint16_t topic_alias_maximum;
    uint8_t request_response_information;
    uint8_t request_problem_information;
    mqtt_str_t user_property;
    mqtt_str_t authentication_method;
    mqtt_str_t authentication_data;
} mqtt_connect_prop_t;

/* connect flags bits. */
#define MQTT_CF_RESERVED         0x01
#define MQTT_CF_CLEAN_SESSION    0x02
#define MQTT_CF_WILL_FLAG        0x04
#define MQTT_CF_WILL_QOS_MASK    0x18
#define MQTT_CF_WILL_QOS(f)      (((f) >> 3) & 0x03)
#define MQTT_CF_WILL_RETAIN      0x20
#define MQTT_CF_PASSWORD         0x40
#define MQTT_CF_USERNAME         0x80

typedef struct {
    mqtt_str_t protocol_name;
    mqtt_version_t protocol_version;
    uint8_t connect_flags;
    uint16_t keep_alive;
    struct {
        mqtt_properties_t properties;
    } v5;
} mqtt_v_connect_t;

typedef struct {
    mqtt_str_t client_id;
    struct {
        mqtt_properties_t will_properties;
    } v5;
    mqtt_str_t will_topic;
    mqtt_str_t will_message;
    mqtt_str_t username;
    mqtt_str_t password;
} mqtt_p_connect_t;

typedef struct {
    uint32_t session_expiry_interval;
    uint16_t receive_maximum;
    uint8_t maximum_qos;
    uint8_t retain_available;
    uint32_t maximum_packet_size;
    mqtt_str_t assigned_client_identifier;
    uint16_t topic_alias_maximum;
    mqtt_str_t reason_string;
    mqtt_str_t user_property;
    uint8_t wildcard_subscription_available;
    uint8_t subscription_identifiers_available;
    uint8_t shared_subscription_available;
    uint16_t server_keep_alive;
    mqtt_str_t response_information;
    mqtt_str_t server_reference;
    mqtt_str_t authentication_method;
    mqtt_str_t authentication_data;
} mqtt_connack_prop_t;

#define MQTT_ACK_SESSION_PRESENT 0x01

typedef struct {
    uint8_t flags;
} mqtt_connect_acknowledge_t;

typedef struct {
    struct {
        mqtt_crc_t return_code;
    } v3;
    struct {
        mqtt_connect_acknowledge_t acknowledge_flags;
        mqtt_crc_t return_code;
    } v4;
    struct {
        mqtt_connect_acknowledge_t acknowledge_flags;
        mqtt_rc_t reason_code;
        mqtt_properties_t properties;
    } v5;
} mqtt_v_connack_t;

typedef struct {
    uint8_t payload_format_indicator;
    uint32_t message_expiry_interval;
    uint16_t topic_alias;
    mqtt_str_t response_topic;
    mqtt_str_t correlation_data;
    mqtt_str_t user_property;
    uint32_t subscription_identifier;
    mqtt_str_t content_type;
} mqtt_publish_prop_t;

typedef struct {
    mqtt_str_t topic_name;
    uint16_t packet_id;
    struct {
        mqtt_properties_t properties;
    } v5;
} mqtt_v_publish_t;

typedef struct {
    mqtt_str_t message;
} mqtt_p_publish_t;

typedef struct {
    mqtt_str_t reason_string;
    mqtt_str_t user_property;
} mqtt_puback_prop_t;

typedef struct {
    uint16_t packet_id;
    struct {
        mqtt_rc_t reason_code;
        mqtt_properties_t properties;
    } v5;
} mqtt_v_puback_t;

typedef struct {
    mqtt_str_t reason_string;
    mqtt_str_t user_property;
} mqtt_pubrec_prop_t;

typedef struct {
    uint16_t packet_id;
    struct {
        mqtt_rc_t reason_code;
        mqtt_properties_t properties;
    } v5;
} mqtt_v_pubrec_t;

typedef struct {
    mqtt_str_t reason_string;
    mqtt_str_t user_property;
} mqtt_pubrel_prop_t;

typedef struct {
    uint16_t packet_id;
    struct {
        mqtt_rc_t reason_code;
        mqtt_properties_t properties;
    } v5;
} mqtt_v_pubrel_t;

typedef struct {
    mqtt_str_t reason_string;
    mqtt_str_t user_property;
} mqtt_pubcomp_prop_t;

typedef struct {
    uint16_t packet_id;
    struct {
        mqtt_rc_t reason_code;
        mqtt_properties_t properties;
    } v5;
} mqtt_v_pubcomp_t;

typedef struct {
    uint32_t subscription_identifier;
    mqtt_str_t user_property;
} mqtt_subscribe_prop_t;

typedef struct {
    uint16_t packet_id;
    struct {
        mqtt_properties_t properties;
    } v5;
} mqtt_v_subscribe_t;

#define MQTT_SUBSCRIBE_OPTIONS_INITIALIZER {.flags = 0}

/* subscribe options bits. */
#define MQTT_SUBOPT_QOS_MASK      0x03
#define MQTT_SUBOPT_NL            0x04
#define MQTT_SUBOPT_RAP           0x08
#define MQTT_SUBOPT_RH_MASK       0x30
#define MQTT_SUBOPT_RH(f)         (((f) >> 4) & 0x03)

typedef struct {
    uint8_t flags;
} mqtt_subscribe_options_t;

typedef struct {
    mqtt_str_t *topic_filters;
    mqtt_subscribe_options_t *options;
    int n;
} mqtt_p_subscribe_t;

typedef struct {
    mqtt_str_t reason_string;
    mqtt_str_t user_property;
} mqtt_suback_prop_t;

typedef struct {
    uint16_t packet_id;
    struct {
        mqtt_properties_t properties;
    } v5;
} mqtt_v_suback_t;

#define MQTT_SUBACK_GRANTED_INITIALIZER {.flags = 0}

typedef struct {
    uint8_t flags;
} mqtt_suback_granted_t;

typedef struct {
    struct {
        mqtt_suback_granted_t *granted;
    } v3;
    struct {
        mqtt_src_t *return_codes;
    } v4;
    struct {
        mqtt_rc_t *reason_codes;
    } v5;
    int n;
} mqtt_p_suback_t;

typedef struct {
    mqtt_str_t user_property;
} mqtt_unsubscribe_prop_t;

typedef struct {
    uint16_t packet_id;
    struct {
        mqtt_properties_t properties;
    } v5;
} mqtt_v_unsubscribe_t;

typedef struct {
    mqtt_str_t *topic_filters;
    int n;
} mqtt_p_unsubscribe_t;

typedef struct {
    mqtt_str_t reason_string;
    mqtt_str_t user_property;
} mqtt_unsuback_prop_t;

typedef struct {
    uint16_t packet_id;
    struct {
        mqtt_properties_t properties;
    } v5;
} mqtt_v_unsuback_t;

typedef struct {
    struct {
        mqtt_rc_t *reason_codes;
        int n;
    } v5;
} mqtt_p_unsuback_t;

typedef struct {
    uint32_t session_expiry_interval;
    mqtt_str_t reason_string;
    mqtt_str_t user_property;
    mqtt_str_t server_reference;
} mqtt_disconnect_prop_t;

typedef struct {
    struct {
        mqtt_rc_t reason_code;
        mqtt_properties_t properties;
    } v5;
} mqtt_v_disconnect_t;

typedef struct {
    mqtt_str_t authentication_method;
    mqtt_str_t authentication_data;
    mqtt_str_t reason_string;
    mqtt_str_t user_property;
} mqtt_auth_prop_t;

typedef struct {
    struct {
        mqtt_rc_t reason_code;
        mqtt_properties_t properties;
    } v5;
} mqtt_v_auth_t;

typedef union {
    mqtt_v_connect_t connect;
    mqtt_v_connack_t connack;
    mqtt_v_publish_t publish;
    mqtt_v_puback_t puback;
    mqtt_v_pubrec_t pubrec;
    mqtt_v_pubrel_t pubrel;
    mqtt_v_pubcomp_t pubcomp;
    mqtt_v_subscribe_t subscribe;
    mqtt_v_suback_t suback;
    mqtt_v_unsubscribe_t unsubscribe;
    mqtt_v_unsuback_t unsuback;
    mqtt_v_disconnect_t disconnect;
    mqtt_v_auth_t auth;
} mqtt_variable_header_t;

typedef union {
    mqtt_p_connect_t connect;
    mqtt_p_publish_t publish;
    mqtt_p_subscribe_t subscribe;
    mqtt_p_suback_t suback;
    mqtt_p_unsubscribe_t unsubscribe;
    mqtt_p_unsuback_t unsuback;
} mqtt_payload_t;

typedef struct {
    mqtt_version_t ver;
    mqtt_fixed_header_t f;
    mqtt_variable_header_t v;
    mqtt_payload_t p;
    mqtt_str_t b;
} mqtt_packet_t;

typedef enum { MQTT_ST_FIXED, MQTT_ST_LENGTH, MQTT_ST_REMAIN } mqtt_parser_state_t;

typedef struct {
    mqtt_version_t version;
    mqtt_parser_state_t state;
    size_t require;
    int multiplier;
    mqtt_error_t error;
    mqtt_packet_t pkt;
} mqtt_parser_t;

/* mqtt-sn flags bits: bit0-1 topic id type, bit2 clean session, bit3 will,
 * bit4 retain, bit5-6 qos, bit7 dup. */
#define MQTT_SNF_TID_TYPE_MASK    0x03
#define MQTT_SNF_TID_TYPE(f)      ((f) & 0x03)
#define MQTT_SNF_CLEAN_SESSION    0x04
#define MQTT_SNF_WILL             0x08
#define MQTT_SNF_RETAIN           0x10
#define MQTT_SNF_QOS_MASK         0x60
#define MQTT_SNF_QOS(f)           (((f) >> 5) & 0x03)
#define MQTT_SNF_DUP              0x80

typedef struct {
    uint8_t flag;
} mqtt_sn_flags_t;

#define MQTT_SN_TOPIC_INITIALIZER {0, .id = 0}

typedef struct {
    mqtt_sn_topic_id_type_t type;
    union {
        uint16_t id;
        char shor[2];
        mqtt_str_t name;
    };
} mqtt_sn_topic_t;

typedef struct {
    uint8_t gwid;
    uint16_t duration;
} mqtt_sn_v_advertise_t;

typedef struct {
    uint8_t radius;
} mqtt_sn_v_searchgw_t;

typedef struct {
    uint8_t gwid;
    mqtt_str_t gwadd;
} mqtt_sn_v_gwinfo_t;

typedef struct {
    mqtt_sn_flags_t flags;
    uint8_t protocol_id;
    uint16_t duration;
    mqtt_str_t client_id;
} mqtt_sn_v_connect_t;

typedef struct {
    mqtt_sn_rc_t return_code;
} mqtt_sn_v_connack_t;

typedef struct {
    mqtt_sn_flags_t flags;
    mqtt_str_t topic_name;
} mqtt_sn_v_willtopic_t;

typedef struct {
    mqtt_str_t message;
} mqtt_sn_v_willmsg_t;

typedef struct {
    uint16_t topic_id;
    uint16_t msg_id;
    mqtt_str_t topic_name;
} mqtt_sn_v_register_t;

typedef struct {
    uint16_t topic_id;
    uint16_t msg_id;
    mqtt_sn_rc_t return_code;
} mqtt_sn_v_regack_t;

typedef struct {
    mqtt_sn_flags_t flags;
    mqtt_sn_topic_t topic;
    uint16_t msg_id;
    mqtt_str_t data;
} mqtt_sn_v_publish_t;

typedef struct {
    mqtt_sn_topic_t topic;
    uint16_t msg_id;
    mqtt_sn_rc_t return_code;
} mqtt_sn_v_puback_t;

typedef struct {
    uint16_t msg_id;
} mqtt_sn_v_pubrec_t;

typedef struct {
    uint16_t msg_id;
} mqtt_sn_v_pubrel_t;

typedef struct {
    uint16_t msg_id;
} mqtt_sn_v_pubcomp_t;

typedef struct {
    mqtt_sn_flags_t flags;
    uint16_t msg_id;
    mqtt_sn_topic_t topic;
} mqtt_sn_v_subscribe_t;

typedef struct {
    mqtt_sn_flags_t flags;
    uint16_t topic_id;
    uint16_t msg_id;
    mqtt_sn_rc_t return_code;
} mqtt_sn_v_suback_t;

typedef struct {
    mqtt_sn_flags_t flags;
    uint16_t msg_id;
    mqtt_sn_topic_t topic;
} mqtt_sn_v_unsubscribe_t;

typedef struct {
    uint16_t msg_id;
} mqtt_sn_v_unsuback_t;

typedef struct {
    mqtt_str_t client_id;
} mqtt_sn_v_pingreq_t;

typedef struct {
    uint16_t duration;
} mqtt_sn_v_disconnect_t;

typedef struct {
    mqtt_sn_flags_t flags;
    mqtt_str_t topic_name;
} mqtt_sn_v_willtopicupd_t;

typedef struct {
    mqtt_str_t message;
} mqtt_sn_v_willmsgupd_t;

typedef struct {
    mqtt_sn_rc_t return_code;
} mqtt_sn_v_willtopicresp_t;

typedef struct {
    mqtt_sn_rc_t return_code;
} mqtt_sn_v_willmsgresp_t;

/* encapsulated ctrl bits. */
#define MQTT_ENC_RADIUS 0x01

typedef struct {
    uint8_t ctrl;
    uint8_t radius;
    mqtt_str_t message;
} mqtt_sn_v_encapsulated_t;

typedef struct {
    mqtt_sn_packet_type_t type;
    union {
        mqtt_sn_v_advertise_t advertise;
        mqtt_sn_v_searchgw_t searchgw;
        mqtt_sn_v_gwinfo_t gwinfo;
        mqtt_sn_v_connect_t connect;
        mqtt_sn_v_connack_t connack;
        mqtt_sn_v_willtopic_t willtopic;
        mqtt_sn_v_willmsg_t willmsg;
        mqtt_sn_v_register_t regist;
        mqtt_sn_v_regack_t regack;
        mqtt_sn_v_publish_t publish;
        mqtt_sn_v_puback_t puback;
        mqtt_sn_v_pubrec_t pubrec;
        mqtt_sn_v_pubrel_t pubrel;
        mqtt_sn_v_pubcomp_t pubcomp;
        mqtt_sn_v_subscribe_t subscribe;
        mqtt_sn_v_suback_t suback;
        mqtt_sn_v_unsubscribe_t unsubscribe;
        mqtt_sn_v_unsuback_t unsuback;
        mqtt_sn_v_pingreq_t pingreq;
        mqtt_sn_v_disconnect_t disconnect;
        mqtt_sn_v_willtopicupd_t willtopicupd;
        mqtt_sn_v_willmsgupd_t willmsgupd;
        mqtt_sn_v_willtopicresp_t willtopicresp;
        mqtt_sn_v_willmsgresp_t willmsgresp;
        mqtt_sn_v_encapsulated_t encapsulated;
    } v;
    mqtt_str_t b;
} mqtt_sn_packet_t;

typedef enum {
    MQTT_SN_GATEWAY_TRANSPARENT,
    MQTT_SN_GATEWAY_AGGREGATING,
} mqtt_sn_gateway_transmission_t;

typedef enum { MQTT_SN_ST_LENGTH, MQTT_SN_ST_TYPE, MQTT_SN_ST_REMAIN } mqtt_sn_parser_state_t;

typedef struct {
    mqtt_sn_parser_state_t state;
    size_t require;
    int multiplier;
    mqtt_error_t error;
    mqtt_sn_packet_t pkt;
} mqtt_sn_parser_t;

typedef void *(*mqtt_malloc_func_t)(size_t size);
typedef void (*mqtt_free_func_t)(void *ptr);

extern mqtt_malloc_func_t mqtt_malloc;
extern mqtt_free_func_t mqtt_free;

#define MQTT_MALLOC(size) (mqtt_malloc ? mqtt_malloc(size) : malloc(size))
#define MQTT_FREE(ptr) (mqtt_free ? mqtt_free(ptr) : free(ptr))

void mqtt_set_allocator(mqtt_malloc_func_t malloc_func, mqtt_free_func_t free_func);

static inline int
mqtt_str_init(mqtt_str_t *b, char *s, size_t n) {
    if (!b)
        return -1;
    b->s = s;
    b->i = 0;
    b->n = n;
    return 0;
}

static inline int
mqtt_str_dup(mqtt_str_t *b, const char *s) {
    if (!b || !s)
        return -1;
    b->n = strlen(s);
    b->i = 0;
    if (b->n > 0) {
        b->s = (char *)MQTT_MALLOC(b->n);
        if (!b->s) {
            b->n = 0;
            return -1;
        }
        memcpy(b->s, s, b->n);
    } else {
        b->s = 0;
    }
    return 0;
}

static inline int
mqtt_str_dup_n(mqtt_str_t *b, const char *s, size_t n) {
    if (!b || !s || !n)
        return -1;
    b->n = n;
    b->i = 0;
    b->s = (char *)MQTT_MALLOC(n);
    if (!b->s) {
        b->n = 0;
        return -1;
    }
    memcpy(b->s, s, n);
    return 0;
}

static inline int
mqtt_str_from(mqtt_str_t *b, const char *s) {
    if (!b || !s)
        return -1;
    b->s = (char *)s;
    b->n = strlen(s);
    b->i = 0;
    return 0;
}

static inline int
mqtt_str_strcmp(mqtt_str_t *b, const char *s) {
    if (!b || !b->s || !s)
        return -1;
    size_t slen = strlen(s);
    int rc = strncmp(b->s, s, b->n);
    if (rc != 0)
        return rc;
    if (b->n < slen)
        return -1;
    if (b->n > slen)
        return 1;
    return 0;
}

static inline int
mqtt_str_equal(mqtt_str_t *b, mqtt_str_t *s) {
    if (!b || !s)
        return 0;
    if (b->n != s->n)
        return 0;
    if (b->n == 0)
        return 1;
    return !strncmp(b->s, s->s, b->n);
}

static inline int
mqtt_str_copy(mqtt_str_t *b, mqtt_str_t *s) {
    if (!b || !s)
        return -1;
    b->s = 0;
    b->i = 0;
    b->n = 0;
    if (s->s && s->n > 0) {
        b->s = (char *)MQTT_MALLOC(s->n);
        if (!b->s)
            return -1;
        memcpy(b->s, s->s, s->n);
        b->n = s->n;
        b->i = s->i;
    }
    return 0;
}

static inline int
mqtt_str_concat(mqtt_str_t *b, const mqtt_str_t *s) {
    if (!b || !s)
        return -1;
    if (s->n > 0 && (b->i > SIZE_MAX - s->n || b->i + s->n > b->n))
        return -1;
    if (s->s && s->n > 0) {
        memcpy(b->s + b->i, s->s, s->n);
        b->i += s->n;
    }
    return 0;
}

static inline int
mqtt_str_set(mqtt_str_t *b, const mqtt_str_t *s) {
    if (!b || !s)
        return -1;
    b->s = s->s;
    b->i = s->i;
    b->n = s->n;
    return 0;
}

static inline int
mqtt_str_empty(const mqtt_str_t *b) {
    return (!b || !b->s || !b->n);
}

static inline void
mqtt_str_free(mqtt_str_t *b) {
    if (b && b->s) {
        MQTT_FREE(b->s);
        b->s = 0;
        b->i = 0;
        b->n = 0;
    }
}

static inline void
mqtt_str_dump(const mqtt_str_t *b, void *ud, void (*print)(void *, const char *)) {
    size_t line, lines;
    if (!b || !b->s || !b->n)
        return;
    lines = (b->n - 1) / 0x10;
    for (line = 0; line <= lines; line++) {
        size_t i, n, idx;
        uint8_t *p;
        char buf[0x100] = {0};
        n = b->n - line * 0x10;
        if (n > 0x10)
            n = 0x10;
        p = ((uint8_t *)b->s + line * 0x10);
        idx = snprintf(buf, sizeof(buf), "%08zx: ", line * 0x10);
        for (i = 0; i < 0x10; i++) {
            if (i == 0x08)
                idx += snprintf(buf + idx, sizeof(buf) - idx, " ");
            if (i >= n)
                idx += snprintf(buf + idx, sizeof(buf) - idx, "  ");
            else
                idx += snprintf(buf + idx, sizeof(buf) - idx, "%02x", p[i]);
            if (i % 0x02 != 0)
                idx += snprintf(buf + idx, sizeof(buf) - idx, " ");
        }
        idx += snprintf(buf + idx, sizeof(buf) - idx, "  ");
        for (i = 0; i < 0x10; i++) {
            if (i >= n) {
                idx += snprintf(buf + idx, sizeof(buf) - idx, " ");
            } else {
                uint8_t c = p[i];
                if (c >= 0x20 && c <= 0x7f)
                    idx += snprintf(buf + idx, sizeof(buf) - idx, "%c", c);
                else
                    idx += snprintf(buf + idx, sizeof(buf) - idx, ".");
            }
        }
        idx += snprintf(buf + idx, sizeof(buf) - idx, "\n");
        if (line % 0x10 == 0x0f)
            idx += snprintf(buf + idx, sizeof(buf) - idx, "\n");
        if (print)
            print(ud, buf);
        else
            printf("%s", buf);
    }
}

static inline size_t
mqtt_vbi_length(size_t length) {
    if (length < 0x80)
        return 1;
    else if (length < 0x4000)
        return 2;
    else if (length < 0x200000)
        return 3;
    else
        return 4;
}

static inline int
mqtt_str_read_utf(mqtt_str_t *b, mqtt_str_t *r) {
    if (!b || !r || !b->s)
        return -1;
    if (b->i + 2 > b->n)
        return -1;
    uint8_t *s = (uint8_t *)(b->s + b->i);
    size_t n = ((*s << 8) + *(s + 1));
    if (n > b->n - b->i - 2)
        return -1;
    r->n = n;
    r->s = b->s + b->i + 2;
    r->i = 0;
    b->i += n + 2;
    return 0;
}

static inline int
mqtt_str_read_u8(mqtt_str_t *b, uint8_t *c8) {
    if (!b || !c8 || !b->s)
        return -1;
    if (b->i + 1 > b->n)
        return -1;
    *c8 = *(uint8_t *)(b->s + b->i);
    b->i += 1;
    return 0;
}

static inline int
mqtt_str_read_u16(mqtt_str_t *b, uint16_t *u16) {
    if (!b || !u16 || !b->s)
        return -1;
    if (b->i + 2 > b->n)
        return -1;
    uint8_t *s = (uint8_t *)(b->s + b->i);
    *u16 = ((uint16_t)(*s << 8) + (uint16_t)(*(s + 1)));
    b->i += 2;
    return 0;
}

static inline int
mqtt_str_read_u32(mqtt_str_t *b, uint32_t *u32) {
    if (!b || !u32 || !b->s)
        return -1;
    if (b->i + 4 > b->n)
        return -1;
    uint8_t *s = (uint8_t *)(b->s + b->i);
    *u32 = ((uint32_t)(*s << 24) + (uint32_t)(*(s + 1) << 16) + (uint32_t)(*(s + 2) << 8) + (uint32_t)(*(s + 3)));
    b->i += 4;
    return 0;
}

static inline int
mqtt_str_read_vbi(mqtt_str_t *b, uint32_t *vbi) {
    if (!b || !vbi || !b->s)
        return -1;
    uint32_t multiplier = 1;
    uint8_t c;
    *vbi = 0;
    do {
        if (b->i >= b->n)
            return -1;
        c = *(uint8_t *)(b->s + b->i);
        b->i++;
        *vbi += (uint32_t)(c & 0x7F) * multiplier;
        if ((c & 0x80) == 0)
            return 0;
        /* a vbi is at most 4 bytes (max value 0x0FFFFFFF) */
        if (multiplier == 0x80 * 0x80 * 0x80)
            return -1;
        multiplier *= 0x80;
    } while (1);
}

static inline int
mqtt_str_read_all(mqtt_str_t *b, mqtt_str_t *r) {
    if (!b || !r || !b->s)
        return -1;
    r->s = b->s + b->i;
    r->n = b->n - b->i;
    b->i = b->n;
    return 0;
}

static inline int
mqtt_str_write_utf(mqtt_str_t *b, const mqtt_str_t *r) {
    if (!b || !r || !b->s)
        return -1;
    if (r->n > 0xFFFF || b->i > b->n || 2 + r->n > b->n - b->i)
        return -1;
    b->s[b->i++] = (char)((r->n & 0xff00) >> 8);
    b->s[b->i++] = (char)(r->n & 0x00ff);
    if (r->n > 0 && r->s) {
        memcpy(&b->s[b->i], r->s, r->n);
        b->i += r->n;
    }
    return 0;
}

static inline int
mqtt_str_write_u8(mqtt_str_t *b, uint8_t r) {
    if (!b || !b->s)
        return -1;
    if (b->i > b->n || 1 > b->n - b->i)
        return -1;
    b->s[b->i++] = (char)r;
    return 0;
}

static inline int
mqtt_str_write_u16(mqtt_str_t *b, uint16_t r) {
    if (!b || !b->s)
        return -1;
    if (b->i > b->n || 2 > b->n - b->i)
        return -1;
    b->s[b->i++] = (char)((r & 0xff00) >> 8);
    b->s[b->i++] = (char)(r & 0x00ff);
    return 0;
}

static inline int
mqtt_str_write_u32(mqtt_str_t *b, uint32_t r) {
    if (!b || !b->s)
        return -1;
    if (b->i > b->n || 4 > b->n - b->i)
        return -1;
    b->s[b->i++] = (char)((r & 0xff000000) >> 24);
    b->s[b->i++] = (char)((r & 0x00ff0000) >> 16);
    b->s[b->i++] = (char)((r & 0x0000ff00) >> 8);
    b->s[b->i++] = (char)(r & 0x000000ff);
    return 0;
}

static inline int
mqtt_str_write_vbi(mqtt_str_t *b, uint32_t vbi) {
    if (!b || !b->s)
        return -1;
    if (vbi >= (1U << 28))
        return -1;
    do {
        uint8_t c;
        c = vbi % 0x80;
        vbi /= 0x80;
        if (vbi > 0)
            c |= 0x80;
        if (b->i > b->n || 1 > b->n - b->i)
            return -1;
        b->s[b->i++] = (char)c;
    } while (vbi > 0);
    return 0;
}

/* read a utf-8 encoded string and validate it ([MQTT-1.5.3]). */
static inline int mqtt_utf8_validate(const mqtt_str_t *s);

static inline int
mqtt_str_read_utf8(mqtt_str_t *b, mqtt_str_t *r) {
    if (mqtt_str_read_utf(b, r))
        return -1;
    return mqtt_utf8_validate(r);
}

static inline int
mqtt_topic_wildcard(const mqtt_str_t *topic) {
    size_t i;
    for (i = 0; i < topic->n; i++) {
        const char *c;
        c = topic->s + i;
        if (*c == '#' || *c == '+')
            return 1;
    }
    return 0;
}

static inline int
mqtt_topic_name_validate(const mqtt_str_t *topic) {
    size_t i;

    if (!topic || !topic->s || topic->n == 0)
        return -1;

    for (i = 0; i < topic->n; i++) {
        char c = topic->s[i];
        if (c == '+' || c == '#')
            return -1;
    }

    return 0;
}

static inline int
mqtt_topic_filter_validate(const mqtt_str_t *filter) {
    size_t i, len;
    const char *s;

    if (!filter || !filter->s || filter->n == 0)
        return -1;

    s = filter->s;
    len = filter->n;

    for (i = 0; i < len; i++) {
        char c = s[i];

        if (c == '+') {
            if (i > 0 && s[i - 1] != '/')
                return -1;
            if (i + 1 < len && s[i + 1] != '/')
                return -1;
        } else if (c == '#') {
            if (i != len - 1)
                return -1;
            if (i > 0 && s[i - 1] != '/')
                return -1;
        }
    }

    return 0;
}

static inline int
mqtt_utf8_validate(const mqtt_str_t *s) {
    size_t i = 0;

    if (!s || !s->s)
        return (s && s->n == 0) ? 0 : -1;

    while (i < s->n) {
        uint8_t c = (uint8_t)s->s[i];

        if (c == 0)
            return -1;

        if (c <= 0x7F) {
            i++;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= s->n || ((uint8_t)s->s[i + 1] & 0xC0) != 0x80)
                return -1;
            if (c == 0xC0 || c == 0xC1)
                return -1;
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= s->n || ((uint8_t)s->s[i + 1] & 0xC0) != 0x80 || ((uint8_t)s->s[i + 2] & 0xC0) != 0x80)
                return -1;
            if (c == 0xE0 && (uint8_t)s->s[i + 1] < 0xA0)
                return -1;
            if (c == 0xED && (uint8_t)s->s[i + 1] >= 0xA0)
                return -1;
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= s->n || ((uint8_t)s->s[i + 1] & 0xC0) != 0x80 || ((uint8_t)s->s[i + 2] & 0xC0) != 0x80 ||
                ((uint8_t)s->s[i + 3] & 0xC0) != 0x80)
                return -1;
            if (c == 0xF0 && (uint8_t)s->s[i + 1] < 0x90)
                return -1;
            if (c > 0xF4)
                return -1;
            if (c == 0xF4 && (uint8_t)s->s[i + 1] > 0x8F)
                return -1;
            i += 4;
        } else {
            return -1;
        }
    }
    return 0;
}

static inline int
mqtt_sn_topic_set(mqtt_sn_topic_t *dst, mqtt_sn_topic_t *src) {
    if (!dst || !src)
        return -1;
    if (src->type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_set(&dst->name, &src->name);
    } else if (src->type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        dst->shor[0] = src->shor[0];
        dst->shor[1] = src->shor[1];
    } else {
        dst->id = src->id;
    }
    dst->type = src->type;
    return 0;
}

static inline int
mqtt_sn_topic_copy(mqtt_sn_topic_t *dst, mqtt_sn_topic_t *src) {
    if (!dst || !src)
        return -1;
    if (src->type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_copy(&dst->name, &src->name);
    } else if (src->type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        dst->shor[0] = src->shor[0];
        dst->shor[1] = src->shor[1];
    } else {
        dst->id = src->id;
    }
    dst->type = src->type;
    return 0;
}

static inline int
mqtt_sn_topic_equal(mqtt_sn_topic_t *dst, mqtt_sn_topic_t *src) {
    if (src->type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        return mqtt_str_equal(&dst->name, &src->name);
    } else if (src->type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        return (dst->shor[0] == src->shor[0] && dst->shor[1] == src->shor[1]);
    } else {
        return dst->id == src->id;
    }
}

static inline void
mqtt_sn_topic_free(mqtt_sn_topic_t *topic) {
    if (!topic)
        return;
    if (topic->type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_free(&topic->name);
    }
}

static inline int
mqtt_fixed_valid(mqtt_fixed_header_t *f, uint8_t retain, uint8_t qos, uint8_t dup) {
    /* compare only the flags bits, type bits are checked by the caller. */
    return (f->flags & 0x0F) == MQTT_FH_BUILD(0, dup, qos, retain);
}

static inline int
mqtt_property_valid(mqtt_property_code_t code, mqtt_packet_type_t type, int will) {
    const mqtt_property_def_t *def;
    int j;
    def = NULL;
    if ((int)code >= 0 && (int)code < MQTT_PROPERTY_DEFS_BY_CODE_SIZE)
        def = MQTT_PROPERTY_DEFS_BY_CODE[code];
    if (!def)
        return 0;
    if (will)
        return def->will;
    for (j = 0; j < MQTT_AUTH && def->types[j] != MQTT_RESERVED; j++) {
        if (def->types[j] == type)
            return 1;
    }
    return 0;
}

static inline int
mqtt_property_value_valid(mqtt_property_code_t code, const mqtt_property_t *property) {
    if (!property)
        return 0;
    switch (code) {
    case MQTT_PROPERTY_RECEIVE_MAXIMUM:
    case MQTT_PROPERTY_TOPIC_ALIAS:
    case MQTT_PROPERTY_MAXIMUM_PACKET_SIZE:
        return property->b2 >= 1;
    case MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER:
        return property->bv >= 1;
    case MQTT_PROPERTY_MAXIMUM_QOS:
        return property->b1 <= 2;
    case MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR:
    case MQTT_PROPERTY_REQUEST_RESPONSE_INFORMATION:
    case MQTT_PROPERTY_REQUEST_PROBLEM_INFORMATION:
    case MQTT_PROPERTY_RETAIN_AVAILABLE:
    case MQTT_PROPERTY_WILDCARD_SUBSCRIPTION_AVAILABLE:
    case MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIERS_AVAILABLE:
    case MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE:
        return property->b1 <= 1;
    default:
        return 1;
    }
}

static inline int
mqtt_properties_valid(const mqtt_properties_t *properties, mqtt_packet_type_t type, int will) {
    mqtt_property_t *property;
    if (!properties)
        return 1;
    property = properties->head;
    while (property) {
        if (!mqtt_property_valid(property->code, type, will))
            return 0;
        if (!mqtt_property_value_valid(property->code, property))
            return 0;
        property = property->next;
    }
    return 1;
}

static inline int
mqtt_subscribe_generate(mqtt_packet_t *pkt, int n) {
    if (n <= 0)
        return -1;
    pkt->p.subscribe.options = (mqtt_subscribe_options_t *)MQTT_MALLOC(n * sizeof(mqtt_subscribe_options_t));
    if (!pkt->p.subscribe.options)
        return -1;
    memset(pkt->p.subscribe.options, 0, n * sizeof(mqtt_subscribe_options_t));
    pkt->p.subscribe.topic_filters = (mqtt_str_t *)MQTT_MALLOC(n * sizeof(mqtt_str_t));
    if (!pkt->p.subscribe.topic_filters) {
        MQTT_FREE(pkt->p.subscribe.options);
        pkt->p.subscribe.options = NULL;
        return -1;
    }
    memset(pkt->p.subscribe.topic_filters, 0, n * sizeof(mqtt_str_t));
    pkt->p.subscribe.n = n;
    return 0;
}

static inline int
mqtt_unsubscribe_generate(mqtt_packet_t *pkt, int n) {
    if (n <= 0)
        return -1;
    pkt->p.unsubscribe.topic_filters = (mqtt_str_t *)MQTT_MALLOC(n * sizeof(mqtt_str_t));
    if (!pkt->p.unsubscribe.topic_filters)
        return -1;
    memset(pkt->p.unsubscribe.topic_filters, 0, n * sizeof(mqtt_str_t));
    pkt->p.unsubscribe.n = n;
    return 0;
}

static inline int
mqtt_suback_generate(mqtt_packet_t *pkt, int n) {
    if (n <= 0)
        return -1;
    switch (pkt->ver) {
    case MQTT_VERSION_3:
        pkt->p.suback.v3.granted = (mqtt_suback_granted_t *)MQTT_MALLOC(n * sizeof(mqtt_suback_granted_t));
        if (!pkt->p.suback.v3.granted)
            return -1;
        memset(pkt->p.suback.v3.granted, 0, n * sizeof(mqtt_suback_granted_t));
        break;
    case MQTT_VERSION_4:
        pkt->p.suback.v4.return_codes = (mqtt_src_t *)MQTT_MALLOC(n * sizeof(mqtt_src_t));
        if (!pkt->p.suback.v4.return_codes)
            return -1;
        memset(pkt->p.suback.v4.return_codes, 0, n * sizeof(mqtt_src_t));
        break;
    case MQTT_VERSION_5:
        pkt->p.suback.v5.reason_codes = (mqtt_rc_t *)MQTT_MALLOC(n * sizeof(mqtt_rc_t));
        if (!pkt->p.suback.v5.reason_codes)
            return -1;
        memset(pkt->p.suback.v5.reason_codes, 0, n * sizeof(mqtt_rc_t));
        break;
    }
    pkt->p.suback.n = n;
    return 0;
}

static inline int
mqtt_unsuback_generate(mqtt_packet_t *pkt, int n) {
    if (pkt->ver == MQTT_VERSION_5) {
        if (n <= 0)
            return -1;
        pkt->p.unsuback.v5.reason_codes = (mqtt_rc_t *)MQTT_MALLOC(n * sizeof(mqtt_rc_t));
        if (!pkt->p.unsuback.v5.reason_codes)
            return -1;
        memset(pkt->p.unsuback.v5.reason_codes, 0, n * sizeof(mqtt_rc_t));
        pkt->p.unsuback.v5.n = n;
    }
    return 0;
}

void mqtt_packet_init(mqtt_packet_t *pkt, mqtt_version_t ver, mqtt_packet_type_t type);
void mqtt_packet_cleanup(mqtt_packet_t *pkt);

/**
 * serialize a mqtt packet into data/size pair
 */
int mqtt_serialize(mqtt_packet_t *pkt, mqtt_str_t *b);

/**
 * mqtt packet parser funcs.
 */
void mqtt_parser_init(mqtt_parser_t *parser);
void mqtt_parser_version(mqtt_parser_t *parser, mqtt_version_t version);
void mqtt_parser_cleanup(mqtt_parser_t *parser);

/**
 * parse data/size pair into mqtt packets
 * return:
 *  -1 - mqtt packet parse error
 *   0 - parse all data and finished
 *   1 - a mqtt packet has parsed
 */
int mqtt_parse(mqtt_parser_t *parser, mqtt_str_t *b, mqtt_packet_t *pkt);

/**
 * mqtt property functions
 */
void mqtt_properties_add(mqtt_properties_t *properties, mqtt_property_code_t code, const void *value, const char *name);
mqtt_property_t *mqtt_properties_find(mqtt_properties_t *properties, mqtt_property_code_t code);
mqtt_property_t *mqtt_properties_remove(mqtt_properties_t *properties, mqtt_property_code_t code);

void mqtt_sn_packet_init(mqtt_sn_packet_t *pkt, mqtt_sn_packet_type_t type);
void mqtt_sn_packet_cleanup(mqtt_sn_packet_t *pkt);

/**
 * serialize a mqtt-sn packet into data/size pair
 */
int mqtt_sn_serialize(mqtt_sn_packet_t *pkt, mqtt_str_t *b);

/**
 * mqtt-sn packet parser funcs.
 */
void mqtt_sn_parser_init(mqtt_sn_parser_t *parser);
void mqtt_sn_parser_cleanup(mqtt_sn_parser_t *parser);

/**
 * parse data/size pair into mqtt-sn packets
 * return:
 *  -1 - mqtt-sn packet parse error
 *   0 - parse all data and finished
 *   1 - a mqtt-sn packet has parsed
 */
int mqtt_sn_parse(mqtt_sn_parser_t *parser, mqtt_str_t *b, mqtt_sn_packet_t *pkt);

#ifdef __cplusplus
}
#endif

#endif /* _MQTT_H_ */

#ifdef MQTT_IMPL

#ifdef __cplusplus
extern "C" {
#endif

mqtt_malloc_func_t mqtt_malloc = 0;
mqtt_free_func_t mqtt_free = 0;

void
mqtt_set_allocator(mqtt_malloc_func_t malloc_func, mqtt_free_func_t free_func) {
    mqtt_malloc = malloc_func;
    mqtt_free = free_func;
}

const char *
mqtt_strerror(mqtt_error_t err) {
    switch (err) {
    case MQTT_OK:
        return "ok";
    case MQTT_ERR_NOMEM:
        return "out of memory";
    case MQTT_ERR_MALFORMED:
        return "malformed packet";
    case MQTT_ERR_PROTOCOL:
        return "protocol error";
    case MQTT_ERR_TOO_LARGE:
        return "packet too large";
    case MQTT_ERR_UNSUPPORTED:
        return "unsupported";
    case MQTT_ERR_INVALID_ARG:
        return "invalid argument";
    }
    return "unknown error";
}

const mqtt_rc_def_t MQTT_RC_DEFS[] = {
    {MQTT_RC_SUCCESS, "Success", {MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_PUBREL, MQTT_PUBCOMP, MQTT_SUBACK, MQTT_UNSUBACK, MQTT_AUTH}},
    {MQTT_RC_NORMAL_DISCONNECTION, "Normal disconnection", {MQTT_DISCONNECT}},
    {MQTT_RC_GRANTED_QOS_0, "Granted QoS 0", {MQTT_SUBACK}},
    {MQTT_RC_GRANTED_QOS_1, "Granted QoS 1", {MQTT_SUBACK}},
    {MQTT_RC_GRANTED_QOS_2, "Granted QoS 2", {MQTT_SUBACK}},
    {MQTT_RC_DISCONNECT_WITH_WILL_MESSAGE, "Disconnect with Will Message", {MQTT_DISCONNECT}},
    {MQTT_RC_NO_MATCHING_SUBSCRIBERS, "No matching subscribers", {MQTT_PUBACK, MQTT_PUBREC}},
    {MQTT_RC_NO_SUBSCRIPTION_EXISTED, "No subscription existed", {MQTT_UNSUBACK}},
    {MQTT_RC_CONTINUE_AUTHENTICATION, "Continue authentication", {MQTT_AUTH}},
    {MQTT_RC_RE_AUTHENTICATE, "Re-authenticate", {MQTT_AUTH}},
    {MQTT_RC_UNSPECIFIED_ERROR, "Unspecified error", {MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT}},
    {MQTT_RC_MALFORMED_PACKET, "Malformed Packet", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_PROTOCOL_ERROR, "Protocol Error", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_IMPLEMENTATION_SPECIFIC_ERROR, "Implementation specific error", {MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT}},
    {MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION, "Unsupported Protocol Version", {MQTT_CONNACK}},
    {MQTT_RC_CLIENT_IDENTIFIER_NOT_VALID, "Client Identifier not valid", {MQTT_CONNACK}},
    {MQTT_RC_BAD_USERNAME_OR_PASSWORD, "Bad User Name or Password", {MQTT_CONNACK}},
    {MQTT_RC_NOT_AUTHORIZED, "Not authorized", {MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT}},
    {MQTT_RC_SERVER_UNAVAILABLE, "Server unavailable", {MQTT_CONNACK}},
    {MQTT_RC_SERVER_BUSY, "Server busy", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_BANNED, "Banned", {MQTT_CONNACK}},
    {MQTT_RC_SERVER_SHUTTING_DOWN, "Server shutting down", {MQTT_DISCONNECT}},
    {MQTT_RC_BAD_AUTHENTICATION_METHOD, "Bad authentication method", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_KEEP_ALIVE_TIMEOUT, "Keep Alive timeout", {MQTT_DISCONNECT}},
    {MQTT_RC_SESSION_TAKEN_OVER, "Session taken over", {MQTT_DISCONNECT}},
    {MQTT_RC_TOPIC_FILTER_INVALID, "Topic Filter invalid", {MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT}},
    {MQTT_RC_TOPIC_NAME_INVALID, "Topic Name invalid", {MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_DISCONNECT}},
    {MQTT_RC_PACKET_IDENTIFIER_IN_USE, "Packet Identifier in use", {MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_UNSUBACK}},
    {MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND, "Packet Identifier not found", {MQTT_PUBREL, MQTT_PUBCOMP}},
    {MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED, "Receive Maximum exceeded", {MQTT_DISCONNECT}},
    {MQTT_RC_TOPIC_ALIAS_INVALID, "Topic Alias invalid", {MQTT_PUBACK, MQTT_DISCONNECT}},
    {MQTT_RC_PACKET_TOO_LARGE, "Packet too large", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_MESSAGE_RATE_TOO_HIGH, "Message rate too high", {MQTT_DISCONNECT}},
    {MQTT_RC_QUOTA_EXCEEDED, "Quota exceeded", {MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_DISCONNECT}},
    {MQTT_RC_ADMINISTRATIVE_ACTION, "Administrative action", {MQTT_DISCONNECT}},
    {MQTT_RC_PAYLOAD_FORMAT_INVALID, "Payload format invalid", {MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_DISCONNECT}},
    {MQTT_RC_RETAIN_NOT_SUPPORTED, "Retain not supported", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_QOS_NOT_SUPPORTED, "QoS not supported", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_USE_ANOTHER_SERVER, "Use another server", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_SERVER_MOVED, "Server moved", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED, "Shared Subscriptions not supported", {MQTT_SUBACK, MQTT_DISCONNECT}},
    {MQTT_RC_CONNECTION_RATE_EXCEEDED, "Connection rate exceeded", {MQTT_CONNACK, MQTT_DISCONNECT}},
    {MQTT_RC_MAXIMUM_CONNECT_TIME, "Maximum connect time", {MQTT_DISCONNECT}},
    {MQTT_RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED, "Subscription Identifiers not supported", {MQTT_SUBACK, MQTT_DISCONNECT}},
    {MQTT_RC_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED, "Wildcard Subscriptions not supported", {MQTT_SUBACK, MQTT_DISCONNECT}},
};

const int MQTT_RC_DEFS_COUNT = sizeof(MQTT_RC_DEFS) / sizeof(MQTT_RC_DEFS[0]);

const mqtt_rc_def_t *const MQTT_RC_DEFS_BY_RC[MQTT_RC_DEFS_BY_RC_SIZE] = {
    [MQTT_RC_SUCCESS] = &MQTT_RC_DEFS[0],
    [MQTT_RC_GRANTED_QOS_1] = &MQTT_RC_DEFS[3],
    [MQTT_RC_GRANTED_QOS_2] = &MQTT_RC_DEFS[4],
    [MQTT_RC_DISCONNECT_WITH_WILL_MESSAGE] = &MQTT_RC_DEFS[5],
    [MQTT_RC_NO_MATCHING_SUBSCRIBERS] = &MQTT_RC_DEFS[6],
    [MQTT_RC_NO_SUBSCRIPTION_EXISTED] = &MQTT_RC_DEFS[7],
    [MQTT_RC_CONTINUE_AUTHENTICATION] = &MQTT_RC_DEFS[8],
    [MQTT_RC_RE_AUTHENTICATE] = &MQTT_RC_DEFS[9],
    [MQTT_RC_UNSPECIFIED_ERROR] = &MQTT_RC_DEFS[10],
    [MQTT_RC_MALFORMED_PACKET] = &MQTT_RC_DEFS[11],
    [MQTT_RC_PROTOCOL_ERROR] = &MQTT_RC_DEFS[12],
    [MQTT_RC_IMPLEMENTATION_SPECIFIC_ERROR] = &MQTT_RC_DEFS[13],
    [MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION] = &MQTT_RC_DEFS[14],
    [MQTT_RC_CLIENT_IDENTIFIER_NOT_VALID] = &MQTT_RC_DEFS[15],
    [MQTT_RC_BAD_USERNAME_OR_PASSWORD] = &MQTT_RC_DEFS[16],
    [MQTT_RC_NOT_AUTHORIZED] = &MQTT_RC_DEFS[17],
    [MQTT_RC_SERVER_UNAVAILABLE] = &MQTT_RC_DEFS[18],
    [MQTT_RC_SERVER_BUSY] = &MQTT_RC_DEFS[19],
    [MQTT_RC_BANNED] = &MQTT_RC_DEFS[20],
    [MQTT_RC_SERVER_SHUTTING_DOWN] = &MQTT_RC_DEFS[21],
    [MQTT_RC_BAD_AUTHENTICATION_METHOD] = &MQTT_RC_DEFS[22],
    [MQTT_RC_KEEP_ALIVE_TIMEOUT] = &MQTT_RC_DEFS[23],
    [MQTT_RC_SESSION_TAKEN_OVER] = &MQTT_RC_DEFS[24],
    [MQTT_RC_TOPIC_FILTER_INVALID] = &MQTT_RC_DEFS[25],
    [MQTT_RC_TOPIC_NAME_INVALID] = &MQTT_RC_DEFS[26],
    [MQTT_RC_PACKET_IDENTIFIER_IN_USE] = &MQTT_RC_DEFS[27],
    [MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND] = &MQTT_RC_DEFS[28],
    [MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED] = &MQTT_RC_DEFS[29],
    [MQTT_RC_TOPIC_ALIAS_INVALID] = &MQTT_RC_DEFS[30],
    [MQTT_RC_PACKET_TOO_LARGE] = &MQTT_RC_DEFS[31],
    [MQTT_RC_MESSAGE_RATE_TOO_HIGH] = &MQTT_RC_DEFS[32],
    [MQTT_RC_QUOTA_EXCEEDED] = &MQTT_RC_DEFS[33],
    [MQTT_RC_ADMINISTRATIVE_ACTION] = &MQTT_RC_DEFS[34],
    [MQTT_RC_PAYLOAD_FORMAT_INVALID] = &MQTT_RC_DEFS[35],
    [MQTT_RC_RETAIN_NOT_SUPPORTED] = &MQTT_RC_DEFS[36],
    [MQTT_RC_QOS_NOT_SUPPORTED] = &MQTT_RC_DEFS[37],
    [MQTT_RC_USE_ANOTHER_SERVER] = &MQTT_RC_DEFS[38],
    [MQTT_RC_SERVER_MOVED] = &MQTT_RC_DEFS[39],
    [MQTT_RC_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED] = &MQTT_RC_DEFS[40],
    [MQTT_RC_CONNECTION_RATE_EXCEEDED] = &MQTT_RC_DEFS[41],
    [MQTT_RC_MAXIMUM_CONNECT_TIME] = &MQTT_RC_DEFS[42],
    [MQTT_RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED] = &MQTT_RC_DEFS[43],
    [MQTT_RC_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED] = &MQTT_RC_DEFS[44],
};

const mqtt_property_def_t MQTT_PROPERTY_DEFS[] = {
    {MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR, "Payload Format Indicator", MQTT_PROPERTY_TYPE_BYTE, {MQTT_PUBLISH}, 1},
    {MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL, "Message Expiry Interval", MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER, {MQTT_PUBLISH}, 1},
    {MQTT_PROPERTY_CONTENT_TYPE, "Content Type", MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING, {MQTT_PUBLISH}, 1},
    {MQTT_PROPERTY_RESPONSE_TOPIC, "Response Topic", MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING, {MQTT_PUBLISH}, 1},
    {MQTT_PROPERTY_CORRELATION_DATA, "Correlation Data", MQTT_PROPERTY_TYPE_BINARY_DATA, {MQTT_PUBLISH}, 1},
    {MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER, "Subscription Identifier", MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER, {MQTT_PUBLISH, MQTT_SUBSCRIBE}, 0},
    {MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL, "Session Expiry Interval", MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER, {MQTT_CONNECT, MQTT_CONNACK, MQTT_DISCONNECT}, 0},
    {MQTT_PROPERTY_ASSIGNED_CLIENT_IDENTIFIER, "Assigned Client Identifier", MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING, {MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_SERVER_KEEP_ALIVE, "Server Keep Alive", MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER, {MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_AUTHENTICATION_METHOD, "Authentication Method", MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING, {MQTT_CONNECT, MQTT_CONNACK, MQTT_AUTH}, 0},
    {MQTT_PROPERTY_AUTHENTICATION_DATA, "Authentication Data", MQTT_PROPERTY_TYPE_BINARY_DATA, {MQTT_CONNECT, MQTT_CONNACK, MQTT_AUTH}, 0},
    {MQTT_PROPERTY_REQUEST_PROBLEM_INFORMATION, "Request Problem Information", MQTT_PROPERTY_TYPE_BYTE, {MQTT_CONNECT}, 0},
    {MQTT_PROPERTY_WILL_DELAY_INTERVAL, "Will Delay Interval", MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER, {MQTT_RESERVED}, 1},
    {MQTT_PROPERTY_REQUEST_RESPONSE_INFORMATION, "Request Response Information", MQTT_PROPERTY_TYPE_BYTE, {MQTT_CONNECT}, 0},
    {MQTT_PROPERTY_RESPONSE_INFORMATION, "Response Information", MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING, {MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_SERVER_REFERENCE, "Server Reference", MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING, {MQTT_CONNACK, MQTT_DISCONNECT}, 0},
    {MQTT_PROPERTY_REASON_STRING, "Reason String", MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING, {MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_PUBREL, MQTT_PUBCOMP, MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT, MQTT_AUTH}, 0},
    {MQTT_PROPERTY_RECEIVE_MAXIMUM, "Receive Maximum", MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER, {MQTT_CONNECT, MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM, "Topic Alias Maximum", MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER, {MQTT_CONNECT, MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_TOPIC_ALIAS, "Topic Alias", MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER, {MQTT_PUBLISH}, 0},
    {MQTT_PROPERTY_MAXIMUM_QOS, "Maximum QoS", MQTT_PROPERTY_TYPE_BYTE, {MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_RETAIN_AVAILABLE, "Retain Available", MQTT_PROPERTY_TYPE_BYTE, {MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_USER_PROPERTY, "User Property", MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR, {MQTT_CONNECT, MQTT_CONNACK, MQTT_PUBLISH, MQTT_PUBACK, MQTT_PUBREC, MQTT_PUBREL, MQTT_PUBCOMP, MQTT_SUBSCRIBE, MQTT_SUBACK, MQTT_UNSUBSCRIBE, MQTT_UNSUBACK, MQTT_DISCONNECT, MQTT_AUTH}, 1},
    {MQTT_PROPERTY_MAXIMUM_PACKET_SIZE, "Maximum Packet Size", MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER, {MQTT_CONNECT, MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_WILDCARD_SUBSCRIPTION_AVAILABLE, "Wildcard Subscription Available", MQTT_PROPERTY_TYPE_BYTE, {MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIERS_AVAILABLE, "Subscription Identifier Available", MQTT_PROPERTY_TYPE_BYTE, {MQTT_CONNACK}, 0},
    {MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE, "Shared Subscription Available", MQTT_PROPERTY_TYPE_BYTE, {MQTT_CONNACK}, 0},
};

const int MQTT_PROPERTY_DEFS_COUNT = sizeof(MQTT_PROPERTY_DEFS) / sizeof(MQTT_PROPERTY_DEFS[0]);

const mqtt_property_def_t *const MQTT_PROPERTY_DEFS_BY_CODE[MQTT_PROPERTY_DEFS_BY_CODE_SIZE] = {
    [MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR] = &MQTT_PROPERTY_DEFS[0],
    [MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL] = &MQTT_PROPERTY_DEFS[1],
    [MQTT_PROPERTY_CONTENT_TYPE] = &MQTT_PROPERTY_DEFS[2],
    [MQTT_PROPERTY_RESPONSE_TOPIC] = &MQTT_PROPERTY_DEFS[3],
    [MQTT_PROPERTY_CORRELATION_DATA] = &MQTT_PROPERTY_DEFS[4],
    [MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER] = &MQTT_PROPERTY_DEFS[5],
    [MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL] = &MQTT_PROPERTY_DEFS[6],
    [MQTT_PROPERTY_ASSIGNED_CLIENT_IDENTIFIER] = &MQTT_PROPERTY_DEFS[7],
    [MQTT_PROPERTY_SERVER_KEEP_ALIVE] = &MQTT_PROPERTY_DEFS[8],
    [MQTT_PROPERTY_AUTHENTICATION_METHOD] = &MQTT_PROPERTY_DEFS[9],
    [MQTT_PROPERTY_AUTHENTICATION_DATA] = &MQTT_PROPERTY_DEFS[10],
    [MQTT_PROPERTY_REQUEST_PROBLEM_INFORMATION] = &MQTT_PROPERTY_DEFS[11],
    [MQTT_PROPERTY_WILL_DELAY_INTERVAL] = &MQTT_PROPERTY_DEFS[12],
    [MQTT_PROPERTY_REQUEST_RESPONSE_INFORMATION] = &MQTT_PROPERTY_DEFS[13],
    [MQTT_PROPERTY_RESPONSE_INFORMATION] = &MQTT_PROPERTY_DEFS[14],
    [MQTT_PROPERTY_SERVER_REFERENCE] = &MQTT_PROPERTY_DEFS[15],
    [MQTT_PROPERTY_REASON_STRING] = &MQTT_PROPERTY_DEFS[16],
    [MQTT_PROPERTY_RECEIVE_MAXIMUM] = &MQTT_PROPERTY_DEFS[17],
    [MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM] = &MQTT_PROPERTY_DEFS[18],
    [MQTT_PROPERTY_TOPIC_ALIAS] = &MQTT_PROPERTY_DEFS[19],
    [MQTT_PROPERTY_MAXIMUM_QOS] = &MQTT_PROPERTY_DEFS[20],
    [MQTT_PROPERTY_RETAIN_AVAILABLE] = &MQTT_PROPERTY_DEFS[21],
    [MQTT_PROPERTY_USER_PROPERTY] = &MQTT_PROPERTY_DEFS[22],
    [MQTT_PROPERTY_MAXIMUM_PACKET_SIZE] = &MQTT_PROPERTY_DEFS[23],
    [MQTT_PROPERTY_WILDCARD_SUBSCRIPTION_AVAILABLE] = &MQTT_PROPERTY_DEFS[24],
    [MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIERS_AVAILABLE] = &MQTT_PROPERTY_DEFS[25],
    [MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE] = &MQTT_PROPERTY_DEFS[26],
};

static void
__properties_free(mqtt_properties_t *properties) {
    mqtt_property_t *property;
    property = properties->head;
    while (property) {
        mqtt_property_t *next;
        next = property->next;
        MQTT_FREE(property);
        property = next;
    }
    properties->head = NULL;
    properties->length = 0;
}

void
mqtt_packet_init(mqtt_packet_t *pkt, mqtt_version_t ver, mqtt_packet_type_t type) {
    memset(pkt, 0, sizeof *pkt);
    pkt->ver = ver;
    pkt->f.flags = MQTT_FH_BUILD(type, 0, 0, 0);
    if (type == MQTT_CONNECT) {
        mqtt_str_from(&pkt->v.connect.protocol_name, mqtt_protocol_name(pkt->ver));
        pkt->v.connect.protocol_version = pkt->ver;
    }
}

static void
__mqtt_packet_free(mqtt_packet_t *pkt) {
    switch (MQTT_FH_TYPE(pkt->f.flags)) {
    case MQTT_CONNECT:
        __properties_free(&pkt->v.connect.v5.properties);
        __properties_free(&pkt->p.connect.v5.will_properties);
        break;
    case MQTT_CONNACK:
        __properties_free(&pkt->v.connack.v5.properties);
        break;
    case MQTT_SUBSCRIBE:
        if (pkt->p.subscribe.topic_filters) {
            MQTT_FREE(pkt->p.subscribe.topic_filters);
            pkt->p.subscribe.topic_filters = NULL;
        }
        if (pkt->p.subscribe.options) {
            MQTT_FREE(pkt->p.subscribe.options);
            pkt->p.subscribe.options = NULL;
        }
        __properties_free(&pkt->v.subscribe.v5.properties);
        break;
    case MQTT_SUBACK:
        if (pkt->p.suback.v3.granted) {
            MQTT_FREE(pkt->p.suback.v3.granted);
            pkt->p.suback.v3.granted = NULL;
        }
        if (pkt->p.suback.v4.return_codes) {
            MQTT_FREE(pkt->p.suback.v4.return_codes);
            pkt->p.suback.v4.return_codes = NULL;
        }
        if (pkt->p.suback.v5.reason_codes) {
            MQTT_FREE(pkt->p.suback.v5.reason_codes);
            pkt->p.suback.v5.reason_codes = NULL;
        }
        __properties_free(&pkt->v.suback.v5.properties);
        break;
    case MQTT_UNSUBSCRIBE:
        if (pkt->p.unsubscribe.topic_filters) {
            MQTT_FREE(pkt->p.unsubscribe.topic_filters);
            pkt->p.unsubscribe.topic_filters = NULL;
        }
        __properties_free(&pkt->v.unsubscribe.v5.properties);
        break;
    case MQTT_UNSUBACK:
        if (pkt->p.unsuback.v5.reason_codes) {
            MQTT_FREE(pkt->p.unsuback.v5.reason_codes);
            pkt->p.unsuback.v5.reason_codes = NULL;
        }
        __properties_free(&pkt->v.unsuback.v5.properties);
        break;
    case MQTT_PUBLISH:
        __properties_free(&pkt->v.publish.v5.properties);
        break;
    case MQTT_PUBACK:
        __properties_free(&pkt->v.puback.v5.properties);
        break;
    case MQTT_PUBREC:
        __properties_free(&pkt->v.pubrec.v5.properties);
        break;
    case MQTT_PUBREL:
        __properties_free(&pkt->v.pubrel.v5.properties);
        break;
    case MQTT_PUBCOMP:
        __properties_free(&pkt->v.pubcomp.v5.properties);
        break;
    case MQTT_DISCONNECT:
        __properties_free(&pkt->v.disconnect.v5.properties);
        break;
    case MQTT_AUTH:
        __properties_free(&pkt->v.auth.v5.properties);
        break;
    case MQTT_PINGREQ:
    case MQTT_PINGRESP:
    case MQTT_RESERVED:
        break;
    }
}

void
mqtt_packet_cleanup(mqtt_packet_t *pkt) {
    if (!pkt)
        return;
    __mqtt_packet_free(pkt);
    mqtt_str_free(&pkt->b);
    memset(pkt, 0, sizeof *pkt);
}

static size_t
__properties_len(const mqtt_properties_t *properties) {
    if (!properties->length)
        return 1;
    return properties->length + mqtt_vbi_length(properties->length);
}

static int
__property_parse(mqtt_property_t *property, mqtt_str_t *b) {
    mqtt_property_type_t type;
    uint8_t u8;

    if (mqtt_str_read_u8(b, &u8))
        return -1;
    property->code = (mqtt_property_code_t)u8;
    /* reject unknown property codes ([MQTT-2.2.2]). */
    if ((int)property->code >= MQTT_PROPERTY_DEFS_BY_CODE_SIZE || !MQTT_PROPERTY_DEFS_BY_CODE[property->code])
        return -1;
    type = mqtt_property_type(property->code);
    switch (type) {
    case MQTT_PROPERTY_TYPE_BYTE:
        if (mqtt_str_read_u8(b, &property->b1))
            return -1;
        break;
    case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
        if (mqtt_str_read_u16(b, &property->b2))
            return -1;
        break;
    case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
        if (mqtt_str_read_u32(b, &property->b4))
            return -1;
        break;
    case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        if (mqtt_str_read_vbi(b, &property->bv))
            return -1;
        break;
    case MQTT_PROPERTY_TYPE_BINARY_DATA:
        if (mqtt_str_read_utf(b, &property->data))
            return -1;
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
        if (mqtt_str_read_utf8(b, &property->str))
            return -1;
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
        if (mqtt_str_read_utf8(b, &property->pair.name))
            return -1;
        if (mqtt_str_read_utf8(b, &property->pair.value))
            return -1;
        break;
    }
    return 0;
}

static int
__properties_parse(mqtt_properties_t *properties, mqtt_str_t *b) {
    uint32_t length;
    mqtt_property_t **tail;

    if (mqtt_str_read_vbi(b, &length))
        return -1;
    if (b->i + length > b->n)
        return -1;
    properties->length = length;
    /* tail-insert to keep wire order. */
    tail = &properties->head;
    while (*tail)
        tail = &(*tail)->next;
    while (length > 0) {
        mqtt_property_t *property;
        size_t i1, i2;

        property = (mqtt_property_t *)MQTT_MALLOC(sizeof *property);
        if (!property)
            return -1;
        memset(property, 0, sizeof *property);
        i1 = b->i;
        if (__property_parse(property, b)) {
            MQTT_FREE(property);
            return -1;
        }
        i2 = b->i;
        if (i2 - i1 > length) {
            MQTT_FREE(property);
            return -1;
        }
        /* duplicates are only allowed for user property and subscription
         * identifier ([MQTT-2.2.2-2]). */
        if (property->code != MQTT_PROPERTY_USER_PROPERTY &&
            property->code != MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER &&
            mqtt_properties_find(properties, property->code)) {
            MQTT_FREE(property);
            return -1;
        }
        length -= (uint32_t)(i2 - i1);
        *tail = property;
        tail = &property->next;
    }
    return 0;
}

static int
__parse_connect(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_connect_t *v;
    mqtt_p_connect_t *p;
    uint8_t u8;

    v = &pkt->v.connect;
    p = &pkt->p.connect;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (mqtt_str_read_utf(remaining, &v->protocol_name))
        return -1;
    if (mqtt_str_read_u8(remaining, &u8))
        return -1;
    v->protocol_version = (mqtt_version_t)u8;
    pkt->ver = v->protocol_version;
    if (!mqtt_is_valid_version(v->protocol_version))
        return -1;
    {
        const char *expected = mqtt_protocol_name(v->protocol_version);
        if (v->protocol_name.n != strlen(expected) || memcmp(v->protocol_name.s, expected, v->protocol_name.n) != 0)
            return -1;
    }
    if (mqtt_str_read_u8(remaining, &v->connect_flags))
        return -1;
    if ((v->connect_flags & MQTT_CF_PASSWORD) && !(v->connect_flags & MQTT_CF_USERNAME))
        return -1;
    if (v->connect_flags & MQTT_CF_RESERVED)
        return -1;
    if (!(v->connect_flags & MQTT_CF_WILL_FLAG) &&
        (MQTT_CF_WILL_QOS(v->connect_flags) || (v->connect_flags & MQTT_CF_WILL_RETAIN)))
        return -1;
    if (mqtt_str_read_u16(remaining, &v->keep_alive))
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_CONNECT, 0))
            return -1;
    }
    if (mqtt_str_read_utf8(remaining, &p->client_id))
        return -1;
    if (v->connect_flags & MQTT_CF_WILL_FLAG) {
        if (pkt->ver == MQTT_VERSION_5) {
            if (__properties_parse(&p->v5.will_properties, remaining))
                return -1;
            if (!mqtt_properties_valid(&p->v5.will_properties, MQTT_RESERVED, 1))
                return -1;
        }
        if (mqtt_str_read_utf8(remaining, &p->will_topic))
            return -1;
        if (mqtt_str_read_utf(remaining, &p->will_message))
            return -1;
        if (mqtt_str_empty(&p->will_topic) || mqtt_str_empty(&p->will_message))
            return -1;
        if (mqtt_topic_name_validate(&p->will_topic))
            return -1;
        if (!MQTT_IS_QOS(MQTT_CF_WILL_QOS(v->connect_flags)))
            return -1;
    }
    if (v->connect_flags & MQTT_CF_USERNAME) {
        if (mqtt_str_read_utf8(remaining, &p->username))
            return -1;
    }
    if (v->connect_flags & MQTT_CF_PASSWORD) {
        if (mqtt_str_read_utf(remaining, &p->password))
            return -1;
    }
    return 0;
}

static int
__parse_connack(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_connack_t *v;
    uint8_t u8;

    v = &pkt->v.connack;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (pkt->ver == MQTT_VERSION_3) {
        if (mqtt_str_read_u8(remaining, &u8))
            return -1;
        if (u8 != 0)
            return -1;
        if (mqtt_str_read_u8(remaining, &u8))
            return -1;
        v->v3.return_code = (mqtt_crc_t)u8;
        if (!MQTT_IS_CRC(v->v3.return_code)) {
            return -1;
        }
    } else if (pkt->ver == MQTT_VERSION_4) {
        if (mqtt_str_read_u8(remaining, &v->v4.acknowledge_flags.flags))
            return -1;
        if (v->v4.acknowledge_flags.flags & ~0x01)
            return -1;
        if (mqtt_str_read_u8(remaining, &u8))
            return -1;
        v->v4.return_code = (mqtt_crc_t)u8;
        if (!MQTT_IS_CRC(v->v4.return_code)) {
            return -1;
        }
    } else if (pkt->ver == MQTT_VERSION_5) {
        if (mqtt_str_read_u8(remaining, &v->v5.acknowledge_flags.flags))
            return -1;
        if (v->v5.acknowledge_flags.flags & ~0x01)
            return -1;
        if (mqtt_str_read_u8(remaining, &u8))
            return -1;
        v->v5.reason_code = (mqtt_rc_t)u8;
        if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_CONNACK)) {
            return -1;
        }
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_CONNACK, 0))
            return -1;
    }
    return 0;
}

static int
__parse_publish(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_publish_t *v;
    mqtt_p_publish_t *p;

    v = &pkt->v.publish;
    p = &pkt->p.publish;

    if (!MQTT_IS_QOS(MQTT_FH_QOS(pkt->f.flags)))
        return -1;
    if (MQTT_FH_QOS(pkt->f.flags) == MQTT_QOS_0 && MQTT_FH_DUP(pkt->f.flags))
        return -1;
    if (mqtt_str_read_utf(remaining, &v->topic_name))
        return -1;
    /* a wildcard in a topic name is a semantic error: let it reach the
     * handler so a v5 server can answer PUBACK 0x90 before closing
     * ([MQTT-3.3.2-8]); the UTF-8 check stays here (malformed packet). */
    if (mqtt_utf8_validate(&v->topic_name) != 0)
        return -1;
    if (pkt->ver != MQTT_VERSION_5 && mqtt_str_empty(&v->topic_name))
        return -1;
    if (MQTT_FH_QOS(pkt->f.flags) > MQTT_QOS_0) {
        if (mqtt_str_read_u16(remaining, &v->packet_id))
            return -1;
        /* zero packet id is not allowed ([MQTT-2.3.1-1]). */
        if (v->packet_id == 0)
            return -1;
    }
    if (pkt->ver == MQTT_VERSION_5) {
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBLISH, 0))
            return -1;
        {
            mqtt_property_t *alias_prop;
            alias_prop = mqtt_properties_find(&v->v5.properties, MQTT_PROPERTY_TOPIC_ALIAS);
            if (alias_prop && alias_prop->b2 == 0)
                return -1;
            if (mqtt_str_empty(&v->topic_name) && !alias_prop)
                return -1;
        }
    }
    mqtt_str_read_all(remaining, &p->message);
    return 0;
}

static int
__parse_puback(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_puback_t *v;

    v = &pkt->v.puback;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (mqtt_str_read_u16(remaining, &v->packet_id))
        return -1;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->i < remaining->n) {
            uint8_t u8;
            if (mqtt_str_read_u8(remaining, &u8))
                return -1;
            v->v5.reason_code = (mqtt_rc_t)u8;
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBACK)) {
                return -1;
            }
        } else
            v->v5.reason_code = MQTT_RC_SUCCESS;
        if (remaining->i < remaining->n) {
            if (__properties_parse(&v->v5.properties, remaining))
                return -1;
        }
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBACK, 0))
            return -1;
    }
    return 0;
}

static int
__parse_pubrec(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_pubrec_t *v;

    v = &pkt->v.pubrec;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (mqtt_str_read_u16(remaining, &v->packet_id))
        return -1;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->i < remaining->n) {
            uint8_t u8;
            if (mqtt_str_read_u8(remaining, &u8))
                return -1;
            v->v5.reason_code = (mqtt_rc_t)u8;
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBREC)) {
                return -1;
            }
        } else
            v->v5.reason_code = MQTT_RC_SUCCESS;
        if (remaining->i < remaining->n) {
            if (__properties_parse(&v->v5.properties, remaining))
                return -1;
        }
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBREC, 0))
            return -1;
    }
    return 0;
}

static int
__parse_pubrel(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_pubrel_t *v;

    v = &pkt->v.pubrel;

    if (!mqtt_fixed_valid(&pkt->f, 0, MQTT_QOS_1, 0))
        return -1;
    if (mqtt_str_read_u16(remaining, &v->packet_id))
        return -1;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->i < remaining->n) {
            uint8_t u8;
            if (mqtt_str_read_u8(remaining, &u8))
                return -1;
            v->v5.reason_code = (mqtt_rc_t)u8;
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBREL)) {
                return -1;
            }
        } else
            v->v5.reason_code = MQTT_RC_SUCCESS;
        if (remaining->i < remaining->n) {
            if (__properties_parse(&v->v5.properties, remaining))
                return -1;
        }
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBREL, 0))
            return -1;
    }
    return 0;
}

static int
__parse_pubcomp(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_pubcomp_t *v;

    v = &pkt->v.pubcomp;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (mqtt_str_read_u16(remaining, &v->packet_id))
        return -1;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->i < remaining->n) {
            uint8_t u8;
            if (mqtt_str_read_u8(remaining, &u8))
                return -1;
            v->v5.reason_code = (mqtt_rc_t)u8;
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBCOMP)) {
                return -1;
            }
        } else
            v->v5.reason_code = MQTT_RC_SUCCESS;
        if (remaining->i < remaining->n) {
            if (__properties_parse(&v->v5.properties, remaining))
                return -1;
        }
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBCOMP, 0))
            return -1;
    }
    return 0;
}

static int
__parse_subscribe(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_subscribe_t *v;
    mqtt_p_subscribe_t *p;
    mqtt_str_t r;
    mqtt_str_t dummy = MQTT_STR_INITIALIZER;
    int i;

    v = &pkt->v.subscribe;
    p = &pkt->p.subscribe;

    if (!mqtt_fixed_valid(&pkt->f, 0, MQTT_QOS_1, 0))
        return -1;
    if (mqtt_str_read_u16(remaining, &v->packet_id))
        return -1;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_SUBSCRIBE, 0))
            return -1;
    }
    mqtt_str_set(&r, remaining);
    while (0 == mqtt_str_read_utf(&r, &dummy)) {
        uint8_t u8;
        if (mqtt_str_empty(&dummy))
            return -1;
        if (mqtt_str_read_u8(&r, &u8))
            return -1;
        p->n++;
    }
    if (p->n == 0)
        return -1;
    p->topic_filters = (mqtt_str_t *)MQTT_MALLOC(p->n * sizeof(mqtt_str_t));
    if (!p->topic_filters) {
        return -1;
    }
    memset(p->topic_filters, 0, p->n * sizeof(mqtt_str_t));
    p->options = (mqtt_subscribe_options_t *)MQTT_MALLOC(p->n * sizeof(mqtt_subscribe_options_t));
    if (!p->options) {
        MQTT_FREE(p->topic_filters);
        p->topic_filters = NULL;
        return -1;
    }
    memset(p->options, 0, p->n * sizeof(mqtt_subscribe_options_t));
    /* topic filters are not validated here: a server must answer a SUBSCRIBE
     * with an invalid filter by SUBACK 0x8F, not by dropping the packet
     * ([MQTT-3.8.4-1]). */
    i = 0;
    while (0 == mqtt_str_read_utf8(remaining, &p->topic_filters[i])) {
        if (mqtt_str_read_u8(remaining, &p->options[i].flags))
            return -1;
        if (!MQTT_IS_QOS(p->options[i].flags & MQTT_SUBOPT_QOS_MASK)) {
            return -1;
        }
        if (pkt->ver == MQTT_VERSION_5) {
            if (p->options[i].flags & 0xC0 || MQTT_SUBOPT_RH(p->options[i].flags) == 3)
                return -1;
        } else {
            if (p->options[i].flags & 0xFC)
                return -1;
        }
        i++;
    }
    return 0;
}

static int
__parse_suback(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_suback_t *v;
    mqtt_p_suback_t *p;
    int i;

    v = &pkt->v.suback;
    p = &pkt->p.suback;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (mqtt_str_read_u16(remaining, &v->packet_id))
        return -1;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_SUBACK, 0))
            return -1;
    }
    p->n = remaining->n - remaining->i;
    if (p->n == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_3) {
        p->v3.granted = (mqtt_suback_granted_t *)MQTT_MALLOC(p->n * sizeof(mqtt_suback_granted_t));
        if (!p->v3.granted)
            return -1;
        i = 0;
        while (remaining->i < remaining->n) {
            if (mqtt_str_read_u8(remaining, &p->v3.granted[i].flags))
                return -1;
            if (!MQTT_IS_QOS(p->v3.granted[i].flags & 0x03)) {
                return -1;
            }
            if (p->v3.granted[i].flags & 0xFC)
                return -1;
            i++;
        }
    } else if (pkt->ver == MQTT_VERSION_4) {
        p->v4.return_codes = (mqtt_src_t *)MQTT_MALLOC(p->n * sizeof(mqtt_src_t));
        if (!p->v4.return_codes)
            return -1;
        i = 0;
        while (remaining->i < remaining->n) {
            uint8_t u8;
            if (mqtt_str_read_u8(remaining, &u8))
                return -1;
            p->v4.return_codes[i] = (mqtt_src_t)u8;
            if (!MQTT_IS_SRC(p->v4.return_codes[i])) {
                return -1;
            }
            i++;
        }
    } else if (pkt->ver == MQTT_VERSION_5) {
        p->v5.reason_codes = (mqtt_rc_t *)MQTT_MALLOC(p->n * sizeof(mqtt_rc_t));
        if (!p->v5.reason_codes)
            return -1;
        i = 0;
        while (remaining->i < remaining->n) {
            uint8_t u8;
            if (mqtt_str_read_u8(remaining, &u8))
                return -1;
            p->v5.reason_codes[i] = (mqtt_rc_t)u8;
            if (!MQTT_IS_RC(p->v5.reason_codes[i]) || !mqtt_rc_valid(p->v5.reason_codes[i], MQTT_SUBACK)) {
                return -1;
            }
            i++;
        }
    }
    return 0;
}

static int
__parse_unsubscribe(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_unsubscribe_t *v;
    mqtt_p_unsubscribe_t *p;
    mqtt_str_t r;
    mqtt_str_t dummy = MQTT_STR_INITIALIZER;
    int i;

    v = &pkt->v.unsubscribe;
    p = &pkt->p.unsubscribe;

    if (!mqtt_fixed_valid(&pkt->f, 0, MQTT_QOS_1, 0))
        return -1;
    if (mqtt_str_read_u16(remaining, &v->packet_id))
        return -1;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_UNSUBSCRIBE, 0))
            return -1;
    }
    mqtt_str_set(&r, remaining);
    while (0 == mqtt_str_read_utf(&r, &dummy)) {
        if (mqtt_str_empty(&dummy))
            return -1;
        p->n++;
    }
    if (p->n == 0)
        return -1;
    p->topic_filters = (mqtt_str_t *)MQTT_MALLOC(p->n * sizeof(mqtt_str_t));
    if (!p->topic_filters)
        return -1;
    memset(p->topic_filters, 0, p->n * sizeof(mqtt_str_t));
    /* topic filters are not validated here: a server must answer an
     * UNSUBSCRIBE with an invalid filter by UNSUBACK 0x8F, not by dropping
     * the packet; see __parse_subscribe for the same reasoning. */
    i = 0;
    while (0 == mqtt_str_read_utf8(remaining, &p->topic_filters[i])) {
        i++;
    }
    return 0;
}

static int
__parse_unsuback(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_unsuback_t *v;
    mqtt_p_unsuback_t *p;

    v = &pkt->v.unsuback;
    p = &pkt->p.unsuback;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (mqtt_str_read_u16(remaining, &v->packet_id))
        return -1;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        int i;
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_UNSUBACK, 0))
            return -1;
        p->v5.n = remaining->n - remaining->i;
        if (p->v5.n == 0)
            return -1;
        p->v5.reason_codes = (mqtt_rc_t *)MQTT_MALLOC(p->v5.n * sizeof(mqtt_rc_t));
        if (!p->v5.reason_codes)
            return -1;
        i = 0;
        while (remaining->i < remaining->n) {
            uint8_t u8;
            if (mqtt_str_read_u8(remaining, &u8))
                return -1;
            p->v5.reason_codes[i] = (mqtt_rc_t)u8;
            if (!MQTT_IS_RC(p->v5.reason_codes[i]) || !mqtt_rc_valid(p->v5.reason_codes[i], MQTT_UNSUBACK)) {
                return -1;
            }
            i++;
        }
    }
    return 0;
}

static int
__parse_pingreq(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (remaining->i != remaining->n)
        return -1;
    return 0;
}

static int
__parse_pingresp(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (remaining->i != remaining->n)
        return -1;
    return 0;
}

static int
__parse_disconnect(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (remaining->i != remaining->n)
            return -1;
    } else if (pkt->ver == MQTT_VERSION_5) {
        mqtt_v_disconnect_t *v;
        v = &pkt->v.disconnect;
        if (remaining->i < remaining->n) {
            uint8_t u8;
            if (mqtt_str_read_u8(remaining, &u8))
                return -1;
            v->v5.reason_code = (mqtt_rc_t)u8;
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_DISCONNECT)) {
                return -1;
            }
        } else {
            v->v5.reason_code = MQTT_RC_NORMAL_DISCONNECTION;
        }
        if (remaining->i < remaining->n) {
            if (__properties_parse(&v->v5.properties, remaining))
                return -1;
        }
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_DISCONNECT, 0))
            return -1;
    }
    return 0;
}

static int
__parse_auth(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_auth_t *v;
    uint8_t u8;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (pkt->ver != MQTT_VERSION_5)
        return -1;
    v = &pkt->v.auth;
    if (remaining->i >= remaining->n) {
        v->v5.reason_code = MQTT_RC_SUCCESS;
        return 0;
    }
    if (mqtt_str_read_u8(remaining, &u8))
        return -1;
    v->v5.reason_code = (mqtt_rc_t)u8;
    if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_AUTH)) {
        return -1;
    }
    if (remaining->i < remaining->n) {
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
    }
    if (!mqtt_properties_valid(&v->v5.properties, MQTT_AUTH, 0))
        return -1;
    return 0;
}

static int
__process(mqtt_parser_t *parser) {
    mqtt_packet_type_t type;
    mqtt_str_t b;
    mqtt_packet_t *pkt;
    int rc;

    pkt = &parser->pkt;
    pkt->ver = parser->version;
    type = (mqtt_packet_type_t)MQTT_FH_TYPE(pkt->f.flags);
    mqtt_str_set(&b, &pkt->b);
    b.i = 0;

    /* before a successful CONNECT the version is unknown, reject anything
     * else as the first packet. */
    if (type != MQTT_CONNECT && !mqtt_is_valid_version(parser->version)) {
        __mqtt_packet_free(pkt);
        return -1;
    }

    switch (type) {
    case MQTT_CONNECT:
        rc = __parse_connect(&b, pkt);
        /* only adopt the version after a valid CONNECT. */
        if (rc == 0)
            parser->version = pkt->ver;
        break;
    case MQTT_CONNACK:
        rc = __parse_connack(&b, pkt);
        break;
    case MQTT_PUBLISH:
        rc = __parse_publish(&b, pkt);
        break;
    case MQTT_PUBACK:
        rc = __parse_puback(&b, pkt);
        break;
    case MQTT_PUBREC:
        rc = __parse_pubrec(&b, pkt);
        break;
    case MQTT_PUBREL:
        rc = __parse_pubrel(&b, pkt);
        break;
    case MQTT_PUBCOMP:
        rc = __parse_pubcomp(&b, pkt);
        break;
    case MQTT_SUBSCRIBE:
        rc = __parse_subscribe(&b, pkt);
        break;
    case MQTT_SUBACK:
        rc = __parse_suback(&b, pkt);
        break;
    case MQTT_UNSUBSCRIBE:
        rc = __parse_unsubscribe(&b, pkt);
        break;
    case MQTT_UNSUBACK:
        rc = __parse_unsuback(&b, pkt);
        break;
    case MQTT_PINGREQ:
        rc = __parse_pingreq(&b, pkt);
        break;
    case MQTT_PINGRESP:
        rc = __parse_pingresp(&b, pkt);
        break;
    case MQTT_DISCONNECT:
        rc = __parse_disconnect(&b, pkt);
        break;
    case MQTT_AUTH:
        rc = __parse_auth(&b, pkt);
        break;
    default:
        rc = -1;
    }
    if (rc < 0) {
        __mqtt_packet_free(pkt);
        return rc;
    }
    if (b.i != b.n) {
        __mqtt_packet_free(pkt);
        return -1;
    }
    return 1;
}

void
mqtt_parser_init(mqtt_parser_t *parser) {
    if (!parser)
        return;
    memset(parser, 0, sizeof *parser);
    parser->state = MQTT_ST_FIXED;
}

void
mqtt_parser_version(mqtt_parser_t *parser, mqtt_version_t version) {
    if (!parser)
        return;
    parser->version = version;
}

void
mqtt_parser_cleanup(mqtt_parser_t *parser) {
    if (!parser)
        return;
    mqtt_packet_cleanup(&parser->pkt);
}

int
mqtt_parse(mqtt_parser_t *parser, mqtt_str_t *b, mqtt_packet_t *pkt) {
    if (!parser || !b || !b->s)
        return -1;
    int rc = 0;
    while (b->i < b->n) {
        uint8_t k = *(uint8_t *)(b->s + b->i);
        switch (parser->state) {
        case MQTT_ST_FIXED:
            parser->error = MQTT_OK;
            memset(&parser->pkt, 0, sizeof parser->pkt);
            parser->pkt.f.flags = k;
            if (!MQTT_IS_PACKET_TYPE(MQTT_FH_TYPE(parser->pkt.f.flags))) {
                parser->error = MQTT_ERR_MALFORMED;
                /* drop the bad byte so the stream can resynchronize. */
                b->i++;
                rc = -1;
                goto e;
            }
            parser->state = MQTT_ST_LENGTH;
            parser->multiplier = 1;
            parser->require = 0;
            b->i++;
            break;
        case MQTT_ST_LENGTH:
            {
                size_t digit = (size_t)(k & 0x7F) * parser->multiplier;
                if (digit > SIZE_MAX - parser->require) {
                    parser->error = MQTT_ERR_MALFORMED;
                    rc = -1;
                    goto e;
                }
                parser->require += digit;
                if (parser->require >= ((size_t)1 << 28)) {
                    parser->error = MQTT_ERR_TOO_LARGE;
                    rc = -1;
                    goto e;
                }
                if (parser->multiplier > 0x80 * 0x80 * 0x80) {
                    parser->error = MQTT_ERR_MALFORMED;
                    rc = -1;
                    goto e;
                }
                parser->multiplier *= 0x80;
            }
            if ((k & 0x80) == 0) {
                if (parser->require > 0) {
                    parser->state = MQTT_ST_REMAIN;
                    parser->pkt.b.s = (char *)MQTT_MALLOC(parser->require);
                    if (!parser->pkt.b.s) {
                        parser->error = MQTT_ERR_NOMEM;
                        rc = -1;
                        goto e;
                    }
                    parser->pkt.b.i = 0;
                    parser->pkt.b.n = parser->require;
                } else {
                    parser->state = MQTT_ST_FIXED;
                    b->i++;
                    rc = __process(parser);
                    goto e;
                }
            }
            b->i++;
            break;
        case MQTT_ST_REMAIN:
            if (!parser->pkt.b.s) {
                parser->error = MQTT_ERR_MALFORMED;
                rc = -1;
                goto e;
            }
            if ((size_t)(b->n - b->i) >= parser->require) {
                if (parser->require > 0) {
                    memcpy(parser->pkt.b.s + parser->pkt.b.i, b->s + b->i, parser->require);
                    parser->pkt.b.i += parser->require;
                }
                parser->state = MQTT_ST_FIXED;
                b->i += parser->require;
                rc = __process(parser);
                goto e;
            } else {
                if (b->i < b->n) {
                    memcpy(parser->pkt.b.s + parser->pkt.b.i, b->s + b->i, b->n - b->i);
                    parser->pkt.b.i += b->n - b->i;
                    parser->require -= b->n - b->i;
                }
                b->i = b->n;
            }
            break;
        }
    }
e:
    if (rc == 1) {
        if (pkt) {
            *pkt = parser->pkt;
            memset(&parser->pkt, 0, sizeof parser->pkt);
        } else {
            /* nobody takes the packet, release it instead of leaking. */
            mqtt_packet_cleanup(&parser->pkt);
        }
    } else if (rc == -1) {
        if (parser->error == MQTT_OK)
            parser->error = MQTT_ERR_PROTOCOL;
        /* reset the parser so it can keep consuming subsequent data. */
        mqtt_packet_cleanup(&parser->pkt);
        parser->state = MQTT_ST_FIXED;
        parser->require = 0;
        parser->multiplier = 1;
    }
    return rc;
}

/*
 * prepare the output buffer: if b->s is preset write in place within the
 * b->n capacity (*owned = 0), otherwise allocate total bytes (*owned = 1).
 */
static int
__serialize_prepare(mqtt_str_t *b, size_t total, int *owned) {
    if (b->s) {
        *owned = 0;
        if (b->i > b->n || total > b->n - b->i)
            return -1;
        return 0;
    }
    *owned = 1;
    b->s = (char *)MQTT_MALLOC(total);
    if (!b->s)
        return -1;
    b->n = total;
    b->i = 0;
    return 0;
}

/* undo __serialize_prepare on failure; only owned buffers are released. */
static void
__serialize_fail(mqtt_str_t *b, int owned) {
    if (owned) {
        MQTT_FREE(b->s);
        b->s = 0;
    }
    b->i = 0;
    if (owned)
        b->n = 0;
}

static int
__property_serialize(const mqtt_property_t *property, mqtt_str_t *b) {
    mqtt_property_type_t type;

    if (mqtt_str_write_u8(b, (uint8_t)property->code))
        return -1;
    type = mqtt_property_type(property->code);
    switch (type) {
    case MQTT_PROPERTY_TYPE_BYTE:
        return mqtt_str_write_u8(b, property->b1);
    case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
        return mqtt_str_write_u16(b, property->b2);
    case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
        return mqtt_str_write_u32(b, property->b4);
    case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        return mqtt_str_write_vbi(b, property->bv);
    case MQTT_PROPERTY_TYPE_BINARY_DATA:
        return mqtt_str_write_utf(b, &property->data);
    case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
        return mqtt_str_write_utf(b, &property->str);
    case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
        if (mqtt_str_write_utf(b, &property->pair.name))
            return -1;
        return mqtt_str_write_utf(b, &property->pair.value);
    }
    return -1;
}

static int
__properties_serialize(const mqtt_properties_t *properties, mqtt_str_t *b) {
    mqtt_property_t *property;

    if (mqtt_str_write_vbi(b, (uint32_t)properties->length))
        return -1;
    property = properties->head;
    while (property) {
        if (__property_serialize(property, b))
            return -1;
        property = property->next;
    }
    return 0;
}

static int
__serialize_connect(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    int owned;
    const mqtt_v_connect_t *v;
    const mqtt_p_connect_t *p;

    v = &pkt->v.connect;
    p = &pkt->p.connect;

    if (!mqtt_is_valid_version(pkt->ver))
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_CONNECT, 0))
            return -1;
        if (!mqtt_properties_valid(&p->v5.will_properties, MQTT_RESERVED, 1))
            return -1;
    }
    if ((v->connect_flags & MQTT_CF_RESERVED) ||
        ((v->connect_flags & MQTT_CF_PASSWORD) && !(v->connect_flags & MQTT_CF_USERNAME)))
        return -1;
    if (mqtt_utf8_validate(&p->client_id))
        return -1;
    if (v->connect_flags & MQTT_CF_WILL_FLAG) {
        if (mqtt_str_empty(&p->will_topic) || mqtt_str_empty(&p->will_message))
            return -1;
        if (mqtt_utf8_validate(&p->will_topic) || mqtt_topic_name_validate(&p->will_topic))
            return -1;
        if (!MQTT_IS_QOS(MQTT_CF_WILL_QOS(v->connect_flags)))
            return -1;
    }
    if ((v->connect_flags & MQTT_CF_USERNAME) && mqtt_utf8_validate(&p->username))
        return -1;

    length = 4;
    if (v->protocol_name.n > SIZE_MAX - 2 - length)
        return -1;
    length += 2 + v->protocol_name.n;
    if (p->client_id.n > SIZE_MAX - 2 - length)
        return -1;
    length += 2 + p->client_id.n;
    if (v->connect_flags & MQTT_CF_USERNAME) {
        if (p->username.n > SIZE_MAX - 2 - length)
            return -1;
        length += 2 + p->username.n;
    }
    if (v->connect_flags & MQTT_CF_PASSWORD) {
        if (p->password.n > SIZE_MAX - 2 - length)
            return -1;
        length += 2 + p->password.n;
    }
    if (v->connect_flags & MQTT_CF_WILL_FLAG) {
        if (p->will_topic.n > SIZE_MAX - 2 - length)
            return -1;
        length += 2 + p->will_topic.n;
        if (p->will_message.n > SIZE_MAX - 2 - length)
            return -1;
        length += 2 + p->will_message.n;
    }
    if (pkt->ver == MQTT_VERSION_5) {
        length += __properties_len(&v->v5.properties);
        if (v->connect_flags & MQTT_CF_WILL_FLAG)
            length += __properties_len(&p->v5.will_properties);
    }

    if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
        return -1;

    if (mqtt_str_write_u8(b, 0x10) ||
        mqtt_str_write_vbi(b, (uint32_t)length) ||
        mqtt_str_write_utf(b, &v->protocol_name) ||
        mqtt_str_write_u8(b, (uint8_t)v->protocol_version) ||
        mqtt_str_write_u8(b, v->connect_flags) ||
        mqtt_str_write_u16(b, v->keep_alive))
        goto fail;
    if (pkt->ver == MQTT_VERSION_5 && __properties_serialize(&v->v5.properties, b))
        goto fail;
    if (mqtt_str_write_utf(b, &p->client_id))
        goto fail;
    if (v->connect_flags & MQTT_CF_WILL_FLAG) {
        if (pkt->ver == MQTT_VERSION_5 && __properties_serialize(&p->v5.will_properties, b))
            goto fail;
        if (mqtt_str_write_utf(b, &p->will_topic) ||
            mqtt_str_write_utf(b, &p->will_message))
            goto fail;
    }
    if ((v->connect_flags & MQTT_CF_USERNAME) && mqtt_str_write_utf(b, &p->username))
        goto fail;
    if ((v->connect_flags & MQTT_CF_PASSWORD) && mqtt_str_write_utf(b, &p->password))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_connack(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    const mqtt_v_connack_t *v;

    v = &pkt->v.connack;
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (pkt->ver == MQTT_VERSION_3) {
            if (!MQTT_IS_CRC(v->v3.return_code))
                return -1;
        } else {
            if (v->v4.acknowledge_flags.flags & ~MQTT_ACK_SESSION_PRESENT)
                return -1;
            if (!MQTT_IS_CRC(v->v4.return_code))
                return -1;
        }
        if (__serialize_prepare(b, 4, &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x20) ||
            mqtt_str_write_u8(b, 0x02))
            goto fail;
        if (pkt->ver == MQTT_VERSION_3) {
            if (mqtt_str_write_u8(b, 0x00) ||
                mqtt_str_write_u8(b, (uint8_t)v->v3.return_code))
                goto fail;
        } else {
            if (mqtt_str_write_u8(b, v->v4.acknowledge_flags.flags) ||
                mqtt_str_write_u8(b, (uint8_t)v->v4.return_code))
                goto fail;
        }
        return 0;
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        if (v->v5.acknowledge_flags.flags & ~MQTT_ACK_SESSION_PRESENT)
            return -1;
        if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_CONNACK))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_CONNACK, 0))
            return -1;
        length = 2 + __properties_len(&v->v5.properties);
        if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x20) ||
            mqtt_str_write_vbi(b, (uint32_t)length) ||
            mqtt_str_write_u8(b, v->v5.acknowledge_flags.flags) ||
            mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code) ||
            __properties_serialize(&v->v5.properties, b))
            goto fail;
        return 0;
    }
    return -1;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_publish(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    int owned;
    const mqtt_v_publish_t *v;
    const mqtt_p_publish_t *p;
    mqtt_qos_t qos;

    v = &pkt->v.publish;
    p = &pkt->p.publish;

    qos = (mqtt_qos_t)MQTT_FH_QOS(pkt->f.flags);
    if (!MQTT_IS_QOS(qos))
        return -1;
    if (qos == MQTT_QOS_0 && MQTT_FH_DUP(pkt->f.flags))
        return -1;
    if (MQTT_FH_RETAIN(pkt->f.flags) > 1)
        return -1;
    if (p->message.n >= ((size_t)1 << 28)) {
        return -1;
    }
    if (pkt->ver == MQTT_VERSION_5) {
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBLISH, 0))
            return -1;
    }
    if (qos > MQTT_QOS_0 && v->packet_id == 0)
        return -1;
    if (mqtt_utf8_validate(&v->topic_name) || mqtt_topic_wildcard(&v->topic_name))
        return -1;
    if (mqtt_str_empty(&v->topic_name) && pkt->ver != MQTT_VERSION_5)
        return -1;

    length = 2 + v->topic_name.n + p->message.n;
    if (qos > MQTT_QOS_0)
        length += 2;
    if (pkt->ver == MQTT_VERSION_5)
        length += __properties_len(&v->v5.properties);

    if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
        return -1;

    if (mqtt_str_write_u8(b, pkt->f.flags) ||
        mqtt_str_write_vbi(b, (uint32_t)length) ||
        mqtt_str_write_utf(b, &v->topic_name))
        goto fail;
    if (qos > MQTT_QOS_0 && mqtt_str_write_u16(b, v->packet_id))
        goto fail;
    if (pkt->ver == MQTT_VERSION_5 && __properties_serialize(&v->v5.properties, b))
        goto fail;
    if (mqtt_str_concat(b, &p->message))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_puback(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    const mqtt_v_puback_t *v;

    v = &pkt->v.puback;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (__serialize_prepare(b, 4, &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x40) ||
            mqtt_str_write_u8(b, 0x02) ||
            mqtt_str_write_u16(b, v->packet_id))
            goto fail;
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBACK))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBACK, 0))
            return -1;
        length = 3 + __properties_len(&v->v5.properties);
        if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x40) ||
            mqtt_str_write_vbi(b, (uint32_t)length) ||
            mqtt_str_write_u16(b, v->packet_id) ||
            mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code) ||
            __properties_serialize(&v->v5.properties, b))
            goto fail;
    } else {
        return -1;
    }
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_pubrec(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    const mqtt_v_pubrec_t *v;

    v = &pkt->v.pubrec;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (__serialize_prepare(b, 4, &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x50) ||
            mqtt_str_write_u8(b, 0x02) ||
            mqtt_str_write_u16(b, v->packet_id))
            goto fail;
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBREC))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBREC, 0))
            return -1;
        length = 3 + __properties_len(&v->v5.properties);
        if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x50) ||
            mqtt_str_write_vbi(b, (uint32_t)length) ||
            mqtt_str_write_u16(b, v->packet_id) ||
            mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code) ||
            __properties_serialize(&v->v5.properties, b))
            goto fail;
    } else {
        return -1;
    }
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_pubrel(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    const mqtt_v_pubrel_t *v;

    v = &pkt->v.pubrel;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (__serialize_prepare(b, 4, &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x62) ||
            mqtt_str_write_u8(b, 0x02) ||
            mqtt_str_write_u16(b, v->packet_id))
            goto fail;
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBREL))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBREL, 0))
            return -1;
        length = 3 + __properties_len(&v->v5.properties);
        if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x62) ||
            mqtt_str_write_vbi(b, (uint32_t)length) ||
            mqtt_str_write_u16(b, v->packet_id) ||
            mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code) ||
            __properties_serialize(&v->v5.properties, b))
            goto fail;
    } else {
        return -1;
    }
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_pubcomp(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    const mqtt_v_pubcomp_t *v;

    v = &pkt->v.pubcomp;
    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (__serialize_prepare(b, 4, &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x70) ||
            mqtt_str_write_u8(b, 0x02) ||
            mqtt_str_write_u16(b, v->packet_id))
            goto fail;
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBCOMP))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBCOMP, 0))
            return -1;
        length = 3 + __properties_len(&v->v5.properties);
        if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0x70) ||
            mqtt_str_write_vbi(b, (uint32_t)length) ||
            mqtt_str_write_u16(b, v->packet_id) ||
            mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code) ||
            __properties_serialize(&v->v5.properties, b))
            goto fail;
    } else {
        return -1;
    }
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_subscribe(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    int owned;
    const mqtt_v_subscribe_t *v;
    const mqtt_p_subscribe_t *p;
    int i;

    v = &pkt->v.subscribe;
    p = &pkt->p.subscribe;

    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_SUBSCRIBE, 0))
            return -1;
    }
    if (p->n == 0)
        return -1;

    length = 2;
    for (i = 0; i < p->n; i++) {
        if (p->topic_filters[i].n == 0)
            return -1;
        if (mqtt_utf8_validate(&p->topic_filters[i]) || mqtt_topic_filter_validate(&p->topic_filters[i]))
            return -1;
        if (!MQTT_IS_QOS(p->options[i].flags & MQTT_SUBOPT_QOS_MASK))
            return -1;
        if (pkt->ver == MQTT_VERSION_5) {
            if (p->options[i].flags & 0xC0 || MQTT_SUBOPT_RH(p->options[i].flags) == 3)
                return -1;
        } else {
            if (p->options[i].flags & 0xFC)
                return -1;
        }
        length += 2 + p->topic_filters[i].n + 1;
    }
    if (pkt->ver == MQTT_VERSION_5)
        length += __properties_len(&v->v5.properties);

    if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
        return -1;

    if (mqtt_str_write_u8(b, 0x82) ||
        mqtt_str_write_vbi(b, (uint32_t)length) ||
        mqtt_str_write_u16(b, v->packet_id))
        goto fail;
    if (pkt->ver == MQTT_VERSION_5 && __properties_serialize(&v->v5.properties, b))
        goto fail;
    for (i = 0; i < p->n; i++) {
        if (mqtt_str_write_utf(b, &p->topic_filters[i]) ||
            mqtt_str_write_u8(b, p->options[i].flags))
            goto fail;
    }
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_suback(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    int owned;
    const mqtt_v_suback_t *v;
    const mqtt_p_suback_t *p;
    int i;

    v = &pkt->v.suback;
    p = &pkt->p.suback;

    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_SUBACK, 0))
            return -1;
    }
    if (p->n == 0)
        return -1;
    for (i = 0; i < p->n; i++) {
        if (pkt->ver == MQTT_VERSION_3) {
            if (p->v3.granted[i].flags & 0xFC)
                return -1;
        } else if (pkt->ver == MQTT_VERSION_4) {
            if (!MQTT_IS_SRC(p->v4.return_codes[i]))
                return -1;
        } else if (pkt->ver == MQTT_VERSION_5) {
            if (!MQTT_IS_RC(p->v5.reason_codes[i]) || !mqtt_rc_valid(p->v5.reason_codes[i], MQTT_SUBACK))
                return -1;
        } else {
            return -1;
        }
    }

    length = p->n + 2;
    if (pkt->ver == MQTT_VERSION_5)
        length += __properties_len(&v->v5.properties);

    if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
        return -1;

    if (mqtt_str_write_u8(b, 0x90) ||
        mqtt_str_write_vbi(b, (uint32_t)length) ||
        mqtt_str_write_u16(b, v->packet_id))
        goto fail;
    if (pkt->ver == MQTT_VERSION_5 && __properties_serialize(&v->v5.properties, b))
        goto fail;
    for (i = 0; i < p->n; i++) {
        if (pkt->ver == MQTT_VERSION_3) {
            if (mqtt_str_write_u8(b, p->v3.granted[i].flags))
                goto fail;
        } else if (pkt->ver == MQTT_VERSION_4) {
            if (mqtt_str_write_u8(b, (uint8_t)p->v4.return_codes[i]))
                goto fail;
        } else if (pkt->ver == MQTT_VERSION_5) {
            if (mqtt_str_write_u8(b, (uint8_t)p->v5.reason_codes[i]))
                goto fail;
        }
    }
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_unsubscribe(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    int owned;
    const mqtt_v_unsubscribe_t *v;
    const mqtt_p_unsubscribe_t *p;
    int i;

    v = &pkt->v.unsubscribe;
    p = &pkt->p.unsubscribe;

    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_5) {
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_UNSUBSCRIBE, 0))
            return -1;
    }
    if (p->n == 0)
        return -1;

    length = 2;
    for (i = 0; i < p->n; i++) {
        if (p->topic_filters[i].n == 0)
            return -1;
        if (mqtt_utf8_validate(&p->topic_filters[i]) || mqtt_topic_filter_validate(&p->topic_filters[i]))
            return -1;
        length += 2 + p->topic_filters[i].n;
    }
    if (pkt->ver == MQTT_VERSION_5)
        length += __properties_len(&v->v5.properties);

    if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
        return -1;

    if (mqtt_str_write_u8(b, 0xa2) ||
        mqtt_str_write_vbi(b, (uint32_t)length) ||
        mqtt_str_write_u16(b, v->packet_id))
        goto fail;
    if (pkt->ver == MQTT_VERSION_5 && __properties_serialize(&v->v5.properties, b))
        goto fail;
    for (i = 0; i < p->n; i++) {
        if (mqtt_str_write_utf(b, &p->topic_filters[i]))
            goto fail;
    }
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_unsuback(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    const mqtt_v_unsuback_t *v;
    const mqtt_p_unsuback_t *p;

    v = &pkt->v.unsuback;
    p = &pkt->p.unsuback;

    if (v->packet_id == 0)
        return -1;
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (__serialize_prepare(b, 4, &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0xb0) ||
            mqtt_str_write_u8(b, 0x02) ||
            mqtt_str_write_u16(b, v->packet_id))
            goto fail;
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        int i;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_UNSUBACK, 0))
            return -1;
        if (p->v5.n == 0)
            return -1;
        for (i = 0; i < p->v5.n; i++) {
            if (!MQTT_IS_RC(p->v5.reason_codes[i]) || !mqtt_rc_valid(p->v5.reason_codes[i], MQTT_UNSUBACK))
                return -1;
        }
        length = 2 + __properties_len(&v->v5.properties) + p->v5.n;
        if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0xb0) ||
            mqtt_str_write_vbi(b, (uint32_t)length) ||
            mqtt_str_write_u16(b, v->packet_id) ||
            __properties_serialize(&v->v5.properties, b))
            goto fail;
        for (i = 0; i < p->v5.n; i++) {
            if (mqtt_str_write_u8(b, (uint8_t)p->v5.reason_codes[i]))
                goto fail;
        }
    } else {
        return -1;
    }
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_pingreq(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    (void)pkt;
    if (__serialize_prepare(b, 2, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 0xc0) ||
        mqtt_str_write_u8(b, 0x00))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_pingresp(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    (void)pkt;
    if (__serialize_prepare(b, 2, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 0xd0) ||
        mqtt_str_write_u8(b, 0x00))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_disconnect(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (__serialize_prepare(b, 2, &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0xe0) ||
            mqtt_str_write_u8(b, 0x00))
            goto fail;
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        const mqtt_v_disconnect_t *v;
        v = &pkt->v.disconnect;
        if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_DISCONNECT))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_DISCONNECT, 0))
            return -1;
        length = 1 + __properties_len(&v->v5.properties);
        if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0xe0) ||
            mqtt_str_write_vbi(b, (uint32_t)length) ||
            mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code) ||
            __properties_serialize(&v->v5.properties, b))
            goto fail;
    } else {
        return -1;
    }
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__serialize_auth(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    /* AUTH only exists in mqttv5.0. */
    if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        const mqtt_v_auth_t *v;
        v = &pkt->v.auth;
        if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_AUTH))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_AUTH, 0))
            return -1;
        length = 1 + __properties_len(&v->v5.properties);
        if (__serialize_prepare(b, length + 1 + mqtt_vbi_length(length), &owned))
            return -1;
        if (mqtt_str_write_u8(b, 0xf0) ||
            mqtt_str_write_vbi(b, (uint32_t)length) ||
            mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code) ||
            __properties_serialize(&v->v5.properties, b))
            goto fail;
        return 0;
    }
    return -1;
fail:
    __serialize_fail(b, owned);
    return -1;
}

int
mqtt_serialize(mqtt_packet_t *pkt, mqtt_str_t *b) {
    int rc;
    int preset;

    if (!pkt || !b)
        return -1;
    /* preset buffer mode: write in place within b->n; otherwise allocate. */
    preset = (b->s != 0);
    if (!preset) {
        b->i = 0;
        b->n = 0;
    } else {
        b->i = 0;
    }
    if (!mqtt_is_valid_version(pkt->ver)) {
        return -1;
    }
    switch (MQTT_FH_TYPE(pkt->f.flags)) {
    case MQTT_CONNECT:
        rc = __serialize_connect(pkt, b);
        break;
    case MQTT_CONNACK:
        rc = __serialize_connack(pkt, b);
        break;
    case MQTT_PUBLISH:
        rc = __serialize_publish(pkt, b);
        break;
    case MQTT_PUBACK:
        rc = __serialize_puback(pkt, b);
        break;
    case MQTT_PUBREC:
        rc = __serialize_pubrec(pkt, b);
        break;
    case MQTT_PUBREL:
        rc = __serialize_pubrel(pkt, b);
        break;
    case MQTT_PUBCOMP:
        rc = __serialize_pubcomp(pkt, b);
        break;
    case MQTT_SUBSCRIBE:
        rc = __serialize_subscribe(pkt, b);
        break;
    case MQTT_SUBACK:
        rc = __serialize_suback(pkt, b);
        break;
    case MQTT_UNSUBSCRIBE:
        rc = __serialize_unsubscribe(pkt, b);
        break;
    case MQTT_UNSUBACK:
        rc = __serialize_unsuback(pkt, b);
        break;
    case MQTT_PINGREQ:
        rc = __serialize_pingreq(pkt, b);
        break;
    case MQTT_PINGRESP:
        rc = __serialize_pingresp(pkt, b);
        break;
    case MQTT_DISCONNECT:
        rc = __serialize_disconnect(pkt, b);
        break;
    case MQTT_AUTH:
        rc = __serialize_auth(pkt, b);
        break;
    case MQTT_RESERVED:
    default:
        rc = -1;
        break;
    }
    if (rc == 0 && preset) {
        /* preset buffer: expose the serialized length in b->n. */
        b->n = b->i;
    }
    return rc;
}

static size_t
__property_len(const mqtt_property_t *property) {
    switch (mqtt_property_type(property->code)) {
    case MQTT_PROPERTY_TYPE_BYTE:
        return 1;
    case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
        return 2;
    case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
        return 4;
    case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        return mqtt_vbi_length(property->bv);
    case MQTT_PROPERTY_TYPE_BINARY_DATA:
        return 2 + property->data.n;
    case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
        return 2 + property->str.n;
    case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
        return 4 + property->pair.name.n + property->pair.value.n;
    }
    return 0;
}

void
mqtt_properties_add(mqtt_properties_t *properties, mqtt_property_code_t code, const void *value, const char *name) {
    mqtt_property_t *property;
    mqtt_property_type_t type;

    if (!properties)
        return;

    type = mqtt_property_type(code);

    property = (mqtt_property_t *)MQTT_MALLOC(sizeof *property);
    if (!property)
        return;
    memset(property, 0, sizeof *property);
    property->code = code;
    /* tail-insert to keep property order ([MQTT-5] §2.2.2). */
    if (properties->head) {
        mqtt_property_t *tail;
        tail = properties->head;
        while (tail->next)
            tail = tail->next;
        tail->next = property;
    } else {
        properties->head = property;
    }

    switch (type) {
    case MQTT_PROPERTY_TYPE_BYTE:
        property->b1 = *(uint8_t *)value;
        break;
    case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
        property->b2 = *(uint16_t *)value;
        break;
    case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
        property->b4 = *(uint32_t *)value;
        break;
    case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        property->bv = *(uint32_t *)value;
        break;
    case MQTT_PROPERTY_TYPE_BINARY_DATA:
        mqtt_str_set(&property->data, (mqtt_str_t *)value);
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
        mqtt_str_from(&property->str, (const char *)value);
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
        mqtt_str_from(&property->pair.name, name);
        mqtt_str_from(&property->pair.value, (const char *)value);
        break;
    }
    properties->length += __property_len(property) + 1;
}

mqtt_property_t *
mqtt_properties_find(mqtt_properties_t *properties, mqtt_property_code_t code) {
    mqtt_property_t *property;
    if (!properties)
        return 0;
    property = properties->head;
    while (property) {
        if (property->code == code)
            return property;
        property = property->next;
    }
    return 0;
}

mqtt_property_t *
mqtt_properties_remove(mqtt_properties_t *properties, mqtt_property_code_t code) {
    mqtt_property_t **pp;
    if (!properties)
        return 0;
    pp = &properties->head;
    while (*pp) {
        mqtt_property_t *property;
        property = *pp;
        if (property->code == code) {
            properties->length -= __property_len(property) + 1;
            *pp = property->next;
            return property;
        }
        pp = &property->next;
    }
    return 0;
}

void
mqtt_sn_packet_init(mqtt_sn_packet_t *pkt, mqtt_sn_packet_type_t type) {
    memset(pkt, 0, sizeof *pkt);
    pkt->type = type;
    if (type == MQTT_SN_CONNECT) {
        pkt->v.connect.protocol_id = MQTT_SN_PROTOCOL_VERSION;
    }
}

void
mqtt_sn_packet_cleanup(mqtt_sn_packet_t *pkt) {
    if (!pkt)
        return;
    mqtt_str_free(&pkt->b);
    memset(pkt, 0, sizeof *pkt);
}

static int
__sn_parse_advertise(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i + 3 != remaining->n)
        return -1;
    if (mqtt_str_read_u8(remaining, &pkt->v.advertise.gwid))
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.advertise.duration))
        return -1;
    return 0;
}

static int
__sn_parse_searchgw(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i + 1 != remaining->n)
        return -1;
    if (mqtt_str_read_u8(remaining, &pkt->v.searchgw.radius))
        return -1;
    return 0;
}

static int
__sn_parse_gwinfo(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (mqtt_str_read_u8(remaining, &pkt->v.gwinfo.gwid))
        return -1;
    if (remaining->i < remaining->n) {
        mqtt_str_read_all(remaining, &pkt->v.gwinfo.gwadd);
    }
    return 0;
}

static int
__sn_parse_connect(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n - remaining->i < 4 || remaining->n - remaining->i > 27)
        return -1;
    if (mqtt_str_read_u8(remaining, &pkt->v.connect.flags.flag))
        return -1;
    if (pkt->v.connect.flags.flag & 0xF3)
        return -1;
    if (mqtt_str_read_u8(remaining, &pkt->v.connect.protocol_id))
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.connect.duration))
        return -1;
    if (remaining->i < remaining->n) {
        mqtt_str_read_all(remaining, &pkt->v.connect.client_id);
    }
    return 0;
}

static int
__sn_parse_connack(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i + 1 != remaining->n)
        return -1;
    uint8_t u8;
    if (mqtt_str_read_u8(remaining, &u8))
        return -1;
    pkt->v.connack.return_code = (mqtt_sn_rc_t)u8;
    if (!MQTT_SN_IS_RC(pkt->v.connack.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_willtopicreq(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    (void)pkt;
    if (remaining->i != remaining->n)
        return -1;
    return 0;
}

static int
__sn_parse_willtopic(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i == remaining->n)
        return 0;
    if (mqtt_str_read_u8(remaining, &pkt->v.willtopic.flags.flag))
        return -1;
    if (remaining->i < remaining->n) {
        mqtt_str_read_all(remaining, &pkt->v.willtopic.topic_name);
    }
    return 0;
}

static int
__sn_parse_willmsgreq(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    (void)pkt;
    if (remaining->i != remaining->n)
        return -1;
    return 0;
}

static int
__sn_parse_willmsg(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i < remaining->n) {
        mqtt_str_read_all(remaining, &pkt->v.willmsg.message);
    }
    return 0;
}

static int
__sn_parse_register(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (mqtt_str_read_u16(remaining, &pkt->v.regist.topic_id))
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.regist.msg_id))
        return -1;
    if (remaining->i == remaining->n)
        return -1;
    mqtt_str_read_all(remaining, &pkt->v.regist.topic_name);
    return 0;
}

static int
__sn_parse_regack(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t u8;
    if (remaining->i + 5 != remaining->n)
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.regack.topic_id))
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.regack.msg_id))
        return -1;
    if (mqtt_str_read_u8(remaining, &u8))
        return -1;
    pkt->v.regack.return_code = (mqtt_sn_rc_t)u8;
    if (!MQTT_SN_IS_RC(pkt->v.regack.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_publish(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t topic_id_type;

    if (remaining->i + 5 > remaining->n)
        return -1;
    if (mqtt_str_read_u8(remaining, &pkt->v.publish.flags.flag))
        return -1;
    if (!MQTT_SN_IS_QOS(MQTT_SNF_QOS(pkt->v.publish.flags.flag)))
        return -1;
    topic_id_type = MQTT_SNF_TID_TYPE(pkt->v.publish.flags.flag);
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED || topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        if (mqtt_str_read_u16(remaining, &pkt->v.publish.topic.id))
            return -1;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        if (remaining->i + 2 > remaining->n)
            return -1;
        memcpy(pkt->v.publish.topic.shor, remaining->s + remaining->i, 2);
        remaining->i += 2;
    } else {
        return -1;
    }
    pkt->v.publish.topic.type = (mqtt_sn_topic_id_type_t)topic_id_type;
    if (mqtt_str_read_u16(remaining, &pkt->v.publish.msg_id))
        return -1;
    if (MQTT_SNF_QOS(pkt->v.publish.flags.flag) == 0 && pkt->v.publish.msg_id != 0)
        return -1;
    if (MQTT_SNF_QOS(pkt->v.publish.flags.flag) == 3 && pkt->v.publish.msg_id != 0)
        return -1;
    if (remaining->i < remaining->n) {
        mqtt_str_read_all(remaining, &pkt->v.publish.data);
    }
    return 0;
}

static int
__sn_parse_puback(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t u8;
    if (remaining->i + 5 != remaining->n)
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.puback.topic.id))
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.puback.msg_id))
        return -1;
    if (mqtt_str_read_u8(remaining, &u8))
        return -1;
    pkt->v.puback.return_code = (mqtt_sn_rc_t)u8;
    if (!MQTT_SN_IS_RC(pkt->v.puback.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_pubrec(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i + 2 != remaining->n)
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.pubrec.msg_id))
        return -1;
    return 0;
}

static int
__sn_parse_pubrel(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i + 2 != remaining->n)
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.pubrel.msg_id))
        return -1;
    return 0;
}

static int
__sn_parse_pubcomp(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i + 2 != remaining->n)
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.pubcomp.msg_id))
        return -1;
    return 0;
}

static int
__sn_parse_subscribe(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t topic_id_type;

    if (remaining->i + 4 > remaining->n)
        return -1;
    if (mqtt_str_read_u8(remaining, &pkt->v.subscribe.flags.flag))
        return -1;
    if (!MQTT_SN_IS_QOS(MQTT_SNF_QOS(pkt->v.subscribe.flags.flag)))
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.subscribe.msg_id))
        return -1;
    topic_id_type = MQTT_SNF_TID_TYPE(pkt->v.subscribe.flags.flag);
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_read_all(remaining, &pkt->v.subscribe.topic.name);
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        if (remaining->i + 2 > remaining->n)
            return -1;
        memcpy(pkt->v.subscribe.topic.shor, remaining->s + remaining->i, 2);
        remaining->i += 2;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED) {
        if (mqtt_str_read_u16(remaining, &pkt->v.subscribe.topic.id))
            return -1;
    }
    pkt->v.subscribe.topic.type = (mqtt_sn_topic_id_type_t)topic_id_type;
    return 0;
}

static int
__sn_parse_suback(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t u8;
    if (remaining->i + 6 > remaining->n)
        return -1;
    if (mqtt_str_read_u8(remaining, &pkt->v.suback.flags.flag))
        return -1;
    if (!MQTT_SN_IS_QOS(MQTT_SNF_QOS(pkt->v.suback.flags.flag)))
        return -1;
    if (MQTT_SNF_QOS(pkt->v.suback.flags.flag) > MQTT_QOS_2)
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.suback.topic_id))
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.suback.msg_id))
        return -1;
    if (mqtt_str_read_u8(remaining, &u8))
        return -1;
    pkt->v.suback.return_code = (mqtt_sn_rc_t)u8;
    if (!MQTT_SN_IS_RC(pkt->v.suback.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_unsubscribe(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t topic_id_type;

    if (remaining->i + 4 > remaining->n)
        return -1;
    if (mqtt_str_read_u8(remaining, &pkt->v.unsubscribe.flags.flag))
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.unsubscribe.msg_id))
        return -1;
    topic_id_type = MQTT_SNF_TID_TYPE(pkt->v.unsubscribe.flags.flag);
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_read_all(remaining, &pkt->v.unsubscribe.topic.name);
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        if (remaining->i + 2 > remaining->n)
            return -1;
        memcpy(pkt->v.unsubscribe.topic.shor, remaining->s + remaining->i, 2);
        remaining->i += 2;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED) {
        if (mqtt_str_read_u16(remaining, &pkt->v.unsubscribe.topic.id))
            return -1;
    }
    pkt->v.unsubscribe.topic.type = (mqtt_sn_topic_id_type_t)topic_id_type;
    return 0;
}

static int
__sn_parse_unsuback(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i + 2 != remaining->n)
        return -1;
    if (mqtt_str_read_u16(remaining, &pkt->v.unsuback.msg_id))
        return -1;
    return 0;
}

static int
__sn_parse_pingreq(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i < remaining->n) {
        mqtt_str_read_all(remaining, &pkt->v.pingreq.client_id);
    }
    return 0;
}

static int
__sn_parse_pingresp(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    (void)pkt;
    if (remaining->i != remaining->n)
        return -1;
    return 0;
}

static int
__sn_parse_disconnect(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i < remaining->n) {
        if (remaining->i + 2 != remaining->n)
            return -1;
        if (mqtt_str_read_u16(remaining, &pkt->v.disconnect.duration))
            return -1;
    }
    return 0;
}

static int
__sn_parse_willtopicupd(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i == remaining->n)
        return 0;
    if (mqtt_str_read_u8(remaining, &pkt->v.willtopicupd.flags.flag))
        return -1;
    if (!MQTT_SN_IS_QOS(MQTT_SNF_QOS(pkt->v.willtopicupd.flags.flag)))
        return -1;
    if (remaining->i < remaining->n) {
        mqtt_str_read_all(remaining, &pkt->v.willtopicupd.topic_name);
    }
    return 0;
}

static int
__sn_parse_willmsgupd(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i < remaining->n) {
        mqtt_str_read_all(remaining, &pkt->v.willmsgupd.message);
    }
    return 0;
}

static int
__sn_parse_willtopicresp(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t u8;
    if (remaining->i + 1 != remaining->n)
        return -1;
    if (mqtt_str_read_u8(remaining, &u8))
        return -1;
    pkt->v.willtopicresp.return_code = (mqtt_sn_rc_t)u8;
    if (!MQTT_SN_IS_RC(pkt->v.willtopicresp.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_willmsgresp(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t u8;
    if (remaining->i + 1 != remaining->n)
        return -1;
    if (mqtt_str_read_u8(remaining, &u8))
        return -1;
    pkt->v.willmsgresp.return_code = (mqtt_sn_rc_t)u8;
    if (!MQTT_SN_IS_RC(pkt->v.willmsgresp.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_encapsulated(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->i == remaining->n)
        return -1;
    if (mqtt_str_read_u8(remaining, &pkt->v.encapsulated.ctrl))
        return -1;
    if (pkt->v.encapsulated.ctrl & MQTT_ENC_RADIUS) {
        if (mqtt_str_read_u8(remaining, &pkt->v.encapsulated.radius))
            return -1;
    }
    if (remaining->i < remaining->n) {
        mqtt_str_read_all(remaining, &pkt->v.encapsulated.message);
    }
    return 0;
}

static int
__sn_process(mqtt_sn_parser_t *parser) {
    mqtt_sn_packet_type_t type;
    mqtt_str_t b;
    mqtt_sn_packet_t *pkt;
    int rc;

    pkt = &parser->pkt;
    type = pkt->type;
    mqtt_str_set(&b, &pkt->b);
    b.i = 0;

    switch (type) {
    case MQTT_SN_ADVERTISE:
        rc = __sn_parse_advertise(pkt, &b);
        break;
    case MQTT_SN_SEARCHGW:
        rc = __sn_parse_searchgw(pkt, &b);
        break;
    case MQTT_SN_GWINFO:
        rc = __sn_parse_gwinfo(pkt, &b);
        break;
    case MQTT_SN_CONNECT:
        rc = __sn_parse_connect(pkt, &b);
        break;
    case MQTT_SN_CONNACK:
        rc = __sn_parse_connack(pkt, &b);
        break;
    case MQTT_SN_WILLTOPICREQ:
        rc = __sn_parse_willtopicreq(pkt, &b);
        break;
    case MQTT_SN_WILLTOPIC:
        rc = __sn_parse_willtopic(pkt, &b);
        break;
    case MQTT_SN_WILLMSGREQ:
        rc = __sn_parse_willmsgreq(pkt, &b);
        break;
    case MQTT_SN_WILLMSG:
        rc = __sn_parse_willmsg(pkt, &b);
        break;
    case MQTT_SN_REGISTER:
        rc = __sn_parse_register(pkt, &b);
        break;
    case MQTT_SN_REGACK:
        rc = __sn_parse_regack(pkt, &b);
        break;
    case MQTT_SN_PUBLISH:
        rc = __sn_parse_publish(pkt, &b);
        break;
    case MQTT_SN_PUBACK:
        rc = __sn_parse_puback(pkt, &b);
        break;
    case MQTT_SN_PUBREC:
        rc = __sn_parse_pubrec(pkt, &b);
        break;
    case MQTT_SN_PUBREL:
        rc = __sn_parse_pubrel(pkt, &b);
        break;
    case MQTT_SN_PUBCOMP:
        rc = __sn_parse_pubcomp(pkt, &b);
        break;
    case MQTT_SN_SUBSCRIBE:
        rc = __sn_parse_subscribe(pkt, &b);
        break;
    case MQTT_SN_SUBACK:
        rc = __sn_parse_suback(pkt, &b);
        break;
    case MQTT_SN_UNSUBSCRIBE:
        rc = __sn_parse_unsubscribe(pkt, &b);
        break;
    case MQTT_SN_UNSUBACK:
        rc = __sn_parse_unsuback(pkt, &b);
        break;
    case MQTT_SN_PINGREQ:
        rc = __sn_parse_pingreq(pkt, &b);
        break;
    case MQTT_SN_PINGRESP:
        rc = __sn_parse_pingresp(pkt, &b);
        break;
    case MQTT_SN_DISCONNECT:
        rc = __sn_parse_disconnect(pkt, &b);
        break;
    case MQTT_SN_WILLTOPICUPD:
        rc = __sn_parse_willtopicupd(pkt, &b);
        break;
    case MQTT_SN_WILLMSGUPD:
        rc = __sn_parse_willmsgupd(pkt, &b);
        break;
    case MQTT_SN_WILLTOPICRESP:
        rc = __sn_parse_willtopicresp(pkt, &b);
        break;
    case MQTT_SN_WILLMSGRESP:
        rc = __sn_parse_willmsgresp(pkt, &b);
        break;
    case MQTT_SN_ENCAPSULATED:
        rc = __sn_parse_encapsulated(pkt, &b);
        break;
    default:
        rc = -1;
    }
    if (rc) {
        return rc;
    }
    if (b.i != b.n) {
        return -1;
    }
    return 1;
}

void
mqtt_sn_parser_init(mqtt_sn_parser_t *parser) {
    if (!parser)
        return;
    memset(parser, 0, sizeof *parser);
    parser->state = MQTT_SN_ST_LENGTH;
}

void
mqtt_sn_parser_cleanup(mqtt_sn_parser_t *parser) {
    if (!parser)
        return;
    mqtt_sn_packet_cleanup(&parser->pkt);
}

int
mqtt_sn_parse(mqtt_sn_parser_t *parser, mqtt_str_t *b, mqtt_sn_packet_t *pkt) {
    if (!parser || !b || !b->s)
        return -1;
    int rc = 0;
    while (b->i < b->n) {
        uint8_t k = *(uint8_t *)(b->s + b->i);
        switch (parser->state) {
        case MQTT_SN_ST_LENGTH:
            parser->error = MQTT_OK;
            memset(&parser->pkt, 0, sizeof parser->pkt);
            if (parser->multiplier == 0) {
                if (k == 0x01) {
                    parser->multiplier = 1;
                    b->i++;
                    continue;
                } else {
                    parser->require = k;
                    if (parser->require < 2) {
                        parser->error = MQTT_ERR_MALFORMED;
                        rc = -1;
                        goto e;
                    }
                    parser->require -= 1;
                    parser->state = MQTT_SN_ST_TYPE;
                }
            } else if (parser->multiplier == 1) {
                parser->require = (uint16_t)k << 8;
                parser->multiplier = 2;
            } else if (parser->multiplier == 2) {
                parser->require += k;
                if (parser->require < 0x100) {
                    parser->error = MQTT_ERR_MALFORMED;
                    rc = -1;
                    goto e;
                }
                if (parser->require > 0xffff) {
                    parser->error = MQTT_ERR_MALFORMED;
                    rc = -1;
                    goto e;
                }
                parser->require -= 3;
                if (parser->require < 1) {
                    parser->error = MQTT_ERR_MALFORMED;
                    rc = -1;
                    goto e;
                }
                parser->state = MQTT_SN_ST_TYPE;
                parser->multiplier = 0;
            }
            b->i++;
            break;
        case MQTT_SN_ST_TYPE:
            parser->pkt.type = (mqtt_sn_packet_type_t)k;
            if (!MQTT_SN_IS_PACKET_TYPE(parser->pkt.type)) {
                parser->error = MQTT_ERR_MALFORMED;
                rc = -1;
                goto e;
            }
            parser->require -= 1;
            if (parser->require == 0) {
                parser->state = MQTT_SN_ST_LENGTH;
                parser->multiplier = 0;
                rc = __sn_process(parser);
                b->i++;
                goto e;
            }
            parser->pkt.b.s = (char *)MQTT_MALLOC(parser->require);
            if (!parser->pkt.b.s) {
                parser->error = MQTT_ERR_NOMEM;
                rc = -1;
                goto e;
            }
            parser->pkt.b.n = parser->require;
            parser->pkt.b.i = 0;
            parser->state = MQTT_SN_ST_REMAIN;
            b->i++;
            break;
        case MQTT_SN_ST_REMAIN:
            if ((size_t)(b->n - b->i) >= parser->require) {
                memcpy(parser->pkt.b.s + parser->pkt.b.i, b->s + b->i, parser->require);
                parser->pkt.b.i += parser->require;
                parser->state = MQTT_SN_ST_LENGTH;
                parser->multiplier = 0;
                rc = __sn_process(parser);
                b->i += parser->require;
                goto e;
            } else {
                memcpy(parser->pkt.b.s + parser->pkt.b.i, b->s + b->i, b->n - b->i);
                parser->pkt.b.i += b->n - b->i;
                parser->require -= b->n - b->i;
                b->i = b->n;
            }
            break;
        }
    }
e:
    if (rc == 1) {
        if (pkt) {
            *pkt = parser->pkt;
            memset(&parser->pkt, 0, sizeof parser->pkt);
        } else {
            /* nobody takes the packet, release it instead of leaking. */
            mqtt_sn_packet_cleanup(&parser->pkt);
        }
    } else if (rc == -1) {
        if (parser->error == MQTT_OK)
            parser->error = MQTT_ERR_PROTOCOL;
        /* reset the parser so it can keep consuming subsequent data. */
        mqtt_sn_packet_cleanup(&parser->pkt);
        parser->state = MQTT_SN_ST_LENGTH;
        parser->require = 0;
        parser->multiplier = 0;
    }
    return rc;
}

static inline uint16_t
mqtt_sn_vbi_length(uint16_t length) {
    return length > 0xfe ? length + 3 : length + 1;
}

static int
mqtt_sn_write_length(mqtt_str_t *b, uint16_t length) {
    if (length > 0xff) {
        if (mqtt_str_write_u8(b, 0x01))
            return -1;
        return mqtt_str_write_u16(b, length);
    }
    return mqtt_str_write_u8(b, (uint8_t)length);
}

/* total wire length for a message whose payload after MsgType is n bytes. */
static uint16_t
__sn_total_length(uint16_t n) {
    uint16_t total = n + 2;
    if (total > 0xff)
        total += 2;
    return total;
}

static int
__sn_serialize_advertise(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (__serialize_prepare(b, 5, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 5) ||
        mqtt_str_write_u8(b, MQTT_SN_ADVERTISE) ||
        mqtt_str_write_u8(b, pkt->v.advertise.gwid) ||
        mqtt_str_write_u16(b, pkt->v.advertise.duration))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_searchgw(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (__serialize_prepare(b, 3, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 3) ||
        mqtt_str_write_u8(b, MQTT_SN_SEARCHGW) ||
        mqtt_str_write_u8(b, pkt->v.searchgw.radius))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_gwinfo(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;

    if (pkt->v.gwinfo.gwadd.n > 252)
        return -1;
    total = 3 + (uint16_t)pkt->v.gwinfo.gwadd.n;
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_str_write_u8(b, (uint8_t)total) ||
        mqtt_str_write_u8(b, MQTT_SN_GWINFO) ||
        mqtt_str_write_u8(b, pkt->v.gwinfo.gwid) ||
        mqtt_str_concat(b, &pkt->v.gwinfo.gwadd))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_connect(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;

    if (pkt->v.connect.client_id.n > 23)
        return -1;
    if (pkt->v.connect.flags.flag & ~(MQTT_SNF_CLEAN_SESSION | MQTT_SNF_WILL))
        return -1;
    total = 6 + (uint16_t)pkt->v.connect.client_id.n;
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_str_write_u8(b, (uint8_t)total) ||
        mqtt_str_write_u8(b, MQTT_SN_CONNECT) ||
        mqtt_str_write_u8(b, pkt->v.connect.flags.flag) ||
        mqtt_str_write_u8(b, pkt->v.connect.protocol_id) ||
        mqtt_str_write_u16(b, pkt->v.connect.duration) ||
        mqtt_str_concat(b, &pkt->v.connect.client_id))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_connack(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (!MQTT_SN_IS_RC(pkt->v.connack.return_code))
        return -1;
    if (__serialize_prepare(b, 3, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 3) ||
        mqtt_str_write_u8(b, MQTT_SN_CONNACK) ||
        mqtt_str_write_u8(b, (uint8_t)pkt->v.connack.return_code))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_willtopicreq(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    (void)pkt;
    if (__serialize_prepare(b, 2, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 2) ||
        mqtt_str_write_u8(b, MQTT_SN_WILLTOPICREQ))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_willtopic(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;
    int has_topic;

    has_topic = !mqtt_str_empty(&pkt->v.willtopic.topic_name);
    if (has_topic) {
        if (pkt->v.willtopic.topic_name.n > 0xFFFC - 3)
            return -1;
        if (mqtt_utf8_validate(&pkt->v.willtopic.topic_name) ||
            mqtt_topic_name_validate(&pkt->v.willtopic.topic_name))
            return -1;
        total = __sn_total_length(1 + (uint16_t)pkt->v.willtopic.topic_name.n);
    } else
        total = 2;
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_sn_write_length(b, total) ||
        mqtt_str_write_u8(b, MQTT_SN_WILLTOPIC))
        goto fail;
    if (has_topic &&
        (mqtt_str_write_u8(b, pkt->v.willtopic.flags.flag) ||
         mqtt_str_concat(b, &pkt->v.willtopic.topic_name)))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_willmsgreq(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    (void)pkt;
    if (__serialize_prepare(b, 2, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 2) ||
        mqtt_str_write_u8(b, MQTT_SN_WILLMSGREQ))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_willmsg(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;

    if (pkt->v.willmsg.message.n > 0xFFFC - 2)
        return -1;
    total = __sn_total_length((uint16_t)pkt->v.willmsg.message.n);
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_sn_write_length(b, total) ||
        mqtt_str_write_u8(b, MQTT_SN_WILLMSG) ||
        mqtt_str_concat(b, &pkt->v.willmsg.message))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_register(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;

    if (pkt->v.regist.topic_name.n > 0xFFFC - 6)
        return -1;
    if (mqtt_utf8_validate(&pkt->v.regist.topic_name) ||
        mqtt_topic_name_validate(&pkt->v.regist.topic_name))
        return -1;
    total = __sn_total_length(4 + (uint16_t)pkt->v.regist.topic_name.n);
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_sn_write_length(b, total) ||
        mqtt_str_write_u8(b, MQTT_SN_REGISTER) ||
        mqtt_str_write_u16(b, pkt->v.regist.topic_id) ||
        mqtt_str_write_u16(b, pkt->v.regist.msg_id) ||
        mqtt_str_concat(b, &pkt->v.regist.topic_name))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_regack(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (!MQTT_SN_IS_RC(pkt->v.regack.return_code))
        return -1;
    if (__serialize_prepare(b, 7, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 7) ||
        mqtt_str_write_u8(b, MQTT_SN_REGACK) ||
        mqtt_str_write_u16(b, pkt->v.regack.topic_id) ||
        mqtt_str_write_u16(b, pkt->v.regack.msg_id) ||
        mqtt_str_write_u8(b, (uint8_t)pkt->v.regack.return_code))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_publish(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;
    uint8_t topic_id_type;

    topic_id_type = MQTT_SNF_TID_TYPE(pkt->v.publish.flags.flag);
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_RESERVED)
        return -1;
    if (!MQTT_IS_QOS(MQTT_SNF_QOS(pkt->v.publish.flags.flag)))
        return -1;
    if (pkt->v.publish.data.n > 0xFFFC - 7)
        return -1;
    total = __sn_total_length(5 + (uint16_t)pkt->v.publish.data.n);
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_sn_write_length(b, total) ||
        mqtt_str_write_u8(b, MQTT_SN_PUBLISH) ||
        mqtt_str_write_u8(b, pkt->v.publish.flags.flag))
        goto fail;
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        if (mqtt_str_write_u8(b, pkt->v.publish.topic.shor[0]) ||
            mqtt_str_write_u8(b, pkt->v.publish.topic.shor[1]))
            goto fail;
    } else if (mqtt_str_write_u16(b, pkt->v.publish.topic.id))
        goto fail;
    if (mqtt_str_write_u16(b, pkt->v.publish.msg_id) ||
        mqtt_str_concat(b, &pkt->v.publish.data))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_puback(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (!MQTT_SN_IS_RC(pkt->v.puback.return_code))
        return -1;
    if (__serialize_prepare(b, 7, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 7) ||
        mqtt_str_write_u8(b, MQTT_SN_PUBACK) ||
        mqtt_str_write_u16(b, pkt->v.puback.topic.id) ||
        mqtt_str_write_u16(b, pkt->v.puback.msg_id) ||
        mqtt_str_write_u8(b, (uint8_t)pkt->v.puback.return_code))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_pubrec(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (__serialize_prepare(b, 4, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 4) ||
        mqtt_str_write_u8(b, MQTT_SN_PUBREC) ||
        mqtt_str_write_u16(b, pkt->v.pubrec.msg_id))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_pubrel(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (__serialize_prepare(b, 4, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 4) ||
        mqtt_str_write_u8(b, MQTT_SN_PUBREL) ||
        mqtt_str_write_u16(b, pkt->v.pubrel.msg_id))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_pubcomp(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (__serialize_prepare(b, 4, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 4) ||
        mqtt_str_write_u8(b, MQTT_SN_PUBCOMP) ||
        mqtt_str_write_u16(b, pkt->v.pubcomp.msg_id))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_subscribe(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;
    uint16_t content;
    uint8_t topic_id_type;

    topic_id_type = MQTT_SNF_TID_TYPE(pkt->v.subscribe.flags.flag);
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_RESERVED)
        return -1;
    content = 3;
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        if (pkt->v.subscribe.topic.name.n > 0xFFFC - 4)
            return -1;
        if (mqtt_utf8_validate(&pkt->v.subscribe.topic.name) ||
            mqtt_topic_filter_validate(&pkt->v.subscribe.topic.name))
            return -1;
        content += (uint16_t)pkt->v.subscribe.topic.name.n;
    } else
        content += 2;
    total = __sn_total_length(content);
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_sn_write_length(b, total) ||
        mqtt_str_write_u8(b, MQTT_SN_SUBSCRIBE) ||
        mqtt_str_write_u8(b, pkt->v.subscribe.flags.flag) ||
        mqtt_str_write_u16(b, pkt->v.subscribe.msg_id))
        goto fail;
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        if (mqtt_str_concat(b, &pkt->v.subscribe.topic.name))
            goto fail;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        if (mqtt_str_write_u8(b, pkt->v.subscribe.topic.shor[0]) ||
            mqtt_str_write_u8(b, pkt->v.subscribe.topic.shor[1]))
            goto fail;
    } else if (mqtt_str_write_u16(b, pkt->v.subscribe.topic.id))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_suback(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (!MQTT_SN_IS_RC(pkt->v.suback.return_code))
        return -1;
    if (__serialize_prepare(b, 8, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 8) ||
        mqtt_str_write_u8(b, MQTT_SN_SUBACK) ||
        mqtt_str_write_u8(b, pkt->v.suback.flags.flag) ||
        mqtt_str_write_u16(b, pkt->v.suback.topic_id) ||
        mqtt_str_write_u16(b, pkt->v.suback.msg_id) ||
        mqtt_str_write_u8(b, (uint8_t)pkt->v.suback.return_code))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_unsubscribe(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;
    uint16_t content;
    uint8_t topic_id_type;

    topic_id_type = MQTT_SNF_TID_TYPE(pkt->v.unsubscribe.flags.flag);
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_RESERVED)
        return -1;
    content = 3;
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        if (pkt->v.unsubscribe.topic.name.n > 0xFFFC - 4)
            return -1;
        if (mqtt_utf8_validate(&pkt->v.unsubscribe.topic.name) ||
            mqtt_topic_filter_validate(&pkt->v.unsubscribe.topic.name))
            return -1;
        content += (uint16_t)pkt->v.unsubscribe.topic.name.n;
    } else
        content += 2;
    total = __sn_total_length(content);
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_sn_write_length(b, total) ||
        mqtt_str_write_u8(b, MQTT_SN_UNSUBSCRIBE) ||
        mqtt_str_write_u8(b, pkt->v.unsubscribe.flags.flag) ||
        mqtt_str_write_u16(b, pkt->v.unsubscribe.msg_id))
        goto fail;
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        if (mqtt_str_concat(b, &pkt->v.unsubscribe.topic.name))
            goto fail;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        if (mqtt_str_write_u8(b, pkt->v.unsubscribe.topic.shor[0]) ||
            mqtt_str_write_u8(b, pkt->v.unsubscribe.topic.shor[1]))
            goto fail;
    } else if (mqtt_str_write_u16(b, pkt->v.unsubscribe.topic.id))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_unsuback(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (__serialize_prepare(b, 4, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 4) ||
        mqtt_str_write_u8(b, MQTT_SN_UNSUBACK) ||
        mqtt_str_write_u16(b, pkt->v.unsuback.msg_id))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_pingreq(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;

    if (pkt->v.pingreq.client_id.n > 253)
        return -1;
    total = 2 + (uint16_t)pkt->v.pingreq.client_id.n;
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_str_write_u8(b, (uint8_t)total) ||
        mqtt_str_write_u8(b, MQTT_SN_PINGREQ))
        goto fail;
    if (pkt->v.pingreq.client_id.n > 0 && mqtt_str_concat(b, &pkt->v.pingreq.client_id))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_pingresp(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    (void)pkt;
    if (__serialize_prepare(b, 2, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 2) ||
        mqtt_str_write_u8(b, MQTT_SN_PINGRESP))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_disconnect(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;

    total = pkt->v.disconnect.duration > 0 ? 4 : 2;
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_str_write_u8(b, (uint8_t)total) ||
        mqtt_str_write_u8(b, MQTT_SN_DISCONNECT))
        goto fail;
    if (pkt->v.disconnect.duration > 0 && mqtt_str_write_u16(b, pkt->v.disconnect.duration))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_willtopicupd(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;
    int has_topic;

    has_topic = !mqtt_str_empty(&pkt->v.willtopicupd.topic_name);
    if (has_topic) {
        if (pkt->v.willtopicupd.topic_name.n > 0xFFFC - 3)
            return -1;
        if (mqtt_utf8_validate(&pkt->v.willtopicupd.topic_name) ||
            mqtt_topic_name_validate(&pkt->v.willtopicupd.topic_name))
            return -1;
        total = __sn_total_length(1 + (uint16_t)pkt->v.willtopicupd.topic_name.n);
    } else
        total = 2;
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_sn_write_length(b, total) ||
        mqtt_str_write_u8(b, MQTT_SN_WILLTOPICUPD))
        goto fail;
    if (has_topic &&
        (mqtt_str_write_u8(b, pkt->v.willtopicupd.flags.flag) ||
         mqtt_str_concat(b, &pkt->v.willtopicupd.topic_name)))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_willmsgupd(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;

    if (pkt->v.willmsgupd.message.n > 0xFFFC - 2)
        return -1;
    total = __sn_total_length((uint16_t)pkt->v.willmsgupd.message.n);
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_sn_write_length(b, total) ||
        mqtt_str_write_u8(b, MQTT_SN_WILLMSGUPD) ||
        mqtt_str_concat(b, &pkt->v.willmsgupd.message))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_willtopicresp(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (!MQTT_SN_IS_RC(pkt->v.willtopicresp.return_code))
        return -1;
    if (__serialize_prepare(b, 3, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 3) ||
        mqtt_str_write_u8(b, MQTT_SN_WILLTOPICRESP) ||
        mqtt_str_write_u8(b, (uint8_t)pkt->v.willtopicresp.return_code))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_willmsgresp(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;

    if (!MQTT_SN_IS_RC(pkt->v.willmsgresp.return_code))
        return -1;
    if (__serialize_prepare(b, 3, &owned))
        return -1;
    if (mqtt_str_write_u8(b, 3) ||
        mqtt_str_write_u8(b, MQTT_SN_WILLMSGRESP) ||
        mqtt_str_write_u8(b, (uint8_t)pkt->v.willmsgresp.return_code))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

static int
__sn_serialize_encapsulated(const mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int owned;
    uint16_t total;
    uint16_t content;

    if (pkt->v.encapsulated.ctrl & ~MQTT_ENC_RADIUS)
        return -1;
    if (pkt->v.encapsulated.message.n > 0xFFFC - 3)
        return -1;
    content = 1 + (uint16_t)pkt->v.encapsulated.message.n;
    if (pkt->v.encapsulated.ctrl & MQTT_ENC_RADIUS)
        content += 1;
    total = __sn_total_length(content);
    if (__serialize_prepare(b, total, &owned))
        return -1;
    if (mqtt_sn_write_length(b, total) ||
        mqtt_str_write_u8(b, MQTT_SN_ENCAPSULATED) ||
        mqtt_str_write_u8(b, pkt->v.encapsulated.ctrl))
        goto fail;
    if ((pkt->v.encapsulated.ctrl & MQTT_ENC_RADIUS) &&
        mqtt_str_write_u8(b, pkt->v.encapsulated.radius))
        goto fail;
    if (mqtt_str_concat(b, &pkt->v.encapsulated.message))
        goto fail;
    return 0;
fail:
    __serialize_fail(b, owned);
    return -1;
}

int
mqtt_sn_serialize(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    int rc;
    int preset;

    preset = (b->s != 0);
    if (!preset) {
        b->i = 0;
        b->n = 0;
    } else
        b->i = 0;
    switch (pkt->type) {
    case MQTT_SN_ADVERTISE:
        rc = __sn_serialize_advertise(pkt, b);
        break;
    case MQTT_SN_SEARCHGW:
        rc = __sn_serialize_searchgw(pkt, b);
        break;
    case MQTT_SN_GWINFO:
        rc = __sn_serialize_gwinfo(pkt, b);
        break;
    case MQTT_SN_CONNECT:
        rc = __sn_serialize_connect(pkt, b);
        break;
    case MQTT_SN_CONNACK:
        rc = __sn_serialize_connack(pkt, b);
        break;
    case MQTT_SN_WILLTOPICREQ:
        rc = __sn_serialize_willtopicreq(pkt, b);
        break;
    case MQTT_SN_WILLTOPIC:
        rc = __sn_serialize_willtopic(pkt, b);
        break;
    case MQTT_SN_WILLMSGREQ:
        rc = __sn_serialize_willmsgreq(pkt, b);
        break;
    case MQTT_SN_WILLMSG:
        rc = __sn_serialize_willmsg(pkt, b);
        break;
    case MQTT_SN_REGISTER:
        rc = __sn_serialize_register(pkt, b);
        break;
    case MQTT_SN_REGACK:
        rc = __sn_serialize_regack(pkt, b);
        break;
    case MQTT_SN_PUBLISH:
        rc = __sn_serialize_publish(pkt, b);
        break;
    case MQTT_SN_PUBACK:
        rc = __sn_serialize_puback(pkt, b);
        break;
    case MQTT_SN_PUBREC:
        rc = __sn_serialize_pubrec(pkt, b);
        break;
    case MQTT_SN_PUBREL:
        rc = __sn_serialize_pubrel(pkt, b);
        break;
    case MQTT_SN_PUBCOMP:
        rc = __sn_serialize_pubcomp(pkt, b);
        break;
    case MQTT_SN_SUBSCRIBE:
        rc = __sn_serialize_subscribe(pkt, b);
        break;
    case MQTT_SN_SUBACK:
        rc = __sn_serialize_suback(pkt, b);
        break;
    case MQTT_SN_UNSUBSCRIBE:
        rc = __sn_serialize_unsubscribe(pkt, b);
        break;
    case MQTT_SN_UNSUBACK:
        rc = __sn_serialize_unsuback(pkt, b);
        break;
    case MQTT_SN_PINGREQ:
        rc = __sn_serialize_pingreq(pkt, b);
        break;
    case MQTT_SN_PINGRESP:
        rc = __sn_serialize_pingresp(pkt, b);
        break;
    case MQTT_SN_DISCONNECT:
        rc = __sn_serialize_disconnect(pkt, b);
        break;
    case MQTT_SN_WILLTOPICUPD:
        rc = __sn_serialize_willtopicupd(pkt, b);
        break;
    case MQTT_SN_WILLMSGUPD:
        rc = __sn_serialize_willmsgupd(pkt, b);
        break;
    case MQTT_SN_WILLTOPICRESP:
        rc = __sn_serialize_willtopicresp(pkt, b);
        break;
    case MQTT_SN_WILLMSGRESP:
        rc = __sn_serialize_willmsgresp(pkt, b);
        break;
    case MQTT_SN_ENCAPSULATED:
        rc = __sn_serialize_encapsulated(pkt, b);
        break;
    default:
        rc = -1;
        break;
    }
    if (rc == 0 && preset)
        b->n = b->i;
    return rc;
}

#ifdef __cplusplus
}
#endif

#endif /* MQTT_IMPL */