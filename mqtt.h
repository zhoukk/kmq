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

static inline bool
mqtt_is_valid_version(mqtt_version_t version) {
    switch (version) {
        case MQTT_VERSION_3:
        case MQTT_VERSION_4:
        case MQTT_VERSION_5:
            return true;
        default:
            return false;
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
    }
    return "";
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
    }
    return "";
}

/* mqtt-sn protocol version */
#define MQTT_SN_PROTOCOL_VERSION 0x01

/* mqtt qos */
typedef enum {
    MQTT_QOS_0 = 0x00,
    MQTT_QOS_1 = 0x01,
    MQTT_QOS_2 = 0x02
} mqtt_qos_t;

#define MQTT_IS_QOS(q) (q >= MQTT_QOS_0 && q <= MQTT_QOS_2)

/* mqtt-sn qos */
typedef enum {
    MQTT_SN_QOS_0 = 0x00,
    MQTT_SN_QOS_1 = 0x01,
    MQTT_SN_QOS_2 = 0x02,
    MQTT_SN_QOS_3 = 0x03
} mqtt_sn_qos_t;

#define MQTT_SN_IS_QOS(q) (q >= MQTT_SN_QOS_0 && q <= MQTT_SN_QOS_3)

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

#define MQTT_IS_PACKET_TYPE(t) (t >= MQTT_CONNECT && t <= MQTT_AUTH)

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
    }
    return "";
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

#define MQTT_SN_IS_PACKET_TYPE(t) (t >= MQTT_SN_ADVERTISE && t <= MQTT_SN_WILLMSGRESP)

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

/* mqtt connect return code for mattv3.1 and mqttv3.1.1 */
typedef enum {
    MQTT_CRC_ACCEPTED                        = 0x00,
    MQTT_CRC_REFUSED_PROTOCOL_VERSION        = 0x01,
    MQTT_CRC_REFUSED_IDENTIFIER_REJECTED     = 0x02,
    MQTT_CRC_REFUSED_SERVER_UNAVAILABLE      = 0x03,
    MQTT_CRC_REFUSED_BAD_USERNAME_PASSWORD   = 0x04,
    MQTT_CRC_REFUSED_NOT_AUTHORIZED          = 0x05
} mqtt_crc_t;

#define MQTT_IS_CRC(c) (c >= MQTT_CRC_ACCEPTED && c <= MQTT_CRC_REFUSED_NOT_AUTHORIZED)

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
    }
    return "";
}

/* mqtt subscribe return code for mattv3.1.1 */
typedef enum {
    MQTT_SRC_QOS_0      = 0x00,
    MQTT_SRC_QOS_1      = 0x01,
    MQTT_SRC_QOS_2      = 0x02,
    MQTT_SRC_QOS_F      = 0x80
} mqtt_src_t;

#define MQTT_IS_SRC(c) ((c >= MQTT_SRC_QOS_0 && c <= MQTT_SRC_QOS_2) || c == MQTT_SRC_QOS_F)

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

#define MQTT_IS_RC(rc) (rc >= MQTT_RC_SUCCESS && rc <= MQTT_RC_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED)

static struct {
    mqtt_rc_t rc;
    const char *name;
    mqtt_packet_type_t types[MQTT_AUTH];
} MQTT_RC_DEFS[] = {
    {
        MQTT_RC_SUCCESS,
        "Success",
        { MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_PUBREL, MQTT_PUBCOMP, MQTT_UNSUBACK, MQTT_AUTH }
    },
    {
        MQTT_RC_NORMAL_DISCONNECTION,
        "Normal disconnection",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_GRANTED_QOS_0,
        "Granted QoS 0",
        { MQTT_SUBACK }
    },
    {
        MQTT_RC_GRANTED_QOS_1,
        "Granted QoS 1",
        { MQTT_SUBACK }
    },
    {
        MQTT_RC_GRANTED_QOS_2,
        "Granted QoS 2",
        { MQTT_SUBACK }
    },
    {
        MQTT_RC_DISCONNECT_WITH_WILL_MESSAGE,
        "Disconnect with Will Message",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_NO_MATCHING_SUBSCRIBERS,
        "No matching subscribers",
        { MQTT_PUBACK, MQTT_PUBREC }
    },
    {
        MQTT_RC_NO_SUBSCRIPTION_EXISTED,
        "No subscription existed",
        { MQTT_UNSUBACK }
    },
    {
        MQTT_RC_CONTINUE_AUTHENTICATION,
        "Continue authentication",
        { MQTT_AUTH }
    },
    {
        MQTT_RC_RE_AUTHENTICATE,
        "Re-authenticate",
        { MQTT_AUTH }
    },
    {
        MQTT_RC_UNSPECIFIED_ERROR,
        "Unspecified error",
        { MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_MALFORMED_PACKET,
        "Malformed Packet",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_PROTOCOL_ERROR,
        "Protocol Error",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_IMPLEMENTATION_SPECIFIC_ERROR,
        "Implementation specific error",
        { MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION,
        "Unsupported Protocol Version",
        { MQTT_CONNACK }
    },
    {
        MQTT_RC_CLIENT_IDENTIFIER_NOT_VALID,
        "Client Identifier not valid",
        { MQTT_CONNACK }
    },
    {
        MQTT_RC_BAD_USERNAME_OR_PASSWORD,
        "Bad User Name or Password",
        { MQTT_CONNACK }
    },
    {
        MQTT_RC_NOT_AUTHORIZED,
        "Not authorized",
        { MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_SERVER_UNAVAILABLE,
        "Server unavailable",
        { MQTT_CONNACK }
    },
    {
        MQTT_RC_SERVER_BUSY,
        "Server busy",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_BANNED,
        "Banned",
        { MQTT_CONNACK }
    },
    {
        MQTT_RC_SERVER_SHUTTING_DOWN,
        "Server shutting down",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_BAD_AUTHENTICATION_METHOD,
        "Bad authentication method",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_KEEP_ALIVE_TIMEOUT,
        "Keep Alive timeout",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_SESSION_TAKEN_OVER,
        "Session taken over",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_TOPIC_FILTER_INVALID,
        "Topic Filter invalid",
        { MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_TOPIC_NAME_INVALID,
        "Topic Name invalid",
        { MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_PACKET_IDENTIFIER_IN_USE,
        "Packet Identifier in use",
        { MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_UNSUBACK }
    },
    {
        MQTT_RC_PACKET_IDENTIFIER_NOT_FOUND,
        "Packet Identifier not found",
        { MQTT_PUBREL, MQTT_PUBCOMP }
    },
    {
        MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED,
        "Receive Maximum exceeded",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_TOPIC_ALIAS_INVALID,
        "Topic Alias invalid",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_PACKET_TOO_LARGE,
        "Packet too large",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_MESSAGE_RATE_TOO_HIGH,
        "Message rate too high",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_QUOTA_EXCEEDED,
        "Quota exceeded",
        { MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_SUBACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_ADMINISTRATIVE_ACTION,
        "Administrative action",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_PAYLOAD_FORMAT_INVALID,
        "Payload format invalid",
        { MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_RETAIN_NOT_SUPPORTED,
        "Retain not supported",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_QOS_NOT_SUPPORTED,
        "QoS not supported",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_USE_ANOTHER_SERVER,
        "Use another server",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_SERVER_MOVED,
        "Server moved",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_SHARED_SUBSCRIPTIONS_NOT_SUPPORTED,
        "Shared Subscriptions not supported",
        { MQTT_SUBACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_CONNECTION_RATE_EXCEEDED,
        "Connection rate exceeded",
        { MQTT_CONNACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_MAXIMUM_CONNECT_TIME,
        "Maximum connect time",
        { MQTT_DISCONNECT }
    },
    {
        MQTT_RC_SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED,
        "Subscription Identifiers not supported",
        { MQTT_SUBACK, MQTT_DISCONNECT }
    },
    {
        MQTT_RC_WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED,
        "Wildcard Subscriptions not supported",
        { MQTT_SUBACK, MQTT_DISCONNECT }
    },
};

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

/* mqtt-sn return code */
typedef enum {
    MQTT_SN_RC_ACCEPTED                        = 0x00,
    MQTT_SN_RC_REJECTED_CONGESTION             = 0x01,
    MQTT_SN_RC_REJECTED_TOPIC_ID               = 0x02,
    MQTT_SN_RC_REJECTED_NOT_SUPPORTED          = 0x03
} mqtt_sn_rc_t;

#define MQTT_SN_IS_RC(c) (c >= MQTT_SN_RC_ACCEPTED && c <= MQTT_SN_RC_REJECTED_NOT_SUPPORTED)

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
    MQTT_PROPERTY_ASSIGNED_CLIENT_IDENTIFER             = 0x12,
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

#define MQTT_IS_PROPERTY(p)                                                    \
    (p >= MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR &&                            \
    p <= MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE)

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

static struct {
    mqtt_property_code_t code;
    const char *name;
    mqtt_property_type_t type;
    mqtt_packet_type_t types[MQTT_AUTH];
    int will;
} MQTT_PROPERTY_DEFS[] = {
    {
        MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR,
        "Payload Format Indicator",
        MQTT_PROPERTY_TYPE_BYTE,
        { MQTT_PUBLISH }, 1
    },
    {
        MQTT_PROPERTY_MESSAGE_EXPIRY_INTERVAL,
        "Message Expiry Interval",
        MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER,
        { MQTT_PUBLISH }, 1
    },
    {
        MQTT_PROPERTY_CONTENT_TYPE,
        "Content Type",
        MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING,
        { MQTT_PUBLISH }, 1
    },
    {
        MQTT_PROPERTY_RESPONSE_TOPIC,
        "Response Topic",
        MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING,
        { MQTT_PUBLISH }, 1
    },
    {
        MQTT_PROPERTY_CORRELATION_DATA,
        "Correlation Data",
        MQTT_PROPERTY_TYPE_BINARY_DATA,
        { MQTT_PUBLISH }, 1
    },
    {
        MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIER,
        "Subscription Identifier",
        MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER,
        { MQTT_PUBLISH, MQTT_SUBSCRIBE }, 0
    },
    {
        MQTT_PROPERTY_SESSION_EXPIRY_INTERVAL,
        "Session Expiry Interval",
        MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER,
        { MQTT_CONNECT, MQTT_CONNACK, MQTT_DISCONNECT }, 0
    },
    {
        MQTT_PROPERTY_ASSIGNED_CLIENT_IDENTIFER,
        "Assigned Client Identifier",
        MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING,
        { MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_SERVER_KEEP_ALIVE,
        "Server Keep Alive",
        MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER,
        { MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_AUTHENTICATION_METHOD,
        "Authentication Method",
        MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING,
        { MQTT_CONNECT, MQTT_CONNACK, MQTT_AUTH }, 0
    },
    {
        MQTT_PROPERTY_AUTHENTICATION_DATA,
        "Authentication Data",
        MQTT_PROPERTY_TYPE_BINARY_DATA,
        { MQTT_CONNECT, MQTT_CONNACK, MQTT_AUTH }, 0
    },
    {
        MQTT_PROPERTY_REQUEST_PROBLEM_INFORMATION,
        "Request Problem Information",
        MQTT_PROPERTY_TYPE_BYTE,
        { MQTT_CONNECT }, 0
    },
    {
        MQTT_PROPERTY_WILL_DELAY_INTERVAL,
        "Will Delay Interval",
        MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER,
        { MQTT_RESERVED }, 1
    },
    {
        MQTT_PROPERTY_REQUEST_RESPONSE_INFORMATION,
        "Request Response Information",
        MQTT_PROPERTY_TYPE_BYTE,
        { MQTT_CONNECT }, 0
    },
    {
        MQTT_PROPERTY_RESPONSE_INFORMATION,
        "Response Information",
        MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING,
        { MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_SERVER_REFERENCE,
        "Server Reference",
        MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING,
        { MQTT_CONNACK, MQTT_DISCONNECT }, 0
    },
    {
        MQTT_PROPERTY_REASON_STRING,
        "Reason String",
        MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING,
        { MQTT_CONNACK, MQTT_PUBACK, MQTT_PUBREC, MQTT_PUBREL, MQTT_PUBCOMP,
        MQTT_SUBACK, MQTT_UNSUBACK, MQTT_DISCONNECT, MQTT_AUTH }, 0
    },
    {
        MQTT_PROPERTY_RECEIVE_MAXIMUM,
        "Receive Maximum",
        MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER,
        { MQTT_CONNECT, MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_TOPIC_ALIAS_MAXIMUM,
        "Topic Alias Maximum",
        MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER,
        { MQTT_CONNECT, MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_TOPIC_ALIAS,
        "Topic Alias",
        MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER,
        { MQTT_PUBLISH }, 0
    },
    {
        MQTT_PROPERTY_MAXIMUM_QOS,
        "Maximum QoS",
        MQTT_PROPERTY_TYPE_BYTE,
        { MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_RETAIN_AVAILABLE,
        "Retain Available",
        MQTT_PROPERTY_TYPE_BYTE,
        { MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_USER_PROPERTY,
        "User Property",
        MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR,
        { MQTT_CONNECT, MQTT_CONNACK, MQTT_PUBLISH, MQTT_PUBACK, MQTT_PUBREC, MQTT_PUBREL,
        MQTT_PUBCOMP, MQTT_SUBSCRIBE, MQTT_SUBACK, MQTT_UNSUBSCRIBE, MQTT_UNSUBACK,
        MQTT_DISCONNECT, MQTT_AUTH }, 1
    },
    {
        MQTT_PROPERTY_MAXIMUM_PACKET_SIZE,
        "Maximum Packet Size",
        MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER,
        { MQTT_CONNECT, MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_WILDCARD_SUBSCRIPTION_AVAILABLE,
        "Wildcard Subscription Available",
        MQTT_PROPERTY_TYPE_BYTE,
        { MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_SUBSCRIPTION_IDENTIFIERS_AVAILABLE,
        "Subscription Identifier Available",
        MQTT_PROPERTY_TYPE_BYTE,
        { MQTT_CONNACK }, 0
    },
    {
        MQTT_PROPERTY_SHARED_SUBSCRIPTION_AVAILABLE,
        "Shared Subscription Available",
        MQTT_PROPERTY_TYPE_BYTE,
        { MQTT_CONNACK }, 0
    },
};

static inline mqtt_property_type_t
mqtt_property_type(mqtt_property_code_t code) {
    int i, n;

    n = sizeof(MQTT_PROPERTY_DEFS) / sizeof(MQTT_PROPERTY_DEFS[0]);
    for (i = 0; i < n; i++) {
        if (MQTT_PROPERTY_DEFS[i].code == code) {
            return MQTT_PROPERTY_DEFS[i].type;
        }
    }
    return MQTT_PROPERTY_TYPE_BYTE;
}

typedef enum {
    MQTT_SN_TOPIC_ID_TYPE_NORMAL = 0b00,
    MQTT_SN_TOPIC_ID_TYPE_PREDEFINED = 0b01,
    MQTT_SN_TOPIC_ID_TYPE_SHORT = 0b10
} mqtt_sn_topic_id_type_t;

#define MQTT_P_PINGREQ            {0xc0, 0x00}
#define MQTT_P_PINGRESP           {0xd0, 0x00}
#define MQTT_P_DISCONNECT         {0xe0, 0x00}
#define MQTT_P_PUBACK(id)         {0x40, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff)}
#define MQTT_P_PUBREC(id)         {0x50, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff)}
#define MQTT_P_PUBREL(id)         {0x62, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff)}
#define MQTT_P_PUBREL_RC(id, rc)  {0x62, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff), ((rc)&0xff), 0x00}
#define MQTT_P_PUBCOMP(id)        {0x70, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff)}
#define MQTT_P_PUBCOMP_RC(id, rc) {0x70, 0x02, (((id)&0xff00)>>8), ((id)&0x00ff), ((rc)&0xff), 0x00}
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

#define MQTT_STR_INITIALIZER \
    { 0, 0 }

#define MQTT_STR_PRINT(str) (int)(str).n, (str).s

typedef struct {
    char *s;
    size_t n;
} mqtt_str_t;

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

#define MQTT_PROPERTIES_INITIALIZER \
    { 0, 0 }

typedef struct {
    mqtt_property_t *head;
    size_t length;
} mqtt_properties_t;

typedef union {
    struct {
        uint8_t retain : 1;
        uint8_t qos : 2;
        uint8_t dup : 1;
        uint8_t type : 4;
    } bits;
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

typedef struct {
    mqtt_str_t protocol_name;
    mqtt_version_t protocol_version;
    union {
        struct {
            uint8_t : 1;
            uint8_t clean_session : 1;
            uint8_t will_flag : 1;
            uint8_t will_qos : 2;
            uint8_t will_retain : 1;
            uint8_t password_flag : 1;
            uint8_t username_flag : 1;
        } bits;
        uint8_t flags;
    } connect_flags;
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

typedef union {
    struct {
        uint8_t session_present : 1;
        uint8_t : 7;
    } bits;
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

#define MQTT_SUBSCRIBE_OPTIONS_INITIALIZER \
    { .flags = 0 }

typedef union {
    struct {
        uint8_t qos : 2;
        uint8_t nl : 1;
        uint8_t rap : 1;
        uint8_t retain_handling : 2;
        uint8_t : 2;
    } bits;
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

#define MQTT_SUBACK_GRANTED_INITIALIZER \
    { .flags = 0 }

typedef union {
    struct {
        uint8_t qos : 2;
        uint8_t : 6;
    } bits;
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

typedef enum {
    MQTT_ST_FIXED,
    MQTT_ST_LENGTH,
    MQTT_ST_REMAIN
} mqtt_parser_state_t;

typedef struct {
    mqtt_version_t version;
    mqtt_parser_state_t state;
    size_t require;
    int multiplier;
    mqtt_packet_t pkt;
} mqtt_parser_t;

typedef struct {
    mqtt_parser_t parser;
    void *io;
    ssize_t (*read)(void *io, void *, size_t);
} mqtt_reader_t;

typedef union {
    uint8_t flag;
    struct {
        uint8_t topic_id_type : 2;
        uint8_t clean_session : 1;
        uint8_t will : 1;
        uint8_t retain : 1;
        uint8_t qos : 2;
        uint8_t dup : 1;
    } bits;
} mqtt_sn_flags_t;

#define MQTT_SN_TOPIC_INITIALIZER \
    { 0, .id = 0 }

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

typedef struct {
    union {
        struct {
            uint8_t radius : 1;
            uint8_t : 7;
        } bits;
        uint8_t ctrl;
    };
    mqtt_str_t wireless_node;
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

typedef enum {
    MQTT_SN_ST_LENGTH,
    MQTT_SN_ST_TYPE,
    MQTT_SN_ST_REMAIN
} mqtt_sn_parser_state_t;

typedef struct {
    mqtt_sn_parser_state_t state;
    size_t require;
    int multiplier;
    mqtt_sn_packet_t pkt;
} mqtt_sn_parser_t;

typedef struct {
    mqtt_sn_parser_t parser;
    void *io;
    ssize_t (*read)(void *io, void *, size_t);
} mqtt_sn_reader_t;

static inline void
mqtt_str_init(mqtt_str_t *b, char *s, size_t n) {
    b->s = s;
    b->n = n;
}

static inline void
mqtt_str_dup(mqtt_str_t *b, const char *s) {
    if (s && strlen(s) > 0) {
        b->s = strdup(s);
        b->n = strlen(s);
    }
}

static inline void
mqtt_str_dup_n(mqtt_str_t *b, const char *s, size_t n) {
    if (s && n) {
        b->n = n;
        b->s = (char *)malloc(n);
        memcpy(b->s, s, n);
    }
}

static inline void
mqtt_str_from(mqtt_str_t *b, const char *s) {
    if (s && strlen(s) > 0) {
        b->s = (char *)s;
        b->n = strlen(s);
    }
}

static inline int
mqtt_str_strcmp(mqtt_str_t *b, const char *s) {
    return strncmp(b->s, s, b->n);
}

static inline int
mqtt_str_equal(mqtt_str_t *b, mqtt_str_t *s) {
    return (b->n == s->n && !strncmp(b->s, s->s, b->n));
}

static inline void
mqtt_str_copy(mqtt_str_t *b, mqtt_str_t *s) {
    if (s->s && s->n > 0) {
        b->s = (char *)malloc(s->n);
        memcpy(b->s, s->s, s->n);
        b->n = s->n;
    }
}

static inline void
mqtt_str_concat(mqtt_str_t *b, const mqtt_str_t *s) {
    if (s->s && s->n > 0) {
        memcpy(b->s + b->n, s->s, s->n);
        b->n += s->n;
    }
}

static inline void
mqtt_str_set(mqtt_str_t *b, const mqtt_str_t *s) {
    b->s = s->s;
    b->n = s->n;
}

static inline int
mqtt_str_empty(const mqtt_str_t *b) {
    return (!b->s || !b->n);
}

static inline void
mqtt_str_free(mqtt_str_t *b) {
    if (b->s) {
        free(b->s);
        b->s = 0;
        b->n = 0;
    }
}

static inline void
mqtt_str_dump(const mqtt_str_t *b, void *ud, void (*print)(void *, const char *)) {
    size_t line, lines;

    lines = b->n / 0x10;
    for (line = 0; line <= lines; line++) {
        size_t i, n, idx;
        uint8_t *p;
        char buf[0x100] = {0};

        n = line == lines ? b->n % 0x10 : 0x10;
        if (n == 0)
            break;
        p = ((uint8_t *)b->s + line * 0x10);
        idx = sprintf(buf, "%08zx: ", line * 0x10);
        for (i = 0; i < 0x10; i++) {
            if (i == 0x08)
                idx += sprintf(buf + idx, " ");
            if (i >= n)
                idx += sprintf(buf + idx, "  ");
            else
                idx += sprintf(buf + idx, "%02x", p[i]);
            if (i % 0x02 != 0)
                idx += sprintf(buf + idx, " ");
        }
        idx += sprintf(buf + idx, "  ");
        for (i = 0; i < 0x10; i++) {
            if (i >= n) {
                idx += sprintf(buf + idx, " ");
            } else {
                uint8_t c = p[i];
                if (c >= 0x20 && c <= 0x7f)
                    idx += sprintf(buf + idx, "%c", c);
                else
                    idx += sprintf(buf + idx, ".");
            }
        }
        idx += sprintf(buf + idx, "\n");
        if (line % 0x10 == 0x0f)
            idx += sprintf(buf + idx, "\n");

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

static inline size_t
mqtt_str_read_utf(mqtt_str_t *b, mqtt_str_t *r) {
    uint8_t *s = (uint8_t *)b->s;
    size_t n = ((*s << 8) + *(s + 1));
    if (n > 0 && b->n >= n) {
        r->n = n;
        r->s = b->s + 2;
        b->s += r->n + 2;
        b->n -= r->n + 2;
        return 2 + n;
    }
    return 0;
}

static inline uint8_t
mqtt_str_read_u8(mqtt_str_t *b) {
    uint8_t u8;
    uint8_t *s = (uint8_t *)b->s;
    u8 = *s;
    b->s += 1;
    b->n -= 1;
    return u8;
}

static inline uint16_t
mqtt_str_read_u16(mqtt_str_t *b) {
    uint16_t u16;
    uint8_t *s = (uint8_t *)b->s;
    u16 = ((uint16_t)(*s << 8) + (uint16_t)(*(s + 1)));
    b->s += 2;
    b->n -= 2;
    return u16;
}

static inline uint32_t
mqtt_str_read_u32(mqtt_str_t *b) {
    uint32_t u32;
    uint8_t *s = (uint8_t *)b->s;
    u32 = ((uint32_t)(*s << 24) + (uint32_t)(*(s + 1) << 16) + (uint32_t)(*(s + 2) << 8) + (uint32_t)(*(s + 3)));
    b->s += 4;
    b->n -= 4;
    return u32;
}

static inline uint32_t
mqtt_str_read_vbi(mqtt_str_t *b, size_t *len) {
    uint32_t vbi = 0;
    size_t n = 0;
    int multiplier = 1;
    uint8_t c;

    do {
        if (!b->n)
            break;
        c = *((uint8_t *)b->s++);
        b->n--;
        n++;
        vbi += (c & 0x7F) * multiplier;
        multiplier *= 0x80;
    } while ((c & 0x80));
    if (len)
        *len = n;
    return vbi;
}

static inline void
mqtt_str_write_utf(mqtt_str_t *b, const mqtt_str_t *r) {
    b->s[b->n++] = (char)((r->n & 0xff00) >> 8);
    b->s[b->n++] = (char)(r->n & 0x00ff);
    if (r->n > 0) {
        memcpy(&b->s[b->n], r->s, r->n);
        b->n += r->n;
    }
}

static inline void
mqtt_str_write_u8(mqtt_str_t *b, uint8_t r) {
    b->s[b->n++] = (char)r;
}

static inline void
mqtt_str_write_u16(mqtt_str_t *b, uint16_t r) {
    b->s[b->n++] = (char)((r & 0xff00) >> 8);
    b->s[b->n++] = (char)(r & 0x00ff);
}

static inline void
mqtt_str_write_u32(mqtt_str_t *b, uint32_t r) {
    b->s[b->n++] = (char)((r & 0xff000000) >> 24);
    b->s[b->n++] = (char)((r & 0x00ff0000) >> 16);
    b->s[b->n++] = (char)((r & 0x0000ff00) >> 8);
    b->s[b->n++] = (char)(r & 0x000000ff);
}

static inline int
mqtt_str_write_vbi(mqtt_str_t *b, uint32_t vbi) {
    int n = 0;

    do {
        uint8_t c;
        c = vbi % 0x80;
        vbi /= 0x80;
        if (vbi > 0)
            c |= 0x80;
        b->s[b->n++] = (char)c;
        n++;
    } while (vbi > 0);
    return n;
}

static inline int
mqtt_topic_wildcard(mqtt_str_t *topic) {
    size_t i;

    for (i = 0; i < topic->n; i++) {
        char *c;

        c = topic->s + i;
        if (*c == '#' || *c == '+')
            return 1;
    }
    return 0;
}

static inline void
mqtt_sn_topic_set(mqtt_sn_topic_t *dst, mqtt_sn_topic_t *src) {
    if (src->type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_set(&dst->name, &src->name);
    } else if (src->type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        dst->shor[0] = src->shor[0];
        dst->shor[1] = src->shor[1];
    } else {
        dst->id = src->id;
    }
    dst->type = src->type;
}

static inline void
mqtt_sn_topic_copy(mqtt_sn_topic_t *dst, mqtt_sn_topic_t *src) {
    if (src->type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_copy(&dst->name, &src->name);
    } else if (src->type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        dst->shor[0] = src->shor[0];
        dst->shor[1] = src->shor[1];
    } else {
        dst->id = src->id;
    }
    dst->type = src->type;
}

static inline int
mqtt_sn_topic_equal(mqtt_sn_topic_t *dst, mqtt_sn_topic_t *src) {
    if (src->type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        return (dst->name.n == src->name.n &&
                !strncmp(dst->name.s, src->name.s, src->name.n));
    } else if (src->type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        return (dst->shor[0] == src->shor[0] && dst->shor[1] == src->shor[1]);
    } else {
        return dst->id == src->id;
    }
}

static inline void
mqtt_sn_topic_free(mqtt_sn_topic_t *topic) {
    if (topic->type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_free(&topic->name);
    }
}

static inline const char *
mqtt_rc_name(mqtt_rc_t rc) {
    int i, n;

    n = sizeof(MQTT_RC_DEFS) / sizeof(MQTT_RC_DEFS[0]);
    for (i = 0; i < n; i++) {
        if (MQTT_RC_DEFS[i].rc == rc) {
            return MQTT_RC_DEFS[i].name;
        }
    }
    return "";
}

static inline int
mqtt_rc_valid(mqtt_rc_t rc, mqtt_packet_type_t type) {
    int i, n;

    n = sizeof(MQTT_RC_DEFS) / sizeof(MQTT_RC_DEFS[0]);
    for (i = 0; i < n; i++) {
        if (MQTT_RC_DEFS[i].rc == rc) {
            int j;

            for (j = 0; j < MQTT_AUTH; j++) {
                if (MQTT_RC_DEFS[i].types[j] == type)
                    return 1;
            }
        }
    }
    return 0;
}

static inline int
mqtt_fixed_valid(mqtt_fixed_header_t *f, uint8_t retain, uint8_t qos, uint8_t dup) {
    return (f->bits.retain == retain && f->bits.qos == qos && f->bits.dup == dup);
}

static inline int
mqtt_property_valid(mqtt_property_code_t code, mqtt_packet_type_t type, int will) {
    int i, j, n;

    n = sizeof(MQTT_PROPERTY_DEFS) / sizeof(MQTT_PROPERTY_DEFS[0]);
    for (i = 0; i < n; i++) {
        if (MQTT_PROPERTY_DEFS[i].code == code) {
            if (will)
                return MQTT_PROPERTY_DEFS[i].will;
            for (j = 0; j < MQTT_AUTH; j++) {
                if (MQTT_PROPERTY_DEFS[i].types[j] == type)
                    return 1;
            }
        }
    }
    return 0;
}

static inline int
mqtt_properties_valid(const mqtt_properties_t *properties, mqtt_packet_type_t type, int will) {
    mqtt_property_t *property;

    property = properties->head;
    while (property) {
        if (!mqtt_property_valid(property->code, type, will))
            return 0;
        property = property->next;
    }
    return 1;
}

static inline void
mqtt_subscribe_generate(mqtt_packet_t *pkt, int n) {
    pkt->p.subscribe.options = (mqtt_subscribe_options_t *)malloc(n * sizeof(mqtt_subscribe_options_t));
    memset(pkt->p.subscribe.options, 0, n * sizeof(mqtt_subscribe_options_t));
    pkt->p.subscribe.topic_filters = (mqtt_str_t *)malloc(n * sizeof(mqtt_str_t));
    pkt->p.subscribe.n = n;
}

static inline void
mqtt_unsubscribe_generate(mqtt_packet_t *pkt, int n) {
    pkt->p.unsubscribe.topic_filters = (mqtt_str_t *)malloc(n * sizeof(mqtt_str_t));
    pkt->p.unsubscribe.n = n;
}

static inline void
mqtt_suback_generate(mqtt_packet_t *pkt, int n) {
    switch (pkt->ver) {
    case MQTT_VERSION_3:
        pkt->p.suback.v3.granted = (mqtt_suback_granted_t *)malloc(n * sizeof(mqtt_suback_granted_t));
        memset(pkt->p.suback.v3.granted, 0, n * sizeof(mqtt_suback_granted_t));
        break;
    case MQTT_VERSION_4:
        pkt->p.suback.v4.return_codes = (mqtt_src_t *)malloc(n * sizeof(mqtt_src_t));
        break;
    case MQTT_VERSION_5:
        pkt->p.suback.v5.reason_codes = (mqtt_rc_t *)malloc(n * sizeof(mqtt_rc_t));
        break;
    }
    pkt->p.suback.n = n;
}

static inline void
mqtt_unsuback_generate(mqtt_packet_t *pkt, int n) {
    if (pkt->ver == MQTT_VERSION_5) {
        pkt->p.unsuback.v5.reason_codes = (mqtt_rc_t *)malloc(n * sizeof(mqtt_rc_t));
        pkt->p.unsuback.v5.n = n;
    }
}

void mqtt_packet_init(mqtt_packet_t *pkt, mqtt_version_t ver, mqtt_packet_type_t type);

void mqtt_packet_unit(mqtt_packet_t *pkt);

/**
 * serialize a mqtt packet into data/size pair
 */
int mqtt_serialize(mqtt_packet_t *pkt, mqtt_str_t *b);

/**
 * mqtt packet parser funcs.
 */
void mqtt_parser_init(mqtt_parser_t *parser);
void mqtt_parser_version(mqtt_parser_t *parser, mqtt_version_t version);
void mqtt_parser_unit(mqtt_parser_t *parser);

/**
 * parse data/size pair into mqtt packets
 * return:
 *  -1 - mqtt packet parse error
 *   0 - parse all data and finished
 *   1 - a mqtt packet has parsed
 */
int mqtt_parse(mqtt_parser_t *parser, mqtt_str_t *b, mqtt_packet_t *pkt);

/**
 * mqtt packet reader funcs.
 */
void mqtt_reader_init(mqtt_reader_t *reader, void *io, ssize_t (*read)(void *io, void *, size_t));
void mqtt_reader_version(mqtt_reader_t *reader, mqtt_version_t version);
void mqtt_reader_unit(mqtt_reader_t *reader);

/**
 * read a mqtt packet from reader
 * return:
 *  -1 - mqtt packet read error
 *   1 - read a mqtt packet
 */
int mqtt_read(mqtt_reader_t *reader, mqtt_packet_t *pkt);

/**
 * mqtt property functions
 */
void mqtt_properties_add(mqtt_properties_t *properties, mqtt_property_code_t code, const void *value, const char *name);
mqtt_property_t *mqtt_properties_find(mqtt_properties_t *properties, mqtt_property_code_t code);
mqtt_property_t *mqtt_properties_remove(mqtt_properties_t *properties, mqtt_property_code_t code);

void mqtt_sn_packet_init(mqtt_sn_packet_t *pkt, mqtt_sn_packet_type_t type);

void mqtt_sn_packet_unit(mqtt_sn_packet_t *pkt);

/**
 * serialize a mqtt-sn packet into data/size pair
 */
void mqtt_sn_serialize(mqtt_sn_packet_t *pkt, mqtt_str_t *b);

/**
 * mqtt-sn packet parser funcs.
 */
void mqtt_sn_parser_init(mqtt_sn_parser_t *parser);
void mqtt_sn_parser_unit(mqtt_sn_parser_t *parser);

/**
 * parse data/size pair into mqtt-sn packets
 * return:
 *  -1 - mqtt-sn packet parse error
 *   0 - parse all data and finished
 *   1 - a mqtt-sn packet has parsed
 */
int mqtt_sn_parse(mqtt_sn_parser_t *parser, mqtt_str_t *b, mqtt_sn_packet_t *pkt);

/**
 * mqtt-sn packet reader funcs.
 */
void mqtt_sn_reader_init(mqtt_sn_reader_t *reader, void *io, ssize_t (*read)(void *io, void *, size_t));
void mqtt_sn_reader_unit(mqtt_sn_reader_t *reader);

/**
 * read a mqtt-sn packet from reader
 * return:
 *  -1 - mqtt-sn packet read error
 *   1 - read a mqtt-sn packet
 */
int mqtt_sn_read(mqtt_sn_reader_t *reader, mqtt_sn_packet_t *pkt);

#endif /* _MQTT_H_ */

#ifdef MQTT_IMPL

static void
__properties_free(mqtt_properties_t *properties) {
    mqtt_property_t *property;

    property = properties->head;
    while (property) {
        mqtt_property_t *next;
        next = property->next;
        free(property);
        property = next;
    }
}

void
mqtt_packet_init(mqtt_packet_t *pkt, mqtt_version_t ver, mqtt_packet_type_t type) {
    memset(pkt, 0, sizeof *pkt);
    pkt->ver = ver;
    pkt->f.bits.type = type;
    if (type == MQTT_CONNECT) {
        mqtt_str_from(&pkt->v.connect.protocol_name, mqtt_protocol_name(pkt->ver));
        pkt->v.connect.protocol_version = pkt->ver;
    }
}

void
mqtt_packet_unit(mqtt_packet_t *pkt) {
    switch (pkt->f.bits.type) {
    case MQTT_CONNECT:
        __properties_free(&pkt->v.connect.v5.properties);
        __properties_free(&pkt->p.connect.v5.will_properties);
        break;
    case MQTT_CONNACK:
        __properties_free(&pkt->v.connack.v5.properties);
        break;
    case MQTT_SUBSCRIBE:
        if (pkt->p.subscribe.topic_filters)
            free(pkt->p.subscribe.topic_filters);
        if (pkt->p.subscribe.options)
            free(pkt->p.subscribe.options);
        __properties_free(&pkt->v.subscribe.v5.properties);
        break;
    case MQTT_SUBACK:
        if (pkt->p.suback.v3.granted)
            free(pkt->p.suback.v3.granted);
        if (pkt->p.suback.v4.return_codes)
            free(pkt->p.suback.v4.return_codes);
        if (pkt->p.suback.v5.reason_codes)
            free(pkt->p.suback.v5.reason_codes);
        __properties_free(&pkt->v.suback.v5.properties);
        break;
    case MQTT_UNSUBSCRIBE:
        if (pkt->p.unsubscribe.topic_filters)
            free(pkt->p.unsubscribe.topic_filters);
        __properties_free(&pkt->v.unsubscribe.v5.properties);
        break;
    case MQTT_UNSUBACK:
        if (pkt->p.unsuback.v5.reason_codes)
            free(pkt->p.unsuback.v5.reason_codes);
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
    mqtt_str_free(&pkt->b);
}

static size_t
__properties_len(const mqtt_properties_t *properties) {
    if (!properties->length)
        return 1;
    return properties->length + mqtt_vbi_length(properties->length);
}

static ssize_t
__property_parse(mqtt_property_t *property, mqtt_str_t *b) {
    mqtt_property_type_t type;
    size_t n, len;

    if (!b->n)
        return -1;
    property->code = (mqtt_property_code_t)mqtt_str_read_u8(b);

    len = 1;
    type = mqtt_property_type(property->code);
    switch (type) {
    case MQTT_PROPERTY_TYPE_BYTE:
        if (b->n < 1)
            return -1;
        property->b1 = mqtt_str_read_u8(b);
        len += 1;
        break;
    case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
        if (b->n < 2)
            return -1;
        property->b2 = mqtt_str_read_u16(b);
        len += 2;
        break;
    case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
        if (b->n < 4)
            return -1;
        property->b4 = mqtt_str_read_u32(b);
        len += 4;
        break;
    case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        property->bv = mqtt_str_read_vbi(b, &n);
        len += n;
        break;
    case MQTT_PROPERTY_TYPE_BINARY_DATA:
        len += mqtt_str_read_utf(b, &property->data);
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
        len += mqtt_str_read_utf(b, &property->str);
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
        len += mqtt_str_read_utf(b, &property->pair.name);
        len += mqtt_str_read_utf(b, &property->pair.value);
        break;
    }
    return len;
}

static int
__properties_parse(mqtt_properties_t *properties, mqtt_str_t *b) {
    uint32_t length;

    length = mqtt_str_read_vbi(b, 0);
    if ((uint32_t)b->n < length)
        return -1;

    properties->length = length;
    while (length > 0) {
        mqtt_property_t *property;
        ssize_t len;

        property = (mqtt_property_t *)malloc(sizeof *property);
        memset(property, 0, sizeof *property);
        len = __property_parse(property, b);
        if (-1 == len) {
            free(property);
            return -1;
        }
        length -= len;

        property->next = properties->head;
        properties->head = property;
    }
    return 0;
}

static int
__parse_connect(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_connect_t *v;
    mqtt_p_connect_t *p;

    v = &pkt->v.connect;
    p = &pkt->p.connect;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (remaining->n <= 2)
        return -1;
    mqtt_str_read_utf(remaining, &v->protocol_name);
    if (remaining->n < 1)
        return -1;
    v->protocol_version = (mqtt_version_t)mqtt_str_read_u8(remaining);
    pkt->ver = v->protocol_version;
    if (remaining->n < 1)
        return -1;
    v->connect_flags.flags = mqtt_str_read_u8(remaining);
    if (remaining->n < 2)
        return -1;
    v->keep_alive = mqtt_str_read_u16(remaining);
    if (pkt->ver == MQTT_VERSION_5) {
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_CONNECT, 0))
            return -1;
    }

    if (remaining->n < 2)
        return -1;
    mqtt_str_read_utf(remaining, &p->client_id);
    if (v->connect_flags.bits.will_flag) {
        if (pkt->ver == MQTT_VERSION_5) {
            if (__properties_parse(&p->v5.will_properties, remaining))
                return -1;
            if (!mqtt_properties_valid(&p->v5.will_properties, MQTT_RESERVED, 1))
                return -1;
        }
        if (remaining->n <= 2)
            return -1;
        mqtt_str_read_utf(remaining, &p->will_topic);
        if (remaining->n <= 2)
            return -1;
        mqtt_str_read_utf(remaining, &p->will_message);
        if (mqtt_str_empty(&p->will_topic) || mqtt_str_empty(&p->will_message))
            return -1;
        if (!MQTT_IS_QOS(v->connect_flags.bits.will_qos))
            return -1;
    }
    if (v->connect_flags.bits.username_flag) {
        if (remaining->n <= 2)
            return -1;
        mqtt_str_read_utf(remaining, &p->username);
        if (v->connect_flags.bits.password_flag) {
            if (remaining->n < 2)
                return -1;
            mqtt_str_read_utf(remaining, &p->password);
        }
    }

    return 0;
}

static int
__parse_connack(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_connack_t *v;

    v = &pkt->v.connack;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (pkt->ver == MQTT_VERSION_3) {
        if (remaining->n != 2)
            return -1;
        mqtt_str_read_u8(remaining);
        v->v3.return_code = (mqtt_crc_t)mqtt_str_read_u8(remaining);
        if (!MQTT_IS_CRC(v->v3.return_code)) {
            return -1;
        }
    } else if (pkt->ver == MQTT_VERSION_4) {
        if (remaining->n != 2)
            return -1;
        v->v4.acknowledge_flags.flags = mqtt_str_read_u8(remaining);
        v->v4.return_code = (mqtt_crc_t)mqtt_str_read_u8(remaining);
        if (!MQTT_IS_CRC(v->v4.return_code)) {
            return -1;
        }
    } else if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 2)
            return -1;
        v->v5.acknowledge_flags.flags = mqtt_str_read_u8(remaining);
        v->v5.reason_code = (mqtt_rc_t)mqtt_str_read_u8(remaining);
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

    if (!MQTT_IS_QOS(pkt->f.bits.qos))
        return -1;
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (remaining->n <= 2)
            return -1;
    } else if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 4)
            return -1;
    } else {
        return -1;
    }
    mqtt_str_read_utf(remaining, &v->topic_name);
    if (mqtt_str_empty(&v->topic_name))
        return -1;
    if (pkt->f.bits.qos > MQTT_QOS_0) {
        if (remaining->n < 2)
            return -1;
        v->packet_id = mqtt_str_read_u16(remaining);
    }
    if (pkt->ver == MQTT_VERSION_5) {
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBLISH, 0))
            return -1;
    }
    mqtt_str_set(&p->message, remaining);
    remaining->s += p->message.n;
    remaining->n -= p->message.n;

    return 0;
}

static int
__parse_puback(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_puback_t *v;

    v = &pkt->v.puback;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (remaining->n != 2)
            return -1;
    } else if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 2)
            return -1;
    } else {
        return -1;
    }
    v->packet_id = mqtt_str_read_u16(remaining);
    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n > 0) {
            v->v5.reason_code = (mqtt_rc_t)mqtt_str_read_u8(remaining);
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBACK)) {
                return -1;
            }
        } else
            v->v5.reason_code = MQTT_RC_SUCCESS;
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
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
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (remaining->n != 2)
            return -1;
    } else if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 2)
            return -1;
    } else {
        return -1;
    }
    v->packet_id = mqtt_str_read_u16(remaining);
    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n > 0) {
            v->v5.reason_code = (mqtt_rc_t)mqtt_str_read_u8(remaining);
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBREC)) {
                return -1;
            }
        } else
            v->v5.reason_code = MQTT_RC_SUCCESS;
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
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
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (remaining->n != 2)
            return -1;
    } else if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 2)
            return -1;
    } else {
        return -1;
    }
    v->packet_id = mqtt_str_read_u16(remaining);
    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n > 0) {
            v->v5.reason_code = (mqtt_rc_t)mqtt_str_read_u8(remaining);
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBREL)) {
                return -1;
            }
        } else
            v->v5.reason_code = MQTT_RC_SUCCESS;
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
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
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (remaining->n != 2)
            return -1;
    } else if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 2)
            return -1;
    } else {
        return -1;
    }
    v->packet_id = mqtt_str_read_u16(remaining);
    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n > 0) {
            v->v5.reason_code = (mqtt_rc_t)mqtt_str_read_u8(remaining);
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_PUBCOMP)) {
                return -1;
            }
        } else
            v->v5.reason_code = MQTT_RC_SUCCESS;
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
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
    int i;

    v = &pkt->v.subscribe;
    p = &pkt->p.subscribe;

    if (!mqtt_fixed_valid(&pkt->f, 0, MQTT_QOS_1, 0))
        return -1;
    if (remaining->n <= 2)
        return -1;
    v->packet_id = mqtt_str_read_u16(remaining);

    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 1)
            return -1;
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_SUBSCRIBE, 0))
            return -1;
    }

    r = *remaining;
    while (r.n >= 2) {
        mqtt_str_t dummy = MQTT_STR_INITIALIZER;

        mqtt_str_read_utf(&r, &dummy);
        if (mqtt_str_empty(&dummy))
            return -1;
        mqtt_str_read_u8(&r);
        p->n++;
    }
    if (p->topic_filters)
        free(p->topic_filters);
    p->topic_filters = (mqtt_str_t *)malloc(p->n * sizeof(mqtt_str_t));
    if (p->options)
        free(p->options);
    p->options = (mqtt_subscribe_options_t *)malloc(p->n * sizeof(mqtt_subscribe_options_t));
    i = 0;
    while (remaining->n > 0) {
        mqtt_str_read_utf(remaining, &p->topic_filters[i]);
        p->options[i].flags = mqtt_str_read_u8(remaining);
        if (!MQTT_IS_QOS(p->options[i].bits.qos)) {
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
    if (remaining->n <= 2)
        return -1;
    v->packet_id = mqtt_str_read_u16(remaining);

    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 1)
            return -1;
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_SUBACK, 0))
            return -1;
    }

    p->n = remaining->n;

    if (pkt->ver == MQTT_VERSION_3) {
        if (p->v3.granted)
            free(p->v3.granted);
        p->v3.granted = (mqtt_suback_granted_t *)malloc(p->n * sizeof(mqtt_suback_granted_t));
        i = 0;
        while (remaining->n > 0) {
            p->v3.granted[i].flags = mqtt_str_read_u8(remaining);
            if (!MQTT_IS_QOS(p->v3.granted[i].bits.qos)) {
                return -1;
            }
            i++;
        }
    } else if (pkt->ver == MQTT_VERSION_4) {
        if (p->v4.return_codes)
            free(p->v4.return_codes);
        p->v4.return_codes = (mqtt_src_t *)malloc(p->n * sizeof(mqtt_src_t));
        i = 0;
        while (remaining->n > 0) {
            p->v4.return_codes[i] = (mqtt_src_t)mqtt_str_read_u8(remaining);
            if (!MQTT_IS_SRC(p->v4.return_codes[i])) {
                return -1;
            }
            i++;
        }
    } else if (pkt->ver == MQTT_VERSION_5) {
        if (p->v5.reason_codes)
            free(p->v5.reason_codes);
        p->v5.reason_codes = (mqtt_rc_t *)malloc(p->n * sizeof(mqtt_rc_t));
        i = 0;
        while (remaining->n > 0) {
            p->v5.reason_codes[i] = (mqtt_rc_t)mqtt_str_read_u8(remaining);
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
    int i;

    v = &pkt->v.unsubscribe;
    p = &pkt->p.unsubscribe;

    if (!mqtt_fixed_valid(&pkt->f, 0, MQTT_QOS_1, 0))
        return -1;
    if (remaining->n <= 2)
        return -1;
    v->packet_id = mqtt_str_read_u16(remaining);

    if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 1)
            return -1;
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_UNSUBSCRIBE, 0))
            return -1;
    }

    r = *remaining;
    while (r.n >= 2) {
        mqtt_str_t dummy = MQTT_STR_INITIALIZER;
        mqtt_str_read_utf(&r, &dummy);
        if (mqtt_str_empty(&dummy))
            return -1;
        p->n++;
    }
    if (p->topic_filters)
        free(p->topic_filters);
    p->topic_filters = (mqtt_str_t *)malloc(p->n * sizeof(mqtt_str_t));
    i = 0;
    while (remaining->n > 2) {
        mqtt_str_read_utf(remaining, &p->topic_filters[i]);
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
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (remaining->n != 2)
            return -1;
    } else if (pkt->ver == MQTT_VERSION_5) {
        if (remaining->n < 3)
            return -1;
    } else {
        return -1;
    }

    v->packet_id = mqtt_str_read_u16(remaining);

    if (pkt->ver == MQTT_VERSION_5) {
        int i;

        if (remaining->n < 1)
            return -1;
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_UNSUBACK, 0))
            return -1;
        p->v5.n = remaining->n;
        if (p->v5.reason_codes)
            free(p->v5.reason_codes);
        p->v5.reason_codes = (mqtt_rc_t *)malloc(p->v5.n * sizeof(mqtt_rc_t));
        i = 0;
        while (remaining->n > 0) {
            p->v5.reason_codes[i] = (mqtt_rc_t)mqtt_str_read_u8(remaining);
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
    if (remaining->n != 0)
        return -1;

    return 0;
}

static int
__parse_pingresp(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;
    if (remaining->n != 0)
        return -1;

    return 0;
}

static int
__parse_disconnect(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;

    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        if (remaining->n != 0)
            return -1;
    } else if (pkt->ver == MQTT_VERSION_5) {
        mqtt_v_disconnect_t *v;

        v = &pkt->v.disconnect;
        if (remaining->n > 0) {
            v->v5.reason_code = (mqtt_rc_t)mqtt_str_read_u8(remaining);
            if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_DISCONNECT)) {
                return -1;
            }
        } else {
            v->v5.reason_code = MQTT_RC_NORMAL_DISCONNECTION;
        }
        if (__properties_parse(&v->v5.properties, remaining))
            return -1;
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_DISCONNECT, 0))
            return -1;
    }

    return 0;
}

static int
__parse_auth(mqtt_str_t *remaining, mqtt_packet_t *pkt) {
    mqtt_v_auth_t *v;

    if (!mqtt_fixed_valid(&pkt->f, 0, 0, 0))
        return -1;

    if (pkt->ver != MQTT_VERSION_5)
        return -1;

    v = &pkt->v.auth;
    if (remaining->n < 2)
        return -1;
    v->v5.reason_code = (mqtt_rc_t)mqtt_str_read_u8(remaining);
    if (!MQTT_IS_RC(v->v5.reason_code) || !mqtt_rc_valid(v->v5.reason_code, MQTT_AUTH)) {
        return -1;
    }
    if (__properties_parse(&v->v5.properties, remaining))
        return -1;
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
    type = (mqtt_packet_type_t)pkt->f.bits.type;
    mqtt_str_set(&b, &pkt->b);
    switch (type) {
    case MQTT_CONNECT:
        rc = __parse_connect(&b, pkt);
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
    if (rc) {
        return rc;
    }
    if (b.n) {
        return -1;
    }
    return 1;
}

void
mqtt_parser_init(mqtt_parser_t *parser) {
    memset(parser, 0, sizeof *parser);
    parser->state = MQTT_ST_FIXED;
}

void
mqtt_parser_version(mqtt_parser_t *parser, mqtt_version_t version) {
    parser->version = version;
}

void
mqtt_parser_unit(mqtt_parser_t *parser) {
    (void)parser;
}

int
mqtt_parse(mqtt_parser_t *parser, mqtt_str_t *b, mqtt_packet_t *pkt) {
    char *c, *e;
    size_t offset;
    int rc;

    e = b->s + b->n;
    c = b->s;
    rc = 0;
    while (c < e) {
        uint8_t k = (uint8_t)(*c);
        switch (parser->state) {
        case MQTT_ST_FIXED:
            memset(&parser->pkt, 0, sizeof parser->pkt);
            parser->pkt.f.flags = k;
            if (!MQTT_IS_PACKET_TYPE(parser->pkt.f.bits.type)) {
                rc = -1;
                goto e;
            }
            parser->state = MQTT_ST_LENGTH;
            parser->multiplier = 1;
            parser->require = 1;
            c++;
            break;
        case MQTT_ST_LENGTH:
            parser->pkt.b.n += (k & 0x7F) * parser->multiplier;
            if (parser->multiplier > 0x80 * 0x80 * 0x80) {
                rc = -1;
                goto e;
            }
            parser->multiplier *= 0x80;
            if ((k & 0x80) == 0) {
                parser->require = parser->pkt.b.n;
                if (parser->require > 0) {
                    parser->state = MQTT_ST_REMAIN;
                    parser->pkt.b.s = (char *)malloc(parser->pkt.b.n);
                } else {
                    parser->state = MQTT_ST_FIXED;
                    rc = __process(parser);
                    c++;
                    b->n = e - c;
                    b->s = c;
                    goto e;
                }
            }
            c++;
            break;
        case MQTT_ST_REMAIN:
            offset = parser->pkt.b.n - parser->require;
            if ((size_t)(e - c) >= parser->require) {
                memcpy(parser->pkt.b.s + offset, c, parser->require);
                c += parser->require;
                parser->state = MQTT_ST_FIXED;
                rc = __process(parser);
                b->n = e - c;
                b->s = c;
                goto e;
            } else {
                memcpy(parser->pkt.b.s + offset, c, e - c);
                parser->require -= e - c;
                c = e;
            }
            break;
        }
    }

e:
    if (rc == 1) {
        *pkt = parser->pkt;
    }
    return rc;
}

void
mqtt_reader_init(mqtt_reader_t *reader, void *io, ssize_t (*read)(void *io, void *, size_t)) {
    reader->io = io;
    reader->read = read;
    mqtt_parser_init(&reader->parser);
}

void
mqtt_reader_version(mqtt_reader_t *reader, mqtt_version_t version) {
    mqtt_parser_version(&reader->parser, version);
}

void
mqtt_reader_unit(mqtt_reader_t *reader) {
    mqtt_parser_unit(&reader->parser);
}

int
mqtt_read(mqtt_reader_t *reader, mqtt_packet_t *pkt) {
    mqtt_parser_t *parser;
    int rc;

    parser = &reader->parser;
    parser->require = 1;
    parser->state = MQTT_ST_FIXED;
    rc = 0;

    while (1) {
        ssize_t nread;
        uint8_t k;
        char *buff;
        if (parser->state == MQTT_ST_REMAIN) {
            buff = (char *)malloc(parser->require);
        } else {
            buff = (char *)&k;
        }
        nread = reader->read(reader->io, buff, parser->require);
        if ((size_t)nread != parser->require) {
            rc = -1;
            goto e;
        }
        switch (parser->state) {
        case MQTT_ST_FIXED:
            memset(&parser->pkt, 0, sizeof parser->pkt);
            parser->pkt.f.flags = k;
            if (!MQTT_IS_PACKET_TYPE(parser->pkt.f.bits.type)) {
                rc = -1;
                goto e;
            }
            parser->state = MQTT_ST_LENGTH;
            parser->multiplier = 1;
            parser->require = 1;
            break;
        case MQTT_ST_LENGTH:
            parser->pkt.b.n += (k & 0x7F) * parser->multiplier;
            if (parser->multiplier > 0x80 * 0x80 * 0x80) {
                rc = -1;
                goto e;
            }
            if (parser->pkt.b.n >= (1 << 28)) {
                rc = -1;
                goto e;
            }
            parser->multiplier *= 0x80;
            if ((k & 0x80) == 0) {
                parser->require = parser->pkt.b.n;
                if (parser->require > 0) {
                    parser->state = MQTT_ST_REMAIN;
                } else {
                    rc = __process(parser);
                    goto e;
                }
            }
            break;
        case MQTT_ST_REMAIN:
            parser->pkt.b.s = buff;
            rc = __process(parser);
            goto e;
        }
    }

e:
    if (rc == 1) {
        *pkt = parser->pkt;
    }
    return rc;
}

static void
__property_serialize(const mqtt_property_t *property, mqtt_str_t *b) {
    mqtt_property_type_t type;

    mqtt_str_write_u8(b, (uint8_t)property->code);

    type = mqtt_property_type(property->code);
    switch (type) {
    case MQTT_PROPERTY_TYPE_BYTE:
        mqtt_str_write_u8(b, property->b1);
        break;
    case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
        mqtt_str_write_u16(b, property->b2);
        break;
    case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
        mqtt_str_write_u32(b, property->b4);
        break;
    case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        mqtt_str_write_vbi(b, property->bv);
        break;
    case MQTT_PROPERTY_TYPE_BINARY_DATA:
        mqtt_str_write_utf(b, &property->data);
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
        mqtt_str_write_utf(b, &property->str);
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
        mqtt_str_write_utf(b, &property->pair.name);
        mqtt_str_write_utf(b, &property->pair.value);
        break;
    }
}

static void
__properties_serialize(const mqtt_properties_t *properties, mqtt_str_t *b) {
    mqtt_property_t *property;

    mqtt_str_write_vbi(b, properties->length);
    property = properties->head;
    while (property) {
        __property_serialize(property, b);
        property = property->next;
    }
}

static int
__serialize_connect(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    const mqtt_v_connect_t *v;
    const mqtt_p_connect_t *p;

    v = &pkt->v.connect;
    p = &pkt->p.connect;

    if (pkt->ver == MQTT_VERSION_5) {
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_CONNECT, 0))
            return -1;
        if (!mqtt_properties_valid(&p->v5.will_properties, MQTT_RESERVED, 1))
            return -1;
    }

    length = 4;
    length += 2 + v->protocol_name.n;
    length += 2 + p->client_id.n;
    if (v->connect_flags.bits.username_flag)
        length += 2 + p->username.n;
    if (v->connect_flags.bits.password_flag)
        length += 2 + p->password.n;
    if (v->connect_flags.bits.will_flag) {
        length += 2 + p->will_topic.n;
        length += 2 + p->will_message.n;
    }
    if (pkt->ver == MQTT_VERSION_5) {
        length += __properties_len(&v->v5.properties);
        if (v->connect_flags.bits.will_flag)
            length += __properties_len(&p->v5.will_properties);
    }

    b->n = length + 1 + mqtt_vbi_length(length);
    b->s = (char *)malloc(b->n);
    b->n = 0;
    mqtt_str_write_u8(b, 0x10);
    mqtt_str_write_vbi(b, length);
    mqtt_str_write_utf(b, &v->protocol_name);
    mqtt_str_write_u8(b, (uint8_t)v->protocol_version);
    mqtt_str_write_u8(b, v->connect_flags.flags);
    mqtt_str_write_u16(b, v->keep_alive);
    if (pkt->ver == MQTT_VERSION_5)
        __properties_serialize(&v->v5.properties, b);
    mqtt_str_write_utf(b, &p->client_id);
    if (v->connect_flags.bits.will_flag) {
        if (pkt->ver == MQTT_VERSION_5)
            __properties_serialize(&p->v5.will_properties, b);
        mqtt_str_write_utf(b, &p->will_topic);
        mqtt_str_write_utf(b, &p->will_message);
    }
    if (v->connect_flags.bits.username_flag)
        mqtt_str_write_utf(b, &p->username);
    if (v->connect_flags.bits.password_flag)
        mqtt_str_write_utf(b, &p->password);

    return 0;
}

static int
__serialize_connack(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    const mqtt_v_connack_t *v;

    v = &pkt->v.connack;

    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        b->s = (char *)malloc(4);
        b->n = 0;
        mqtt_str_write_u8(b, 0x20);
        mqtt_str_write_u8(b, 0x02);
        if (pkt->ver == MQTT_VERSION_3) {
            mqtt_str_write_u8(b, 0x00);
            mqtt_str_write_u8(b, (uint8_t)v->v3.return_code);
        } else {
            mqtt_str_write_u8(b, v->v4.acknowledge_flags.flags);
            mqtt_str_write_u8(b, (uint8_t)v->v4.return_code);
        }
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;

        if (!mqtt_properties_valid(&v->v5.properties, MQTT_CONNACK, 0))
            return -1;

        length = 2 + __properties_len(&v->v5.properties);
        b->n = length + 1 + mqtt_vbi_length(length);
        b->s = (char *)malloc(b->n);
        b->n = 0;
        mqtt_str_write_u8(b, 0x20);
        mqtt_str_write_vbi(b, length);
        mqtt_str_write_u8(b, v->v5.acknowledge_flags.flags);
        mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code);
        __properties_serialize(&v->v5.properties, b);
    }

    return 0;
}

static int
__serialize_publish(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    const mqtt_v_publish_t *v;
    const mqtt_p_publish_t *p;

    v = &pkt->v.publish;
    p = &pkt->p.publish;

    if (p->message.n >= (1 << 28)) {
        return -1;
    }

    if (pkt->ver == MQTT_VERSION_5) {
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBLISH, 0))
            return -1;
    }

    length = 2 + v->topic_name.n + p->message.n;
    if (pkt->f.bits.qos > MQTT_QOS_0)
        length += 2;
    if (pkt->ver == MQTT_VERSION_5)
        length += __properties_len(&v->v5.properties);
    b->n = length + 1 + mqtt_vbi_length(length);
    b->s = (char *)malloc(b->n);
    b->n = 0;
    mqtt_str_write_u8(b, pkt->f.flags);
    mqtt_str_write_vbi(b, length);
    mqtt_str_write_utf(b, &v->topic_name);
    if (pkt->f.bits.qos > MQTT_QOS_0)
        mqtt_str_write_u16(b, v->packet_id);
    if (pkt->ver == MQTT_VERSION_5)
        __properties_serialize(&v->v5.properties, b);
    mqtt_str_concat(b, &p->message);

    return 0;
}

static int
__serialize_puback(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    const mqtt_v_puback_t *v;

    v = &pkt->v.puback;

    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        b->s = (char *)malloc(4);
        b->n = 0;
        mqtt_str_write_u8(b, 0x40);
        mqtt_str_write_u8(b, 0x02);
        mqtt_str_write_u16(b, v->packet_id);
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;

        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBACK, 0))
            return -1;

        length = 3 + __properties_len(&v->v5.properties);
        b->n = length + 1 + mqtt_vbi_length(length);
        b->s = (char *)malloc(b->n);
        b->n = 0;
        mqtt_str_write_u8(b, 0x40);
        mqtt_str_write_vbi(b, length);
        mqtt_str_write_u16(b, v->packet_id);
        mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code);
        __properties_serialize(&v->v5.properties, b);
    }

    return 0;
}

static int
__serialize_pubrec(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    const mqtt_v_pubrec_t *v;

    v = &pkt->v.pubrec;

    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        b->s = (char *)malloc(4);
        b->n = 0;
        mqtt_str_write_u8(b, 0x50);
        mqtt_str_write_u8(b, 0x02);
        mqtt_str_write_u16(b, v->packet_id);
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;

        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBREC, 0))
            return -1;

        length = 3 + __properties_len(&v->v5.properties);
        b->n = length + 1 + mqtt_vbi_length(length);
        b->s = (char *)malloc(b->n);
        b->n = 0;
        mqtt_str_write_u8(b, 0x50);
        mqtt_str_write_vbi(b, length);
        mqtt_str_write_u16(b, v->packet_id);
        mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code);
        __properties_serialize(&v->v5.properties, b);
    }

    return 0;
}

static int
__serialize_pubrel(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    const mqtt_v_pubrel_t *v;

    v = &pkt->v.pubrel;

    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        b->s = (char *)malloc(4);
        b->n = 0;
        mqtt_str_write_u8(b, 0x62);
        mqtt_str_write_u8(b, 0x02);
        mqtt_str_write_u16(b, v->packet_id);
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;

        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBREL, 0))
            return -1;

        length = 3 + __properties_len(&v->v5.properties);
        b->n = length + 1 + mqtt_vbi_length(length);
        b->s = (char *)malloc(b->n);
        b->n = 0;
        mqtt_str_write_u8(b, 0x62);
        mqtt_str_write_vbi(b, length);
        mqtt_str_write_u16(b, v->packet_id);
        mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code);
        __properties_serialize(&v->v5.properties, b);
    }

    return 0;
}

static int
__serialize_pubcomp(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    const mqtt_v_pubcomp_t *v;

    v = &pkt->v.pubcomp;

    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        b->s = (char *)malloc(4);
        b->n = 0;
        mqtt_str_write_u8(b, 0x70);
        mqtt_str_write_u8(b, 0x02);
        mqtt_str_write_u16(b, v->packet_id);
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;

        if (!mqtt_properties_valid(&v->v5.properties, MQTT_PUBCOMP, 0))
            return -1;

        length = 3 + __properties_len(&v->v5.properties);
        b->n = length + 1 + mqtt_vbi_length(length);
        b->s = (char *)malloc(b->n);
        b->n = 0;
        mqtt_str_write_u8(b, 0x70);
        mqtt_str_write_vbi(b, length);
        mqtt_str_write_u16(b, v->packet_id);
        mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code);
        __properties_serialize(&v->v5.properties, b);
    }

    return 0;
}

static int
__serialize_subscribe(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    const mqtt_v_subscribe_t *v;
    const mqtt_p_subscribe_t *p;
    int i;

    v = &pkt->v.subscribe;
    p = &pkt->p.subscribe;

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
        length += 2 + p->topic_filters[i].n + 1;
    }
    if (pkt->ver == MQTT_VERSION_5)
        length += __properties_len(&v->v5.properties);
    b->n = length + 1 + mqtt_vbi_length(length);
    b->s = (char *)malloc(b->n);
    b->n = 0;
    mqtt_str_write_u8(b, 0x82);
    mqtt_str_write_vbi(b, length);
    mqtt_str_write_u16(b, v->packet_id);
    if (pkt->ver == MQTT_VERSION_5)
        __properties_serialize(&v->v5.properties, b);
    for (i = 0; i < p->n; i++) {
        mqtt_str_write_utf(b, &p->topic_filters[i]);
        mqtt_str_write_u8(b, p->options[i].flags);
    }

    return 0;
}

static int
__serialize_suback(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    const mqtt_v_suback_t *v;
    const mqtt_p_suback_t *p;
    int i;

    v = &pkt->v.suback;
    p = &pkt->p.suback;

    if (pkt->ver == MQTT_VERSION_5) {
        if (!mqtt_properties_valid(&v->v5.properties, MQTT_SUBACK, 0))
            return -1;
    }

    if (p->n == 0)
        return -1;

    length = p->n + 2;
    if (pkt->ver == MQTT_VERSION_5)
        length += __properties_len(&v->v5.properties);
    b->n = length + 1 + mqtt_vbi_length(length);
    b->s = (char *)malloc(b->n);
    b->n = 0;
    mqtt_str_write_u8(b, 0x90);
    mqtt_str_write_vbi(b, length);
    mqtt_str_write_u16(b, v->packet_id);
    if (pkt->ver == MQTT_VERSION_5)
        __properties_serialize(&v->v5.properties, b);
    for (i = 0; i < p->n; i++) {
        if (pkt->ver == MQTT_VERSION_3)
            mqtt_str_write_u8(b, p->v3.granted[i].flags);
        else if (pkt->ver == MQTT_VERSION_4)
            mqtt_str_write_u8(b, (uint8_t)p->v4.return_codes[i]);
        else if (pkt->ver == MQTT_VERSION_5)
            mqtt_str_write_u8(b, (uint8_t)p->v5.reason_codes[i]);
    }

    return 0;
}

static int
__serialize_unsubscribe(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    size_t length;
    const mqtt_v_unsubscribe_t *v;
    const mqtt_p_unsubscribe_t *p;
    int i;

    v = &pkt->v.unsubscribe;
    p = &pkt->p.unsubscribe;

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
        length += 2 + p->topic_filters[i].n;
    }
    if (pkt->ver == MQTT_VERSION_5)
        length += __properties_len(&v->v5.properties);
    b->n = length + 1 + mqtt_vbi_length(length);
    b->s = (char *)malloc(b->n);
    b->n = 0;
    mqtt_str_write_u8(b, 0xa2);
    mqtt_str_write_vbi(b, length);
    mqtt_str_write_u16(b, v->packet_id);
    if (pkt->ver == MQTT_VERSION_5)
        __properties_serialize(&v->v5.properties, b);
    for (i = 0; i < p->n; i++) mqtt_str_write_utf(b, &p->topic_filters[i]);

    return 0;
}

static int
__serialize_unsuback(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    const mqtt_v_unsuback_t *v;
    const mqtt_p_unsuback_t *p;

    v = &pkt->v.unsuback;
    p = &pkt->p.unsuback;

    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        b->s = (char *)malloc(4);
        b->n = 0;
        mqtt_str_write_u8(b, 0xb0);
        mqtt_str_write_u8(b, 0x02);
        mqtt_str_write_u16(b, v->packet_id);
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        int i;

        if (!mqtt_properties_valid(&v->v5.properties, MQTT_UNSUBACK, 0))
            return -1;

        length = 2 + __properties_len(&v->v5.properties) + p->v5.n;
        b->n = length + 1 + mqtt_vbi_length(length);
        b->s = (char *)malloc(b->n);
        b->n = 0;
        mqtt_str_write_u8(b, 0xb0);
        mqtt_str_write_vbi(b, length);
        mqtt_str_write_u16(b, v->packet_id);
        __properties_serialize(&v->v5.properties, b);
        for (i = 0; i < p->v5.n; i++) mqtt_str_write_u8(b, (uint8_t)p->v5.reason_codes[i]);
    }

    return 0;
}

static int
__serialize_pingreq(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    (void)pkt;

    b->s = (char *)malloc(2);
    b->n = 0;
    mqtt_str_write_u8(b, 0xc0);
    mqtt_str_write_u8(b, 0x00);

    return 0;
}

static int
__serialize_pingresp(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    (void)pkt;

    b->s = (char *)malloc(2);
    b->n = 0;
    mqtt_str_write_u8(b, 0xd0);
    mqtt_str_write_u8(b, 0x00);

    return 0;
}

static int
__serialize_disconnect(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    if (pkt->ver == MQTT_VERSION_3 || pkt->ver == MQTT_VERSION_4) {
        b->s = (char *)malloc(2);
        b->n = 0;
        mqtt_str_write_u8(b, 0xe0);
        mqtt_str_write_u8(b, 0x00);
    } else if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        const mqtt_v_disconnect_t *v;

        v = &pkt->v.disconnect;

        if (!mqtt_properties_valid(&v->v5.properties, MQTT_DISCONNECT, 0))
            return -1;

        length = 1 + __properties_len(&v->v5.properties);
        b->n = length + 1 + mqtt_vbi_length(length);
        b->s = (char *)malloc(b->n);
        b->n = 0;
        mqtt_str_write_u8(b, 0xe0);
        mqtt_str_write_vbi(b, length);
        mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code);
        __properties_serialize(&v->v5.properties, b);
    }

    return 0;
}

static int
__serialize_auth(const mqtt_packet_t *pkt, mqtt_str_t *b) {
    if (pkt->ver == MQTT_VERSION_5) {
        size_t length;
        const mqtt_v_auth_t *v;

        v = &pkt->v.auth;

        if (!mqtt_properties_valid(&v->v5.properties, MQTT_AUTH, 0))
            return -1;

        length = 1 + __properties_len(&v->v5.properties);
        b->n = length + 1 + mqtt_vbi_length(length);
        b->s = (char *)malloc(b->n);
        b->n = 0;
        mqtt_str_write_u8(b, 0xf0);
        mqtt_str_write_vbi(b, length);
        mqtt_str_write_u8(b, (uint8_t)v->v5.reason_code);
        __properties_serialize(&v->v5.properties, b);
    }

    return 0;
}

int
mqtt_serialize(mqtt_packet_t *pkt, mqtt_str_t *b) {
    int rc;

    mqtt_str_init(b, 0, 0);
    if (!mqtt_is_valid_version(pkt->ver)) {
        return -1;
    }
    switch (pkt->f.bits.type) {
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
    return rc;
}

void
mqtt_properties_add(mqtt_properties_t *properties, mqtt_property_code_t code, const void *value, const char *name) {
    mqtt_property_t *property;
    mqtt_property_type_t type;
    size_t len;

    len = 0;
    type = mqtt_property_type(code);
    property = (mqtt_property_t *)malloc(sizeof *property);
    memset(property, 0, sizeof *property);
    property->code = code;

    property->next = properties->head;
    properties->head = property;

    switch (type) {
    case MQTT_PROPERTY_TYPE_BYTE:
        property->b1 = *(uint8_t *)value;
        len = 1;
        break;
    case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
        property->b2 = *(uint16_t *)value;
        len = 2;
        break;
    case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
        property->b4 = *(uint32_t *)value;
        len = 4;
        break;
    case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
        property->bv = *(uint32_t *)value;
        len = mqtt_vbi_length(property->bv);
        break;
    case MQTT_PROPERTY_TYPE_BINARY_DATA:
        mqtt_str_set(&property->data, (mqtt_str_t *)value);
        len = 2 + property->data.n;
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
        mqtt_str_from(&property->str, (const char *)value);
        len = 2 + property->str.n;
        break;
    case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
        mqtt_str_from(&property->pair.name, name);
        mqtt_str_from(&property->pair.value, (const char *)value);
        len = 4 + property->pair.name.n + property->pair.value.n;
        break;
    }
    properties->length += len + 1;
}

mqtt_property_t *
mqtt_properties_find(mqtt_properties_t *properties, mqtt_property_code_t code) {
    mqtt_property_t *property;

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

    pp = &properties->head;
    while (*pp) {
        mqtt_property_t *property;

        property = *pp;
        if (property->code == code) {
            mqtt_property_type_t type;
            size_t len;

            len = 0;
            type = mqtt_property_type(property->code);

            switch (type) {
            case MQTT_PROPERTY_TYPE_BYTE:
                len = 1;
                break;
            case MQTT_PROPERTY_TYPE_TWO_BYTE_INTEGER:
                len = 2;
                break;
            case MQTT_PROPERTY_TYPE_FOUR_BYTE_INTEGER:
                len = 4;
                break;
            case MQTT_PROPERTY_TYPE_VARIABLE_BYTE_INTEGER:
                len = mqtt_vbi_length(property->bv);
                break;
            case MQTT_PROPERTY_TYPE_BINARY_DATA:
                len = 2 + property->data.n;
                break;
            case MQTT_PROPERTY_TYPE_UTF_8_ENCODED_STRING:
                len = 2 + property->str.n;
                break;
            case MQTT_PROPERTY_TYPE_UTF_8_STRING_PAIR:
                len = 4 + property->pair.name.n + property->pair.value.n;
                break;
            }
            properties->length -= len + 1;
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
mqtt_sn_packet_unit(mqtt_sn_packet_t *pkt) {
    mqtt_str_free(&pkt->b);
}

static int
__sn_parse_advertise(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 3)
        return -1;
    pkt->v.advertise.gwid = mqtt_str_read_u8(remaining);
    pkt->v.advertise.duration = mqtt_str_read_u16(remaining);
    return 0;
}

static int
__sn_parse_searchgw(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 1)
        return -1;
    pkt->v.searchgw.radius = mqtt_str_read_u8(remaining);
    return 0;
}

static int
__sn_parse_gwinfo(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n < 1)
        return -1;
    pkt->v.gwinfo.gwid = mqtt_str_read_u8(remaining);
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.gwinfo.gwadd, remaining);
        remaining->s += pkt->v.gwinfo.gwadd.n;
        remaining->n -= pkt->v.gwinfo.gwadd.n;
    }
    return 0;
}

static int
__sn_parse_connect(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n < 6 || remaining->n > 27)
        return -1;
    pkt->v.connect.flags.flag = mqtt_str_read_u8(remaining);
    pkt->v.connect.protocol_id = mqtt_str_read_u8(remaining);
    pkt->v.connect.duration = mqtt_str_read_u16(remaining);
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.connect.client_id, remaining);
        remaining->s += pkt->v.connect.client_id.n;
        remaining->n -= pkt->v.connect.client_id.n;
    }
    return 0;
}

static int
__sn_parse_connack(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 1)
        return -1;
    pkt->v.connack.return_code = (mqtt_sn_rc_t)mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_RC(pkt->v.connack.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_willtopicreq(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    (void)pkt;
    if (remaining->n != 0)
        return -1;
    return 0;
}

static int
__sn_parse_willtopic(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n < 1)
        return 0;
    pkt->v.willtopic.flags.flag = mqtt_str_read_u8(remaining);
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.willtopic.topic_name, remaining);
        remaining->s += pkt->v.willtopic.topic_name.n;
        remaining->n -= pkt->v.willtopic.topic_name.n;
    }
    return 0;
}

static int
__sn_parse_willmsgreq(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    (void)pkt;
    if (remaining->n != 0)
        return -1;
    return 0;
}

static int
__sn_parse_willmsg(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.willmsg.message, remaining);
        remaining->s += pkt->v.willmsg.message.n;
        remaining->n -= pkt->v.willmsg.message.n;
    }
    return 0;
}

static int
__sn_parse_register(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n < 4)
        return -1;
    pkt->v.regist.topic_id = mqtt_str_read_u16(remaining);
    pkt->v.regist.msg_id = mqtt_str_read_u16(remaining);
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.regist.topic_name, remaining);
        remaining->s += pkt->v.regist.topic_name.n;
        remaining->n -= pkt->v.regist.topic_name.n;
    }
    return 0;
}

static int
__sn_parse_regack(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 5)
        return -1;
    pkt->v.regack.topic_id = mqtt_str_read_u16(remaining);
    pkt->v.regack.msg_id = mqtt_str_read_u16(remaining);
    pkt->v.regack.return_code = (mqtt_sn_rc_t)mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_RC(pkt->v.regack.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_publish(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t topic_id_type;
    if (remaining->n < 5)
        return -1;
    pkt->v.publish.flags.flag = mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_QOS(pkt->v.publish.flags.bits.qos))
        return -1;
    topic_id_type = pkt->v.publish.flags.bits.topic_id_type;
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED || topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL)
        pkt->v.publish.topic.id = mqtt_str_read_u16(remaining);
    else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        memcpy(pkt->v.publish.topic.shor, remaining->s, 2);
        remaining->s += 2;
        remaining->n -= 2;
    }
    pkt->v.publish.topic.type = (mqtt_sn_topic_id_type_t)topic_id_type;
    pkt->v.publish.msg_id = mqtt_str_read_u16(remaining);
    if (pkt->v.publish.flags.bits.qos == 0 && pkt->v.publish.msg_id != 0)
        return -1;
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.publish.data, remaining);
        remaining->s += pkt->v.publish.data.n;
        remaining->n -= pkt->v.publish.data.n;
    }
    return 0;
}

static int
__sn_parse_puback(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 5)
        return -1;
    pkt->v.puback.topic.id = mqtt_str_read_u16(remaining);
    pkt->v.puback.msg_id = mqtt_str_read_u16(remaining);
    pkt->v.puback.return_code = (mqtt_sn_rc_t)mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_RC(pkt->v.puback.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_pubrec(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 2)
        return -1;
    pkt->v.pubrec.msg_id = mqtt_str_read_u16(remaining);
    return 0;
}

static int
__sn_parse_pubrel(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 2)
        return -1;
    pkt->v.pubrel.msg_id = mqtt_str_read_u16(remaining);
    return 0;
}

static int
__sn_parse_pubcomp(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 2)
        return -1;
    pkt->v.pubcomp.msg_id = mqtt_str_read_u16(remaining);
    return 0;
}

static int
__sn_parse_subscribe(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t topic_id_type;
    if (remaining->n < 5)
        return -1;
    pkt->v.subscribe.flags.flag = mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_QOS(pkt->v.subscribe.flags.bits.qos))
        return -1;
    pkt->v.subscribe.msg_id = mqtt_str_read_u16(remaining);
    topic_id_type = pkt->v.subscribe.flags.bits.topic_id_type;
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_set(&pkt->v.subscribe.topic.name, remaining);
        remaining->s += pkt->v.subscribe.topic.name.n;
        remaining->n -= pkt->v.subscribe.topic.name.n;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        memcpy(pkt->v.publish.topic.shor, remaining->s, 2);
        remaining->s += 2;
        remaining->n -= 2;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED) {
        pkt->v.subscribe.topic.id = mqtt_str_read_u16(remaining);
    }
    pkt->v.subscribe.topic.type = (mqtt_sn_topic_id_type_t)topic_id_type;
    return 0;
}

static int
__sn_parse_suback(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n < 6)
        return -1;
    pkt->v.suback.flags.flag = mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_QOS(pkt->v.suback.flags.bits.qos))
        return -1;
    pkt->v.suback.topic_id = mqtt_str_read_u16(remaining);
    pkt->v.suback.msg_id = mqtt_str_read_u16(remaining);
    pkt->v.suback.return_code = (mqtt_sn_rc_t)mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_RC(pkt->v.suback.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_unsubscribe(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    uint8_t topic_id_type;
    if (remaining->n < 5)
        return -1;
    pkt->v.unsubscribe.flags.flag = mqtt_str_read_u8(remaining);
    pkt->v.unsubscribe.msg_id = mqtt_str_read_u16(remaining);
    topic_id_type = pkt->v.unsubscribe.flags.bits.topic_id_type;
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL) {
        mqtt_str_set(&pkt->v.unsubscribe.topic.name, remaining);
        remaining->s += pkt->v.unsubscribe.topic.name.n;
        remaining->n -= pkt->v.unsubscribe.topic.name.n;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        memcpy(pkt->v.publish.topic.shor, remaining->s, 2);
        remaining->s += 2;
        remaining->n -= 2;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED) {
        pkt->v.unsubscribe.topic.id = mqtt_str_read_u16(remaining);
    }
    pkt->v.unsubscribe.topic.type = (mqtt_sn_topic_id_type_t)topic_id_type;
    return 0;
}

static int
__sn_parse_unsuback(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 2)
        return -1;
    pkt->v.unsuback.msg_id = mqtt_str_read_u16(remaining);
    return 0;
}

static int
__sn_parse_pingreq(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.pingreq.client_id, remaining);
        remaining->s += pkt->v.pingreq.client_id.n;
        remaining->n -= pkt->v.pingreq.client_id.n;
    }
    return 0;
}

static int
__sn_parse_pingresp(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    (void)pkt;
    if (remaining->n != 0)
        return -1;
    return 0;
}

static int
__sn_parse_disconnect(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n > 0) {
        if (remaining->n != 2)
            return -1;
        pkt->v.disconnect.duration = mqtt_str_read_u16(remaining);
    }
    return 0;
}

static int
__sn_parse_willtopicupd(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n < 1)
        return -1;
    pkt->v.willtopicupd.flags.flag = mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_QOS(pkt->v.willtopicupd.flags.bits.qos))
        return -1;
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.willtopicupd.topic_name, remaining);
        remaining->s += pkt->v.willtopicupd.topic_name.n;
        remaining->n -= pkt->v.willtopicupd.topic_name.n;
    }
    return 0;
}

static int
__sn_parse_willmsgupd(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.willmsgupd.message, remaining);
        remaining->s += pkt->v.willmsgupd.message.n;
        remaining->n -= pkt->v.willmsgupd.message.n;
    }
    return 0;
}

static int
__sn_parse_willtopicresp(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 1)
        return -1;
    pkt->v.willtopicresp.return_code = (mqtt_sn_rc_t)mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_RC(pkt->v.willtopicresp.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_willmsgresp(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n != 1)
        return -1;
    pkt->v.willmsgresp.return_code = (mqtt_sn_rc_t)mqtt_str_read_u8(remaining);
    if (!MQTT_SN_IS_RC(pkt->v.willmsgresp.return_code))
        return -1;
    return 0;
}

static int
__sn_parse_encapsulated(mqtt_sn_packet_t *pkt, mqtt_str_t *remaining) {
    if (remaining->n < 1)
        return -1;
    pkt->v.encapsulated.ctrl = mqtt_str_read_u8(remaining);
    if (remaining->n > 0) {
        mqtt_str_set(&pkt->v.encapsulated.wireless_node, remaining);
        remaining->s += pkt->v.encapsulated.wireless_node.n;
        remaining->n -= pkt->v.encapsulated.wireless_node.n;
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
    if (b.n) {
        return -1;
    }
    return 1;
}

void
mqtt_sn_parser_init(mqtt_sn_parser_t *parser) {
    memset(parser, 0, sizeof *parser);
    parser->state = MQTT_SN_ST_LENGTH;
}

void
mqtt_sn_parser_unit(mqtt_sn_parser_t *parser) {
    (void)parser;
}

int
mqtt_sn_parse(mqtt_sn_parser_t *parser, mqtt_str_t *b, mqtt_sn_packet_t *pkt) {
    char *c, *e;
    size_t offset;
    int rc;

    e = b->s + b->n;
    c = b->s;
    rc = 0;
    while (c < e) {
        uint8_t k = (uint8_t)(*c);
        switch (parser->state) {
        case MQTT_SN_ST_LENGTH:
            memset(&parser->pkt, 0, sizeof parser->pkt);
            if (parser->multiplier == 1) {
                parser->require = k * 0x80;
                parser->multiplier = 2;
            } else if (parser->multiplier == 2) {
                parser->require += k;
                if (parser->require < 0x100) {
                    rc = -1;
                    goto e;
                }
                parser->require -= 3;
                if (parser->require < 1) {
                    rc = -1;
                    goto e;
                }
                parser->state = MQTT_SN_ST_TYPE;
            } else if (k == 0x01) {
                parser->multiplier = 1;
            } else {
                parser->require = k - 1;
                if (parser->require < 1) {
                    rc = -1;
                    goto e;
                }
                parser->state = MQTT_SN_ST_TYPE;
            }
            c++;
            break;
        case MQTT_SN_ST_TYPE:
            parser->pkt.type = (mqtt_sn_packet_type_t)k;
            if (!MQTT_SN_IS_PACKET_TYPE(parser->pkt.type)) {
                rc = -1;
                goto e;
            }
            parser->require -= 1;
            if (parser->require == 0) {
                parser->state = MQTT_SN_ST_LENGTH;
                rc = __sn_process(parser);
                c++;
                b->n = e - c;
                b->s = c;
                goto e;
            }
            parser->pkt.b.s = (char *)malloc(parser->require);
            parser->pkt.b.n = parser->require;
            parser->state = MQTT_SN_ST_REMAIN;
            c++;
            break;
        case MQTT_SN_ST_REMAIN:
            offset = parser->pkt.b.n - parser->require;
            if ((size_t)(e - c) >= parser->require) {
                memcpy(parser->pkt.b.s + offset, c, parser->require);
                c += parser->require;
                parser->state = MQTT_SN_ST_LENGTH;
                rc = __sn_process(parser);
                b->n = e - c;
                b->s = c;
                goto e;
            } else {
                memcpy(parser->pkt.b.s + offset, c, e - c);
                parser->require -= e - c;
                c = e;
            }
            break;
        }
    }

e:
    if (rc == 1) {
        *pkt = parser->pkt;
    }
    return rc;
}

void
mqtt_sn_reader_init(mqtt_sn_reader_t *reader, void *io, ssize_t (*read)(void *io, void *, size_t)) {
    reader->io = io;
    reader->read = read;
    mqtt_sn_parser_init(&reader->parser);
}

void
mqtt_sn_reader_unit(mqtt_sn_reader_t *reader) {
    mqtt_sn_parser_unit(&reader->parser);
}

int
mqtt_sn_read(mqtt_sn_reader_t *reader, mqtt_sn_packet_t *pkt) {
    mqtt_sn_parser_t *parser;
    int rc;

    parser = &reader->parser;
    parser->multiplier = 0;
    parser->require = 0;
    rc = 0;

    while (1) {
        ssize_t nread;
        uint8_t k;
        char *buff;
        size_t required;

        if (parser->state == MQTT_SN_ST_REMAIN) {
            buff = (char *)malloc(parser->require);
            required = parser->require;
        } else {
            buff = (char *)&k;
            required = 1;
        }
        nread = reader->read(reader->io, buff, required);
        if ((size_t)nread != required) {
            rc = -1;
            goto e;
        }
        switch (parser->state) {
        case MQTT_SN_ST_LENGTH:
            memset(&parser->pkt, 0, sizeof parser->pkt);
            if (parser->multiplier == 1) {
                parser->require = k * 0x80;
                parser->multiplier = 2;
            } else if (parser->multiplier == 2) {
                parser->require += k;
                if (parser->require < 0x100) {
                    rc = -1;
                    goto e;
                }
                parser->require -= 3;
                if (parser->require < 1) {
                    rc = -1;
                    goto e;
                }
                parser->state = MQTT_SN_ST_TYPE;
            } else if (k == 0x01) {
                parser->multiplier = 1;
            } else {
                parser->require = k - 1;
                if (parser->require < 1) {
                    rc = -1;
                    goto e;
                }
                parser->state = MQTT_SN_ST_TYPE;
            }
            break;
        case MQTT_SN_ST_TYPE:
            parser->pkt.type = (mqtt_sn_packet_type_t)k;
            if (!MQTT_SN_IS_PACKET_TYPE(parser->pkt.type)) {
                rc = -1;
                goto e;
            }
            parser->require -= 1;
            if (parser->require == 0) {
                parser->state = MQTT_SN_ST_LENGTH;
                rc = __sn_process(parser);
                goto e;
            }
            parser->state = MQTT_SN_ST_REMAIN;
            break;
        case MQTT_SN_ST_REMAIN:
            parser->pkt.b.n = parser->require;
            parser->pkt.b.s = buff;
            rc = __sn_process(parser);
            goto e;
        }
    }

e:
    if (rc == 1) {
        *pkt = parser->pkt;
    }
    return rc;
}

static inline uint16_t
mqtt_sn_vbi_length(uint16_t length) {
    return length > 0xff ? length + 3 : length + 1;
}

static void
mqtt_sn_write_length(mqtt_str_t *b, uint16_t length) {
    if (length > 0xff) {
        mqtt_str_write_u8(b, 0x01);
        mqtt_str_write_u16(b, length);
    } else {
        mqtt_str_write_u8(b, (uint8_t)length);
    }
}

static void
__sn_serialize_advertise(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 5;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_ADVERTISE);
    mqtt_str_write_u8(b, pkt->v.advertise.gwid);
    mqtt_str_write_u16(b, pkt->v.advertise.duration);
}

static void
__sn_serialize_searchgw(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 3;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_SEARCHGW);
    mqtt_str_write_u8(b, pkt->v.searchgw.radius);
}

static void
__sn_serialize_gwinfo(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 3 + pkt->v.gwinfo.gwadd.n;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_GWINFO);
    mqtt_str_write_u8(b, pkt->v.gwinfo.gwid);
    mqtt_str_concat(b, &pkt->v.gwinfo.gwadd);
}

static void
__sn_serialize_connect(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 6 + pkt->v.connect.client_id.n;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_CONNECT);
    mqtt_str_write_u8(b, pkt->v.connect.flags.flag);
    mqtt_str_write_u8(b, pkt->v.connect.protocol_id);
    mqtt_str_write_u16(b, pkt->v.connect.duration);
    mqtt_str_concat(b, &pkt->v.connect.client_id);
}

static void
__sn_serialize_connack(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 3;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_CONNACK);
    mqtt_str_write_u8(b, (uint8_t)pkt->v.connack.return_code);
}

static void
__sn_serialize_willtopicreq(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    (void)pkt;
    uint8_t length = 2;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_WILLTOPICREQ);
}

static void
__sn_serialize_willtopic(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint16_t length;

    if (pkt->v.willtopic.topic_name.n)
        length = mqtt_sn_vbi_length(2 + pkt->v.willtopic.topic_name.n);
    else
        length = 2;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_sn_write_length(b, length);
    mqtt_str_write_u8(b, MQTT_SN_WILLTOPIC);
    if (length > 2 && pkt->v.willtopic.topic_name.n) {
        mqtt_str_write_u8(b, pkt->v.willtopic.flags.flag);
        mqtt_str_concat(b, &pkt->v.willtopic.topic_name);
    }
}

static void
__sn_serialize_willmsgreq(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    (void)pkt;
    uint8_t length = 2;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_WILLMSGREQ);
}

static void
__sn_serialize_willmsg(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint16_t length = mqtt_sn_vbi_length(1 + pkt->v.willmsg.message.n);
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_sn_write_length(b, length);
    mqtt_str_write_u8(b, MQTT_SN_WILLMSG);
    mqtt_str_concat(b, &pkt->v.willmsg.message);
}

static void
__sn_serialize_register(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint16_t length = mqtt_sn_vbi_length(5 + pkt->v.regist.topic_name.n);
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_sn_write_length(b, length);
    mqtt_str_write_u8(b, MQTT_SN_REGISTER);
    mqtt_str_write_u16(b, pkt->v.regist.topic_id);
    mqtt_str_write_u16(b, pkt->v.regist.msg_id);
    mqtt_str_concat(b, &pkt->v.regist.topic_name);
}

static void
__sn_serialize_regack(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 7;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_REGACK);
    mqtt_str_write_u16(b, pkt->v.regack.topic_id);
    mqtt_str_write_u16(b, pkt->v.regack.msg_id);
    mqtt_str_write_u8(b, (uint8_t)pkt->v.regack.return_code);
}

static void
__sn_serialize_publish(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t topic_id_type = pkt->v.publish.flags.bits.topic_id_type;
    uint16_t length = mqtt_sn_vbi_length(6 + pkt->v.publish.data.n);
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_sn_write_length(b, length);
    mqtt_str_write_u8(b, MQTT_SN_PUBLISH);
    mqtt_str_write_u8(b, pkt->v.publish.flags.flag);

    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        memcpy(b->s + b->n, pkt->v.publish.topic.shor, 2);
        b->n += 2;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED)
        mqtt_str_write_u16(b, pkt->v.publish.topic.id);

    mqtt_str_write_u16(b, pkt->v.publish.msg_id);
    mqtt_str_concat(b, &pkt->v.publish.data);
}

static void
__sn_serialize_puback(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 7;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_PUBACK);
    mqtt_str_write_u16(b, pkt->v.puback.topic.id);
    mqtt_str_write_u16(b, pkt->v.puback.msg_id);
    mqtt_str_write_u8(b, (uint8_t)pkt->v.puback.return_code);
}

static void
__sn_serialize_pubrec(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 4;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_PUBREC);
    mqtt_str_write_u16(b, pkt->v.pubrec.msg_id);
}

static void
__sn_serialize_pubrel(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 4;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_PUBREL);
    mqtt_str_write_u16(b, pkt->v.pubrel.msg_id);
}

static void
__sn_serialize_pubcomp(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 4;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_PUBCOMP);
    mqtt_str_write_u16(b, pkt->v.pubcomp.msg_id);
}

static void
__sn_serialize_subscribe(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint16_t length = 4;
    uint8_t topic_id_type = pkt->v.subscribe.flags.bits.topic_id_type;

    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL)
        length += pkt->v.subscribe.topic.name.n;
    else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT)
        length += 2;
    else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED)
        length += 2;
    length = mqtt_sn_vbi_length(length);
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_sn_write_length(b, length);
    mqtt_str_write_u8(b, MQTT_SN_SUBSCRIBE);
    mqtt_str_write_u8(b, pkt->v.subscribe.flags.flag);
    mqtt_str_write_u16(b, pkt->v.subscribe.msg_id);
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL)
        mqtt_str_concat(b, &pkt->v.subscribe.topic.name);
    else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        memcpy(b->s + b->n, pkt->v.subscribe.topic.shor, 2);
        b->n += 2;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED)
        mqtt_str_write_u16(b, pkt->v.subscribe.topic.id);
}

static void
__sn_serialize_suback(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 8;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_SUBACK);
    mqtt_str_write_u8(b, pkt->v.suback.flags.flag);
    mqtt_str_write_u16(b, pkt->v.suback.topic_id);
    mqtt_str_write_u16(b, pkt->v.suback.msg_id);
    mqtt_str_write_u8(b, (uint8_t)pkt->v.suback.return_code);
}

static void
__sn_serialize_unsubscribe(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint16_t length = 4;
    uint8_t topic_id_type = pkt->v.unsubscribe.flags.bits.topic_id_type;

    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL)
        length += pkt->v.unsubscribe.topic.name.n;
    else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT)
        length += 2;
    else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED)
        length += 2;
    length = mqtt_sn_vbi_length(length);
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_sn_write_length(b, length);
    mqtt_str_write_u8(b, MQTT_SN_UNSUBSCRIBE);
    mqtt_str_write_u8(b, pkt->v.unsubscribe.flags.flag);
    mqtt_str_write_u16(b, pkt->v.unsubscribe.msg_id);
    if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_NORMAL)
        mqtt_str_concat(b, &pkt->v.unsubscribe.topic.name);
    else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT) {
        memcpy(b->s + b->n, pkt->v.unsubscribe.topic.shor, 2);
        b->n += 2;
    } else if (topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED)
        mqtt_str_write_u16(b, pkt->v.unsubscribe.topic.id);
}

static void
__sn_serialize_unsuback(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 4;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_UNSUBACK);
    mqtt_str_write_u16(b, pkt->v.unsuback.msg_id);
}

static void
__sn_serialize_pingreq(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 2 + pkt->v.pingreq.client_id.n;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_PINGREQ);
    if (pkt->v.pingreq.client_id.n > 0)
        mqtt_str_concat(b, &pkt->v.pingreq.client_id);
}

static void
__sn_serialize_pingresp(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    (void)pkt;
    uint8_t length = 2;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_PINGRESP);
}

static void
__sn_serialize_disconnect(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 2;

    if (pkt->v.disconnect.duration > 0)
        length += 2;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_DISCONNECT);
    if (pkt->v.disconnect.duration > 0)
        mqtt_str_write_u16(b, pkt->v.disconnect.duration);
}

static void
__sn_serialize_willtopicupd(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint16_t length;

    if (mqtt_str_empty(&pkt->v.willtopicupd.topic_name))
        length = 2;
    else
        length = mqtt_sn_vbi_length(2 + pkt->v.willtopicupd.topic_name.n);

    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_sn_write_length(b, length);
    mqtt_str_write_u8(b, MQTT_SN_WILLTOPICUPD);
    if (!mqtt_str_empty(&pkt->v.willtopicupd.topic_name)) {
        mqtt_str_write_u8(b, pkt->v.willtopicupd.flags.flag);
        mqtt_str_concat(b, &pkt->v.willtopicupd.topic_name);
    }
}

static void
__sn_serialize_willmsgupd(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint16_t length = mqtt_sn_vbi_length(1 + pkt->v.willmsgupd.message.n);
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_sn_write_length(b, length);
    mqtt_str_write_u8(b, MQTT_SN_WILLMSGUPD);
    mqtt_str_concat(b, &pkt->v.willmsgupd.message);
}

static void
__sn_serialize_willtopicresp(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 3;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_WILLTOPICRESP);
    mqtt_str_write_u8(b, (uint8_t)pkt->v.willtopicresp.return_code);
}

static void
__sn_serialize_willmsgresp(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint8_t length = 3;
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_str_write_u8(b, length);
    mqtt_str_write_u8(b, MQTT_SN_WILLMSGRESP);
    mqtt_str_write_u8(b, (uint8_t)pkt->v.willmsgresp.return_code);
}

static void
__sn_serialize_encapsulated(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    uint16_t length = mqtt_sn_vbi_length(2 + pkt->v.encapsulated.wireless_node.n);
    b->s = (char *)malloc(length);
    b->n = 0;

    mqtt_sn_write_length(b, length);
    mqtt_str_write_u8(b, MQTT_SN_ENCAPSULATED);
    mqtt_str_write_u8(b, pkt->v.encapsulated.ctrl);
    mqtt_str_concat(b, &pkt->v.encapsulated.wireless_node);
}

void
mqtt_sn_serialize(mqtt_sn_packet_t *pkt, mqtt_str_t *b) {
    mqtt_str_init(b, 0, 0);
    switch (pkt->type) {
    case MQTT_SN_ADVERTISE:
        __sn_serialize_advertise(pkt, b);
        break;
    case MQTT_SN_SEARCHGW:
        __sn_serialize_searchgw(pkt, b);
        break;
    case MQTT_SN_GWINFO:
        __sn_serialize_gwinfo(pkt, b);
        break;
    case MQTT_SN_CONNECT:
        __sn_serialize_connect(pkt, b);
        break;
    case MQTT_SN_CONNACK:
        __sn_serialize_connack(pkt, b);
        break;
    case MQTT_SN_WILLTOPICREQ:
        __sn_serialize_willtopicreq(pkt, b);
        break;
    case MQTT_SN_WILLTOPIC:
        __sn_serialize_willtopic(pkt, b);
        break;
    case MQTT_SN_WILLMSGREQ:
        __sn_serialize_willmsgreq(pkt, b);
        break;
    case MQTT_SN_WILLMSG:
        __sn_serialize_willmsg(pkt, b);
        break;
    case MQTT_SN_REGISTER:
        __sn_serialize_register(pkt, b);
        break;
    case MQTT_SN_REGACK:
        __sn_serialize_regack(pkt, b);
        break;
    case MQTT_SN_PUBLISH:
        __sn_serialize_publish(pkt, b);
        break;
    case MQTT_SN_PUBACK:
        __sn_serialize_puback(pkt, b);
        break;
    case MQTT_SN_PUBREC:
        __sn_serialize_pubrec(pkt, b);
        break;
    case MQTT_SN_PUBREL:
        __sn_serialize_pubrel(pkt, b);
        break;
    case MQTT_SN_PUBCOMP:
        __sn_serialize_pubcomp(pkt, b);
        break;
    case MQTT_SN_SUBSCRIBE:
        __sn_serialize_subscribe(pkt, b);
        break;
    case MQTT_SN_SUBACK:
        __sn_serialize_suback(pkt, b);
        break;
    case MQTT_SN_UNSUBSCRIBE:
        __sn_serialize_unsubscribe(pkt, b);
        break;
    case MQTT_SN_UNSUBACK:
        __sn_serialize_unsuback(pkt, b);
        break;
    case MQTT_SN_PINGREQ:
        __sn_serialize_pingreq(pkt, b);
        break;
    case MQTT_SN_PINGRESP:
        __sn_serialize_pingresp(pkt, b);
        break;
    case MQTT_SN_DISCONNECT:
        __sn_serialize_disconnect(pkt, b);
        break;
    case MQTT_SN_WILLTOPICUPD:
        __sn_serialize_willtopicupd(pkt, b);
        break;
    case MQTT_SN_WILLMSGUPD:
        __sn_serialize_willmsgupd(pkt, b);
        break;
    case MQTT_SN_WILLTOPICRESP:
        __sn_serialize_willtopicresp(pkt, b);
        break;
    case MQTT_SN_WILLMSGRESP:
        __sn_serialize_willmsgresp(pkt, b);
        break;
    case MQTT_SN_ENCAPSULATED:
        __sn_serialize_encapsulated(pkt, b);
        break;
    default:
        break;
    }
}

#endif /* MQTT_IMPL */
