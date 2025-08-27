#define MQTT_IMPL
#include "mqtt.h"

#include <assert.h>

static void
test_mqtt() {
    {
        // v3
        mqtt_str_t bs = MQTT_STR_INITIALIZER;
        mqtt_str_t bp = MQTT_STR_INITIALIZER;
        mqtt_packet_t pkt;
        mqtt_parser_t parser;
        int rc;

        // connect
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_CONNECT);
        pkt.v.connect.connect_flags.bits.clean_session = 1;
        pkt.v.connect.connect_flags.bits.will_flag = 1;
        pkt.v.connect.connect_flags.bits.will_qos = MQTT_QOS_1;
        pkt.v.connect.connect_flags.bits.will_retain = 1;
        pkt.v.connect.connect_flags.bits.username_flag = 1;
        pkt.v.connect.connect_flags.bits.password_flag = 1;
        mqtt_str_from(&pkt.p.connect.will_topic, "hello");
        mqtt_str_from(&pkt.p.connect.will_message, "world");
        mqtt_str_from(&pkt.p.connect.client_id, "mqtt");
        mqtt_str_from(&pkt.p.connect.username, "username");
        mqtt_str_from(&pkt.p.connect.password, "password");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_CONNECT);
        assert(pkt.v.connect.protocol_version == MQTT_VERSION_3);
        assert(!mqtt_str_strcmp(&pkt.v.connect.protocol_name, mqtt_protocol_name(MQTT_VERSION_3)));
        assert(pkt.v.connect.connect_flags.bits.clean_session == 1);
        assert(pkt.v.connect.connect_flags.bits.will_flag == 1);
        assert(pkt.v.connect.connect_flags.bits.will_qos == MQTT_QOS_1);
        assert(pkt.v.connect.connect_flags.bits.will_retain == 1);
        assert(pkt.v.connect.connect_flags.bits.username_flag == 1);
        assert(pkt.v.connect.connect_flags.bits.password_flag == 1);
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_topic, "hello"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_message, "world"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.client_id, "mqtt"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.username, "username"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.password, "password"));

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // connack
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_CONNACK);
        pkt.v.connack.v3.return_code = MQTT_CRC_ACCEPTED;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_CONNACK);
        assert(pkt.v.connack.v3.return_code == MQTT_CRC_ACCEPTED);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // subscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_SUBSCRIBE);
        pkt.v.subscribe.packet_id = 0x03;
        mqtt_subscribe_generate(&pkt, 2);
        pkt.p.subscribe.options[0].bits.qos = MQTT_QOS_2;
        mqtt_str_from(&pkt.p.subscribe.topic_filters[0], "topic_filter_1");
        pkt.p.subscribe.options[1].bits.qos = MQTT_QOS_1;
        mqtt_str_from(&pkt.p.subscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_SUBSCRIBE);
        assert(pkt.v.subscribe.packet_id == 0x03);
        assert(pkt.p.subscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[0], "topic_filter_1"));
        assert(pkt.p.subscribe.options[0].bits.qos == MQTT_QOS_2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[1], "topic_filter_2"));
        assert(pkt.p.subscribe.options[1].bits.qos == MQTT_QOS_1);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // suback
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_SUBACK);
        pkt.v.suback.packet_id = 0x05;
        mqtt_suback_generate(&pkt, 2);
        pkt.p.suback.v3.granted[0].bits.qos = MQTT_QOS_0;
        pkt.p.suback.v3.granted[1].bits.qos = MQTT_QOS_2;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_SUBACK);
        assert(pkt.v.suback.packet_id == 0x05);
        assert(pkt.p.suback.n == 2);
        assert(pkt.p.suback.v3.granted[0].bits.qos == MQTT_QOS_0);
        assert(pkt.p.suback.v3.granted[1].bits.qos == MQTT_QOS_2);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // unsubscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_UNSUBSCRIBE);
        pkt.v.unsubscribe.packet_id = 0x22;
        mqtt_unsubscribe_generate(&pkt, 2);
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1");
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_UNSUBSCRIBE);
        assert(pkt.v.unsubscribe.packet_id == 0x22);
        assert(pkt.p.unsubscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1"));
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2"));

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // unsuback
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_UNSUBACK);
        pkt.v.unsuback.packet_id = 0x05;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_UNSUBACK);
        assert(pkt.v.unsuback.packet_id == 0x05);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // publish
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.bits.dup = 1;
        pkt.f.bits.qos = MQTT_QOS_2;
        pkt.f.bits.retain = 1;
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        mqtt_str_from(&pkt.p.publish.message, "publish_message");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PUBLISH);
        assert(pkt.f.bits.dup == 1);
        assert(pkt.f.bits.qos == MQTT_QOS_2);
        assert(pkt.f.bits.retain == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(!mqtt_str_strcmp(&pkt.p.publish.message, "publish_message"));

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // puback
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBACK);
        pkt.v.puback.packet_id = 0x22;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PUBACK);
        assert(pkt.v.puback.packet_id == 0x22);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pubrec
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBREC);
        pkt.v.puback.packet_id = 0x25;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PUBREC);
        assert(pkt.v.puback.packet_id == 0x25);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pubrel
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBREL);
        pkt.v.puback.packet_id = 0x23;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PUBREL);
        assert(pkt.v.puback.packet_id == 0x23);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pubcomp
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBCOMP);
        pkt.v.puback.packet_id = 0x30;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PUBCOMP);
        assert(pkt.v.puback.packet_id == 0x30);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pingreq
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PINGREQ);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PINGREQ);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pingresp
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PINGRESP);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PINGRESP);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // disconnect
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_DISCONNECT);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_DISCONNECT);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);
    }

    {
        // v4
        mqtt_str_t bs = MQTT_STR_INITIALIZER;
        mqtt_str_t bp = MQTT_STR_INITIALIZER;
        mqtt_packet_t pkt;
        mqtt_parser_t parser;
        int rc;

        // connect
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_CONNECT);
        pkt.v.connect.connect_flags.bits.clean_session = 1;
        pkt.v.connect.connect_flags.bits.will_flag = 1;
        pkt.v.connect.connect_flags.bits.will_qos = MQTT_QOS_1;
        pkt.v.connect.connect_flags.bits.will_retain = 1;
        pkt.v.connect.connect_flags.bits.username_flag = 1;
        pkt.v.connect.connect_flags.bits.password_flag = 1;
        mqtt_str_from(&pkt.p.connect.will_topic, "hello");
        mqtt_str_from(&pkt.p.connect.will_message, "world");
        mqtt_str_from(&pkt.p.connect.client_id, "mqtt");
        mqtt_str_from(&pkt.p.connect.username, "username");
        mqtt_str_from(&pkt.p.connect.password, "password");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.f.bits.type == MQTT_CONNECT);
        assert(pkt.v.connect.protocol_version == MQTT_VERSION_4);
        assert(!mqtt_str_strcmp(&pkt.v.connect.protocol_name, mqtt_protocol_name(MQTT_VERSION_4)));
        assert(pkt.v.connect.connect_flags.bits.clean_session == 1);
        assert(pkt.v.connect.connect_flags.bits.will_flag == 1);
        assert(pkt.v.connect.connect_flags.bits.will_qos == MQTT_QOS_1);
        assert(pkt.v.connect.connect_flags.bits.will_retain == 1);
        assert(pkt.v.connect.connect_flags.bits.username_flag == 1);
        assert(pkt.v.connect.connect_flags.bits.password_flag == 1);
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_topic, "hello"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_message, "world"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.client_id, "mqtt"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.username, "username"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.password, "password"));

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // connack
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_CONNACK);
        pkt.v.connack.v4.acknowledge_flags.bits.session_present = 1;
        pkt.v.connack.v4.return_code = MQTT_CRC_ACCEPTED;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_CONNACK);
        assert(pkt.v.connack.v4.acknowledge_flags.bits.session_present == 1);
        assert(pkt.v.connack.v4.return_code == MQTT_CRC_ACCEPTED);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // subscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_SUBSCRIBE);
        pkt.v.subscribe.packet_id = 0x03;
        mqtt_subscribe_generate(&pkt, 2);
        pkt.p.subscribe.options[0].bits.qos = MQTT_QOS_2;
        mqtt_str_from(&pkt.p.subscribe.topic_filters[0], "topic_filter_1");
        pkt.p.subscribe.options[1].bits.qos = MQTT_QOS_1;
        mqtt_str_from(&pkt.p.subscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_SUBSCRIBE);
        assert(pkt.v.subscribe.packet_id == 0x03);
        assert(pkt.p.subscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[0], "topic_filter_1"));
        assert(pkt.p.subscribe.options[0].bits.qos == MQTT_QOS_2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[1], "topic_filter_2"));
        assert(pkt.p.subscribe.options[1].bits.qos == MQTT_QOS_1);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // suback
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_SUBACK);
        pkt.v.suback.packet_id = 0x05;
        mqtt_suback_generate(&pkt, 2);
        pkt.p.suback.v4.return_codes[0] = MQTT_SRC_QOS_1;
        pkt.p.suback.v4.return_codes[1] = MQTT_SRC_QOS_F;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_SUBACK);
        assert(pkt.v.suback.packet_id == 0x05);
        assert(pkt.p.suback.n == 2);
        assert(pkt.p.suback.v4.return_codes[0] == MQTT_SRC_QOS_1);
        assert(pkt.p.suback.v4.return_codes[1] == MQTT_SRC_QOS_F);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // unsubscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_UNSUBSCRIBE);
        pkt.v.unsubscribe.packet_id = 0x22;
        mqtt_unsubscribe_generate(&pkt, 2);
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1");
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_UNSUBSCRIBE);
        assert(pkt.v.unsubscribe.packet_id == 0x22);
        assert(pkt.p.unsubscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1"));
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2"));

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // unsuback
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_UNSUBACK);
        pkt.v.unsuback.packet_id = 0x05;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_UNSUBACK);
        assert(pkt.v.unsuback.packet_id == 0x05);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // publish
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBLISH);
        pkt.f.bits.dup = 1;
        pkt.f.bits.qos = MQTT_QOS_2;
        pkt.f.bits.retain = 1;
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        mqtt_str_from(&pkt.p.publish.message, "publish_message");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_PUBLISH);
        assert(pkt.f.bits.dup == 1);
        assert(pkt.f.bits.qos == MQTT_QOS_2);
        assert(pkt.f.bits.retain == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(!mqtt_str_strcmp(&pkt.p.publish.message, "publish_message"));

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // puback
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBACK);
        pkt.v.puback.packet_id = 0x22;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_PUBACK);
        assert(pkt.v.puback.packet_id == 0x22);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pubrec
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBREC);
        pkt.v.puback.packet_id = 0x25;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_PUBREC);
        assert(pkt.v.puback.packet_id == 0x25);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pubrel
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBREL);
        pkt.v.puback.packet_id = 0x23;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_PUBREL);
        assert(pkt.v.puback.packet_id == 0x23);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pubcomp
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBCOMP);
        pkt.v.puback.packet_id = 0x30;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_PUBCOMP);
        assert(pkt.v.puback.packet_id == 0x30);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pingreq
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PINGREQ);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_PINGREQ);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pingresp
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PINGRESP);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_PINGRESP);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // disconnect
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_DISCONNECT);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(pkt.f.bits.type == MQTT_DISCONNECT);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);
    }

    {
        // v5
        mqtt_str_t bs = MQTT_STR_INITIALIZER;
        mqtt_str_t bp = MQTT_STR_INITIALIZER;
        mqtt_packet_t pkt;
        mqtt_parser_t parser;
        mqtt_property_t *prop;
        mqtt_str_t authentication_data = MQTT_STR_INITIALIZER;
        int rc;

        // connect
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_CONNECT);
        pkt.v.connect.connect_flags.bits.clean_session = 1;
        pkt.v.connect.connect_flags.bits.will_flag = 1;
        pkt.v.connect.connect_flags.bits.will_qos = MQTT_QOS_2;
        pkt.v.connect.connect_flags.bits.will_retain = 1;
        pkt.v.connect.connect_flags.bits.username_flag = 1;
        pkt.v.connect.connect_flags.bits.password_flag = 1;
        mqtt_str_from(&pkt.p.connect.will_topic, "hello");
        mqtt_str_from(&pkt.p.connect.will_message, "world");
        mqtt_str_from(&pkt.p.connect.client_id, "mqtt");
        mqtt_str_from(&pkt.p.connect.username, "username");
        mqtt_str_from(&pkt.p.connect.password, "password");

        mqtt_str_from(&authentication_data, "password@libmqtt");
        mqtt_properties_add(&pkt.v.connect.v5.properties, MQTT_PROPERTY_AUTHENTICATION_METHOD, (void *)"oauth2", 0);
        mqtt_properties_add(&pkt.v.connect.v5.properties, MQTT_PROPERTY_AUTHENTICATION_DATA,
                            (void *)&authentication_data, 0);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.f.bits.type == MQTT_CONNECT);
        assert(pkt.v.connect.protocol_version == MQTT_VERSION_5);
        assert(!mqtt_str_strcmp(&pkt.v.connect.protocol_name, mqtt_protocol_name(MQTT_VERSION_5)));
        assert(pkt.v.connect.connect_flags.bits.clean_session == 1);
        assert(pkt.v.connect.connect_flags.bits.will_flag == 1);
        assert(pkt.v.connect.connect_flags.bits.will_qos == MQTT_QOS_2);
        assert(pkt.v.connect.connect_flags.bits.will_retain == 1);
        assert(pkt.v.connect.connect_flags.bits.username_flag == 1);
        assert(pkt.v.connect.connect_flags.bits.password_flag == 1);
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_topic, "hello"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_message, "world"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.client_id, "mqtt"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.username, "username"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.password, "password"));

        prop = mqtt_properties_find(&pkt.v.connect.v5.properties, MQTT_PROPERTY_AUTHENTICATION_METHOD);
        assert(prop);
        assert(!mqtt_str_strcmp(&prop->str, "oauth2"));

        prop = mqtt_properties_find(&pkt.v.connect.v5.properties, MQTT_PROPERTY_AUTHENTICATION_DATA);
        assert(prop);
        assert(!mqtt_str_strcmp(&prop->data, "password@libmqtt"));

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // connack
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_CONNACK);
        pkt.v.connack.v5.acknowledge_flags.bits.session_present = 1;
        pkt.v.connack.v5.reason_code = MQTT_RC_BAD_AUTHENTICATION_METHOD;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_CONNACK);
        assert(pkt.v.connack.v5.acknowledge_flags.bits.session_present == 1);
        assert(pkt.v.connack.v5.reason_code == MQTT_RC_BAD_AUTHENTICATION_METHOD);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // subscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_SUBSCRIBE);
        pkt.v.subscribe.packet_id = 0x03;
        mqtt_subscribe_generate(&pkt, 2);
        pkt.p.subscribe.options[0].bits.qos = MQTT_QOS_2;
        pkt.p.subscribe.options[0].bits.nl = 1;
        pkt.p.subscribe.options[0].bits.rap = 0;
        pkt.p.subscribe.options[0].bits.retain_handling = 1;
        mqtt_str_from(&pkt.p.subscribe.topic_filters[0], "topic_filter_1");
        pkt.p.subscribe.options[1].bits.qos = MQTT_QOS_1;
        pkt.p.subscribe.options[1].bits.nl = 0;
        pkt.p.subscribe.options[1].bits.rap = 1;
        pkt.p.subscribe.options[1].bits.retain_handling = 0;
        mqtt_str_from(&pkt.p.subscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_SUBSCRIBE);
        assert(pkt.v.subscribe.packet_id == 0x03);
        assert(pkt.p.subscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[0], "topic_filter_1"));
        assert(pkt.p.subscribe.options[0].bits.qos == MQTT_QOS_2);
        assert(pkt.p.subscribe.options[0].bits.nl == 1);
        assert(pkt.p.subscribe.options[0].bits.rap == 0);
        assert(pkt.p.subscribe.options[0].bits.retain_handling == 1);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[1], "topic_filter_2"));
        assert(pkt.p.subscribe.options[1].bits.qos == MQTT_QOS_1);
        assert(pkt.p.subscribe.options[1].bits.nl == 0);
        assert(pkt.p.subscribe.options[1].bits.rap == 1);
        assert(pkt.p.subscribe.options[1].bits.retain_handling == 0);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // suback
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_SUBACK);
        pkt.v.suback.packet_id = 0x05;
        mqtt_suback_generate(&pkt, 2);
        pkt.p.suback.v5.reason_codes[0] = MQTT_RC_TOPIC_FILTER_INVALID;
        pkt.p.suback.v5.reason_codes[1] = MQTT_RC_GRANTED_QOS_1;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_SUBACK);
        assert(pkt.v.suback.packet_id == 0x05);
        assert(pkt.p.suback.n == 2);
        assert(pkt.p.suback.v5.reason_codes[0] == MQTT_RC_TOPIC_FILTER_INVALID);
        assert(pkt.p.suback.v5.reason_codes[1] == MQTT_RC_GRANTED_QOS_1);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // unsubscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_UNSUBSCRIBE);
        pkt.v.unsubscribe.packet_id = 0x22;
        mqtt_unsubscribe_generate(&pkt, 2);
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1");
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_UNSUBSCRIBE);
        assert(pkt.v.unsubscribe.packet_id == 0x22);
        assert(pkt.p.unsubscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1"));
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2"));

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // unsuback
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_UNSUBACK);
        pkt.v.unsuback.packet_id = 0x05;
        mqtt_unsuback_generate(&pkt, 2);
        pkt.p.unsuback.v5.reason_codes[0] = MQTT_RC_TOPIC_FILTER_INVALID;
        pkt.p.unsuback.v5.reason_codes[1] = MQTT_RC_NO_SUBSCRIPTION_EXISTED;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_UNSUBACK);
        assert(pkt.v.unsuback.packet_id == 0x05);
        assert(pkt.p.unsuback.v5.n == 2);
        assert(pkt.p.unsuback.v5.reason_codes[0] == MQTT_RC_TOPIC_FILTER_INVALID);
        assert(pkt.p.unsuback.v5.reason_codes[1] == MQTT_RC_NO_SUBSCRIPTION_EXISTED);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // publish
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBLISH);
        pkt.f.bits.dup = 1;
        pkt.f.bits.qos = MQTT_QOS_2;
        pkt.f.bits.retain = 1;
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        mqtt_str_from(&pkt.p.publish.message, "publish_message");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_PUBLISH);
        assert(pkt.f.bits.dup == 1);
        assert(pkt.f.bits.qos == MQTT_QOS_2);
        assert(pkt.f.bits.retain == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(!mqtt_str_strcmp(&pkt.p.publish.message, "publish_message"));

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // puback
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBACK);
        pkt.v.puback.packet_id = 0x22;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_PUBACK);
        assert(pkt.v.puback.packet_id == 0x22);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pubrec
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBREC);
        pkt.v.puback.packet_id = 0x25;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_PUBREC);
        assert(pkt.v.puback.packet_id == 0x25);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pubrel
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBREL);
        pkt.v.puback.packet_id = 0x23;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_PUBREL);
        assert(pkt.v.puback.packet_id == 0x23);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pubcomp
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBCOMP);
        pkt.v.puback.packet_id = 0x30;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_PUBCOMP);
        assert(pkt.v.puback.packet_id == 0x30);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pingreq
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PINGREQ);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_PINGREQ);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // pingresp
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PINGRESP);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_PINGRESP);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // disconnect
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_DISCONNECT);
        pkt.v.disconnect.v5.reason_code = MQTT_RC_SERVER_BUSY;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_DISCONNECT);
        assert(pkt.v.disconnect.v5.reason_code == MQTT_RC_SERVER_BUSY);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);

        // auth
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_AUTH);
        pkt.f.bits.type = MQTT_AUTH;
        pkt.v.auth.v5.reason_code = MQTT_RC_RE_AUTHENTICATE;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(pkt.f.bits.type == MQTT_AUTH);
        assert(pkt.v.auth.v5.reason_code == MQTT_RC_RE_AUTHENTICATE);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);
    }

    {
        mqtt_str_t bs = MQTT_STR_INITIALIZER;
        mqtt_str_t bp = MQTT_STR_INITIALIZER;
        mqtt_packet_t pkt;
        mqtt_parser_t parser;
        int rc;
        char *s;

        s = malloc(100);
        memset(s, 'K', 100);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.bits.dup = 1;
        pkt.f.bits.qos = MQTT_QOS_2;
        pkt.f.bits.retain = 1;
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        pkt.p.publish.message.n = 100;
        pkt.p.publish.message.s = s;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        // mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PUBLISH);
        assert(pkt.f.bits.dup == 1);
        assert(pkt.f.bits.qos == MQTT_QOS_2);
        assert(pkt.f.bits.retain == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(pkt.p.publish.message.n == 100);
        assert(pkt.p.publish.message.s[0] == 'K');
        assert(pkt.p.publish.message.s[99] == 'K');

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);
        free(s);

        s = malloc(10000);
        memset(s, 'K', 10000);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.bits.dup = 1;
        pkt.f.bits.qos = MQTT_QOS_2;
        pkt.f.bits.retain = 1;
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        pkt.p.publish.message.n = 10000;
        pkt.p.publish.message.s = s;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        // mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PUBLISH);
        assert(pkt.f.bits.dup == 1);
        assert(pkt.f.bits.qos == MQTT_QOS_2);
        assert(pkt.f.bits.retain == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(pkt.p.publish.message.n == 10000);
        assert(pkt.p.publish.message.s[0] == 'K');
        assert(pkt.p.publish.message.s[9999] == 'K');

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);
        free(s);

        s = malloc(2000000);
        memset(s, 'K', 2000000);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.bits.dup = 1;
        pkt.f.bits.qos = MQTT_QOS_2;
        pkt.f.bits.retain = 1;
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        pkt.p.publish.message.n = 2000000;
        pkt.p.publish.message.s = s;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        // mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PUBLISH);
        assert(pkt.f.bits.dup == 1);
        assert(pkt.f.bits.qos == MQTT_QOS_2);
        assert(pkt.f.bits.retain == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(pkt.p.publish.message.n == 2000000);
        assert(pkt.p.publish.message.s[0] == 'K');
        assert(pkt.p.publish.message.s[9999] == 'K');

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);
        free(s);

        s = malloc(26800000);
        memset(s, 'K', 26800000);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.bits.dup = 1;
        pkt.f.bits.qos = MQTT_QOS_2;
        pkt.f.bits.retain = 1;
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        pkt.p.publish.message.n = 26800000;
        pkt.p.publish.message.s = s;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_unit(&pkt);
        assert(rc == 0);

        // mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(pkt.f.bits.type == MQTT_PUBLISH);
        assert(pkt.f.bits.dup == 1);
        assert(pkt.f.bits.qos == MQTT_QOS_2);
        assert(pkt.f.bits.retain == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(pkt.p.publish.message.n == 26800000);
        assert(pkt.p.publish.message.s[0] == 'K');
        assert(pkt.p.publish.message.s[9999] == 'K');

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);

        mqtt_str_free(&bs);
        free(s);
    }

    {
        mqtt_str_t bp = MQTT_STR_INITIALIZER;
        mqtt_packet_t pkt;
        mqtt_parser_t parser;
        int rc;

        char s[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
        mqtt_str_init(&bp, s, 15);

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == -1);

        mqtt_packet_unit(&pkt);
        mqtt_parser_unit(&parser);
    }
}

static void
test_mqtt_sn() {
    mqtt_str_t bs = MQTT_STR_INITIALIZER;
    mqtt_str_t bp = MQTT_STR_INITIALIZER;
    mqtt_sn_packet_t pkt;
    mqtt_sn_parser_t parser;
    int rc;

    // connect
    mqtt_sn_packet_init(&pkt, MQTT_SN_CONNECT);
    pkt.v.connect.flags.bits.will = 1;
    pkt.v.connect.flags.bits.clean_session = 1;
    pkt.v.connect.protocol_id = MQTT_SN_PROTOCOL_VERSION;
    mqtt_str_from(&pkt.v.connect.client_id, "mqtt_sn_client_id");
    pkt.v.connect.duration = 900;
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_CONNECT);
    assert(pkt.v.connect.flags.bits.will == 1);
    assert(pkt.v.connect.flags.bits.clean_session == 1);
    assert(pkt.v.connect.protocol_id == MQTT_SN_PROTOCOL_VERSION);
    assert(!mqtt_str_strcmp(&pkt.v.connect.client_id, "mqtt_sn_client_id"));
    assert(pkt.v.connect.duration == 900);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // connack
    mqtt_sn_packet_init(&pkt, MQTT_SN_CONNACK);
    pkt.v.connack.return_code = MQTT_SN_RC_REJECTED_NOT_SUPPORTED;
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_CONNACK);
    assert(pkt.v.connack.return_code == MQTT_SN_RC_REJECTED_NOT_SUPPORTED);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // subscribe
    mqtt_sn_packet_init(&pkt, MQTT_SN_SUBSCRIBE);
    pkt.v.subscribe.flags.bits.qos = MQTT_SN_QOS_2;
    pkt.v.subscribe.flags.bits.topic_id_type = MQTT_SN_TOPIC_ID_TYPE_PREDEFINED;
    pkt.v.subscribe.msg_id = 0x10;
    pkt.v.subscribe.topic.id = 0x20;
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_SUBSCRIBE);
    assert(pkt.v.subscribe.flags.bits.qos == MQTT_SN_QOS_2);
    assert(pkt.v.subscribe.flags.bits.topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED);
    assert(pkt.v.subscribe.msg_id == 0x10);
    assert(pkt.v.subscribe.topic.id == 0x20);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // suback
    mqtt_sn_packet_init(&pkt, MQTT_SN_SUBACK);
    pkt.v.suback.flags.bits.qos = MQTT_SN_QOS_1;
    pkt.v.suback.msg_id = 0x30;
    pkt.v.suback.return_code = MQTT_SN_RC_REJECTED_TOPIC_ID;
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_SUBACK);
    assert(pkt.v.suback.flags.bits.qos == MQTT_SN_QOS_1);
    assert(pkt.v.suback.msg_id == 0x30);
    assert(pkt.v.suback.return_code == MQTT_SN_RC_REJECTED_TOPIC_ID);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // unsubscribe
    mqtt_sn_packet_init(&pkt, MQTT_SN_UNSUBSCRIBE);
    pkt.v.unsubscribe.flags.bits.topic_id_type = MQTT_SN_TOPIC_ID_TYPE_SHORT;
    pkt.v.unsubscribe.msg_id = 0x40;
    pkt.v.unsubscribe.topic.shor[0] = 'A';
    pkt.v.unsubscribe.topic.shor[1] = 'B';
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_UNSUBSCRIBE);
    assert(pkt.v.unsubscribe.flags.bits.topic_id_type == MQTT_SN_TOPIC_ID_TYPE_SHORT);
    assert(pkt.v.unsubscribe.msg_id == 0x40);
    assert(pkt.v.unsubscribe.topic.shor[0] == 'A');
    assert(pkt.v.unsubscribe.topic.shor[1] == 'B');

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // unsuback
    mqtt_sn_packet_init(&pkt, MQTT_SN_UNSUBACK);
    pkt.v.unsuback.msg_id = 0x50;
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_UNSUBACK);
    assert(pkt.v.unsuback.msg_id == 0x50);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // publish
    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBLISH);
    pkt.v.publish.flags.bits.dup = 1;
    pkt.v.publish.flags.bits.qos = MQTT_SN_QOS_1;
    pkt.v.publish.flags.bits.topic_id_type = MQTT_SN_TOPIC_ID_TYPE_PREDEFINED;
    pkt.v.publish.msg_id = 0x22;
    pkt.v.publish.topic.id = 0x12;
    mqtt_str_from(&pkt.v.publish.data, "mqtt_sn_publish");
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_PUBLISH);
    assert(pkt.v.publish.flags.bits.dup == 1);
    assert(pkt.v.publish.flags.bits.qos == MQTT_SN_QOS_1);
    assert(pkt.v.publish.flags.bits.topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED);
    assert(pkt.v.publish.msg_id == 0x22);
    assert(pkt.v.publish.topic.id == 0x12);
    assert(!mqtt_str_strcmp(&pkt.v.publish.data, "mqtt_sn_publish"));

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // puback
    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBACK);
    pkt.v.puback.msg_id = 0x11;
    pkt.v.puback.return_code = MQTT_SN_RC_ACCEPTED;
    pkt.v.puback.topic.id = 0x12;
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_PUBACK);
    assert(pkt.v.puback.msg_id == 0x11);
    assert(pkt.v.puback.return_code == MQTT_SN_RC_ACCEPTED);
    assert(pkt.v.puback.topic.id == 0x12);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // pubrec
    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBREC);
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_PUBREC);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // pubrel
    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBREL);
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_PUBREL);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // pubcomp
    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBCOMP);
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_PUBCOMP);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // pingreq
    mqtt_sn_packet_init(&pkt, MQTT_SN_PINGREQ);
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_PINGREQ);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // pingresp
    mqtt_sn_packet_init(&pkt, MQTT_SN_PINGRESP);
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_PINGRESP);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // disconnect
    mqtt_sn_packet_init(&pkt, MQTT_SN_DISCONNECT);
    pkt.v.disconnect.duration = 600;
    mqtt_sn_serialize(&pkt, &bs);

    mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_DISCONNECT);
    assert(pkt.v.disconnect.duration == 600);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    // test length

    char *s;

    s = malloc(65000);
    memset(s, 'K', 65000);

    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBLISH);
    pkt.v.publish.flags.bits.dup = 1;
    pkt.v.publish.flags.bits.qos = MQTT_SN_QOS_1;
    pkt.v.publish.flags.bits.topic_id_type = MQTT_SN_TOPIC_ID_TYPE_PREDEFINED;
    pkt.v.publish.msg_id = 0x22;
    pkt.v.publish.topic.id = 0x12;
    pkt.v.publish.data.s = s;
    pkt.v.publish.data.n = 65000;
    mqtt_sn_serialize(&pkt, &bs);

    // mqtt_str_dump(&bs, 0, 0);
    mqtt_str_set(&bp, &bs);
    bp.i = 0;

    mqtt_sn_parser_init(&parser);
    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    assert(rc == 1);
    assert(pkt.type == MQTT_SN_PUBLISH);
    assert(pkt.v.publish.flags.bits.dup == 1);
    assert(pkt.v.publish.flags.bits.qos == MQTT_SN_QOS_1);
    assert(pkt.v.publish.flags.bits.topic_id_type == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED);
    assert(pkt.v.publish.msg_id == 0x22);
    assert(pkt.v.publish.topic.id == 0x12);
    pkt.v.publish.data.n = 65000;

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);

    mqtt_str_free(&bs);

    free(s);
}

static void
test_mqtt_random() {
    mqtt_str_t bp = MQTT_STR_INITIALIZER;
    mqtt_packet_t pkt;
    mqtt_parser_t parser;
    int rc;

    srand(time(NULL));
    size_t data_len = rand() % 1000 + 1;

    char *random_data = malloc(data_len);
    if (!random_data) {
        printf("Failed to allocate memory for random data\n");
        return;
    }

    for (size_t i = 0; i < data_len; i++) {
        random_data[i] = (char)(rand() % 256);
    }

    mqtt_str_init(&bp, random_data, data_len);
    bp.i = 0;

    memset(&pkt, 0, sizeof(pkt));

    mqtt_parser_init(&parser);

    rc = mqtt_parse(&parser, &bp, &pkt);

    printf("Random data test:\n");
    printf("  Data length: %zu\n", data_len);
    printf("  Parse result: %d\n", rc);

    mqtt_packet_unit(&pkt);
    mqtt_parser_unit(&parser);
    free(random_data);
}

static void
test_mqtt_sn_random() {
    mqtt_str_t bp = MQTT_STR_INITIALIZER;
    mqtt_sn_packet_t pkt;
    mqtt_sn_parser_t parser;
    int rc;

    srand(time(NULL));
    size_t data_len = rand() % 1000 + 1;

    char *random_data = malloc(data_len);
    if (!random_data) {
        printf("Failed to allocate memory for random data\n");
        return;
    }

    for (size_t i = 0; i < data_len; i++) {
        random_data[i] = (char)(rand() % 256);
    }

    mqtt_str_init(&bp, random_data, data_len);
    bp.i = 0;

    memset(&pkt, 0, sizeof(pkt));

    mqtt_sn_parser_init(&parser);

    rc = mqtt_sn_parse(&parser, &bp, &pkt);

    printf("Random data test:\n");
    printf("  Data length: %zu\n", data_len);
    printf("  Parse result: %d\n", rc);

    mqtt_sn_packet_unit(&pkt);
    mqtt_sn_parser_unit(&parser);
    free(random_data);
}

int
main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    test_mqtt();
    test_mqtt_sn();

    for (int i = 0; i < 100; i++) {
        test_mqtt_random();
    }

    for (int i = 0; i < 100; i++) {
        test_mqtt_sn_random();
    }

    return 0;
}
