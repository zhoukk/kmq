#define MQTT_IMPL
#include "mqtt.h"

#include <assert.h>
#include <time.h>

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
        pkt.v.connect.connect_flags |= MQTT_CF_CLEAN_SESSION;
        pkt.v.connect.connect_flags |= MQTT_CF_WILL_FLAG;
        pkt.v.connect.connect_flags |= (uint8_t)(((MQTT_QOS_1) & 0x03) << 3);
        pkt.v.connect.connect_flags |= MQTT_CF_WILL_RETAIN;
        pkt.v.connect.connect_flags |= MQTT_CF_USERNAME;
        pkt.v.connect.connect_flags |= MQTT_CF_PASSWORD;
        mqtt_str_from(&pkt.p.connect.will_topic, "hello");
        mqtt_str_from(&pkt.p.connect.will_message, "world");
        mqtt_str_from(&pkt.p.connect.client_id, "mqtt");
        mqtt_str_from(&pkt.p.connect.username, "username");
        mqtt_str_from(&pkt.p.connect.password, "password");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_CONNECT);
        assert(pkt.v.connect.protocol_version == MQTT_VERSION_3);
        assert(!mqtt_str_strcmp(&pkt.v.connect.protocol_name, mqtt_protocol_name(MQTT_VERSION_3)));
        assert((pkt.v.connect.connect_flags & MQTT_CF_CLEAN_SESSION) != 0);
        assert((pkt.v.connect.connect_flags & MQTT_CF_WILL_FLAG) != 0);
        assert(MQTT_CF_WILL_QOS(pkt.v.connect.connect_flags) == MQTT_QOS_1);
        assert((pkt.v.connect.connect_flags & MQTT_CF_WILL_RETAIN) != 0);
        assert((pkt.v.connect.connect_flags & MQTT_CF_USERNAME) != 0);
        assert((pkt.v.connect.connect_flags & MQTT_CF_PASSWORD) != 0);
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_topic, "hello"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_message, "world"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.client_id, "mqtt"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.username, "username"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.password, "password"));

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // connack
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_CONNACK);
        pkt.v.connack.v3.return_code = MQTT_CRC_ACCEPTED;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_CONNACK);
        assert(pkt.v.connack.v3.return_code == MQTT_CRC_ACCEPTED);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // subscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_SUBSCRIBE);
        pkt.v.subscribe.packet_id = 0x03;
        mqtt_subscribe_generate(&pkt, 2);
        pkt.p.subscribe.options[0].flags = (uint8_t)((pkt.p.subscribe.options[0].flags & ~MQTT_SUBOPT_QOS_MASK) | ((MQTT_QOS_2) & MQTT_SUBOPT_QOS_MASK));
        mqtt_str_from(&pkt.p.subscribe.topic_filters[0], "topic_filter_1");
        pkt.p.subscribe.options[1].flags = (uint8_t)((pkt.p.subscribe.options[1].flags & ~MQTT_SUBOPT_QOS_MASK) | ((MQTT_QOS_1) & MQTT_SUBOPT_QOS_MASK));
        mqtt_str_from(&pkt.p.subscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_SUBSCRIBE);
        assert(pkt.v.subscribe.packet_id == 0x03);
        assert(pkt.p.subscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[0], "topic_filter_1"));
        assert((pkt.p.subscribe.options[0].flags& MQTT_SUBOPT_QOS_MASK) == MQTT_QOS_2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[1], "topic_filter_2"));
        assert((pkt.p.subscribe.options[1].flags& MQTT_SUBOPT_QOS_MASK) == MQTT_QOS_1);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // suback
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_SUBACK);
        pkt.v.suback.packet_id = 0x05;
        mqtt_suback_generate(&pkt, 2);
        pkt.p.suback.v3.granted[0].flags = (uint8_t)((pkt.p.suback.v3.granted[0].flags & ~MQTT_SUBOPT_QOS_MASK) | ((MQTT_QOS_0) & MQTT_SUBOPT_QOS_MASK));
        pkt.p.suback.v3.granted[1].flags = (uint8_t)((pkt.p.suback.v3.granted[1].flags & ~MQTT_SUBOPT_QOS_MASK) | ((MQTT_QOS_2) & MQTT_SUBOPT_QOS_MASK));
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_SUBACK);
        assert(pkt.v.suback.packet_id == 0x05);
        assert(pkt.p.suback.n == 2);
        assert((pkt.p.suback.v3.granted[0].flags& MQTT_SUBOPT_QOS_MASK) == MQTT_QOS_0);
        assert((pkt.p.suback.v3.granted[1].flags& MQTT_SUBOPT_QOS_MASK) == MQTT_QOS_2);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // unsubscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_UNSUBSCRIBE);
        pkt.v.unsubscribe.packet_id = 0x22;
        mqtt_unsubscribe_generate(&pkt, 2);
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1");
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_UNSUBSCRIBE);
        assert(pkt.v.unsubscribe.packet_id == 0x22);
        assert(pkt.p.unsubscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1"));
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2"));

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // unsuback
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_UNSUBACK);
        pkt.v.unsuback.packet_id = 0x05;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_UNSUBACK);
        assert(pkt.v.unsuback.packet_id == 0x05);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // publish
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, MQTT_QOS_2, 1);
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        mqtt_str_from(&pkt.p.publish.message, "publish_message");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBLISH);
        assert(MQTT_FH_DUP(pkt.f.flags) == 1);
        assert(MQTT_FH_QOS(pkt.f.flags) == MQTT_QOS_2);
        assert(MQTT_FH_RETAIN(pkt.f.flags) == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(!mqtt_str_strcmp(&pkt.p.publish.message, "publish_message"));

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // puback
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBACK);
        pkt.v.puback.packet_id = 0x22;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBACK);
        assert(pkt.v.puback.packet_id == 0x22);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pubrec
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBREC);
        pkt.v.puback.packet_id = 0x25;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBREC);
        assert(pkt.v.puback.packet_id == 0x25);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pubrel
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBREL);
        pkt.v.puback.packet_id = 0x23;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBREL);
        assert(pkt.v.puback.packet_id == 0x23);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pubcomp
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBCOMP);
        pkt.v.puback.packet_id = 0x30;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBCOMP);
        assert(pkt.v.puback.packet_id == 0x30);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pingreq
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PINGREQ);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PINGREQ);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pingresp
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PINGRESP);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PINGRESP);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // disconnect
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_DISCONNECT);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_DISCONNECT);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

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
        pkt.v.connect.connect_flags |= MQTT_CF_CLEAN_SESSION;
        pkt.v.connect.connect_flags |= MQTT_CF_WILL_FLAG;
        pkt.v.connect.connect_flags |= (uint8_t)(((MQTT_QOS_1) & 0x03) << 3);
        pkt.v.connect.connect_flags |= MQTT_CF_WILL_RETAIN;
        pkt.v.connect.connect_flags |= MQTT_CF_USERNAME;
        pkt.v.connect.connect_flags |= MQTT_CF_PASSWORD;
        mqtt_str_from(&pkt.p.connect.will_topic, "hello");
        mqtt_str_from(&pkt.p.connect.will_message, "world");
        mqtt_str_from(&pkt.p.connect.client_id, "mqtt");
        mqtt_str_from(&pkt.p.connect.username, "username");
        mqtt_str_from(&pkt.p.connect.password, "password");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_CONNECT);
        assert(pkt.v.connect.protocol_version == MQTT_VERSION_4);
        assert(!mqtt_str_strcmp(&pkt.v.connect.protocol_name, mqtt_protocol_name(MQTT_VERSION_4)));
        assert((pkt.v.connect.connect_flags & MQTT_CF_CLEAN_SESSION) != 0);
        assert((pkt.v.connect.connect_flags & MQTT_CF_WILL_FLAG) != 0);
        assert(MQTT_CF_WILL_QOS(pkt.v.connect.connect_flags) == MQTT_QOS_1);
        assert((pkt.v.connect.connect_flags & MQTT_CF_WILL_RETAIN) != 0);
        assert((pkt.v.connect.connect_flags & MQTT_CF_USERNAME) != 0);
        assert((pkt.v.connect.connect_flags & MQTT_CF_PASSWORD) != 0);
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_topic, "hello"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.will_message, "world"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.client_id, "mqtt"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.username, "username"));
        assert(!mqtt_str_strcmp(&pkt.p.connect.password, "password"));

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // connack
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_CONNACK);
        pkt.v.connack.v4.acknowledge_flags.flags |= MQTT_ACK_SESSION_PRESENT;
        pkt.v.connack.v4.return_code = MQTT_CRC_ACCEPTED;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_CONNACK);
        assert((pkt.v.connack.v4.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT) != 0);
        assert(pkt.v.connack.v4.return_code == MQTT_CRC_ACCEPTED);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // subscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_SUBSCRIBE);
        pkt.v.subscribe.packet_id = 0x03;
        mqtt_subscribe_generate(&pkt, 2);
        pkt.p.subscribe.options[0].flags = (uint8_t)((pkt.p.subscribe.options[0].flags & ~MQTT_SUBOPT_QOS_MASK) | ((MQTT_QOS_2) & MQTT_SUBOPT_QOS_MASK));
        mqtt_str_from(&pkt.p.subscribe.topic_filters[0], "topic_filter_1");
        pkt.p.subscribe.options[1].flags = (uint8_t)((pkt.p.subscribe.options[1].flags & ~MQTT_SUBOPT_QOS_MASK) | ((MQTT_QOS_1) & MQTT_SUBOPT_QOS_MASK));
        mqtt_str_from(&pkt.p.subscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_SUBSCRIBE);
        assert(pkt.v.subscribe.packet_id == 0x03);
        assert(pkt.p.subscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[0], "topic_filter_1"));
        assert((pkt.p.subscribe.options[0].flags& MQTT_SUBOPT_QOS_MASK) == MQTT_QOS_2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[1], "topic_filter_2"));
        assert((pkt.p.subscribe.options[1].flags& MQTT_SUBOPT_QOS_MASK) == MQTT_QOS_1);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // suback
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_SUBACK);
        pkt.v.suback.packet_id = 0x05;
        mqtt_suback_generate(&pkt, 2);
        pkt.p.suback.v4.return_codes[0] = MQTT_SRC_QOS_1;
        pkt.p.suback.v4.return_codes[1] = MQTT_SRC_QOS_F;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_SUBACK);
        assert(pkt.v.suback.packet_id == 0x05);
        assert(pkt.p.suback.n == 2);
        assert(pkt.p.suback.v4.return_codes[0] == MQTT_SRC_QOS_1);
        assert(pkt.p.suback.v4.return_codes[1] == MQTT_SRC_QOS_F);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // unsubscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_UNSUBSCRIBE);
        pkt.v.unsubscribe.packet_id = 0x22;
        mqtt_unsubscribe_generate(&pkt, 2);
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1");
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_UNSUBSCRIBE);
        assert(pkt.v.unsubscribe.packet_id == 0x22);
        assert(pkt.p.unsubscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1"));
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2"));

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // unsuback
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_UNSUBACK);
        pkt.v.unsuback.packet_id = 0x05;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_UNSUBACK);
        assert(pkt.v.unsuback.packet_id == 0x05);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // publish
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBLISH);
        pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, MQTT_QOS_2, 1);
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        mqtt_str_from(&pkt.p.publish.message, "publish_message");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBLISH);
        assert(MQTT_FH_DUP(pkt.f.flags) == 1);
        assert(MQTT_FH_QOS(pkt.f.flags) == MQTT_QOS_2);
        assert(MQTT_FH_RETAIN(pkt.f.flags) == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(!mqtt_str_strcmp(&pkt.p.publish.message, "publish_message"));

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // puback
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBACK);
        pkt.v.puback.packet_id = 0x22;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBACK);
        assert(pkt.v.puback.packet_id == 0x22);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pubrec
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBREC);
        pkt.v.puback.packet_id = 0x25;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBREC);
        assert(pkt.v.puback.packet_id == 0x25);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pubrel
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBREL);
        pkt.v.puback.packet_id = 0x23;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBREL);
        assert(pkt.v.puback.packet_id == 0x23);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pubcomp
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PUBCOMP);
        pkt.v.puback.packet_id = 0x30;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBCOMP);
        assert(pkt.v.puback.packet_id == 0x30);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pingreq
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PINGREQ);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PINGREQ);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pingresp
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_PINGRESP);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PINGRESP);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // disconnect
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_DISCONNECT);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_4);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_4);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_DISCONNECT);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

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
        pkt.v.connect.connect_flags |= MQTT_CF_CLEAN_SESSION;
        pkt.v.connect.connect_flags |= MQTT_CF_WILL_FLAG;
        pkt.v.connect.connect_flags |= (uint8_t)(((MQTT_QOS_2) & 0x03) << 3);
        pkt.v.connect.connect_flags |= MQTT_CF_WILL_RETAIN;
        pkt.v.connect.connect_flags |= MQTT_CF_USERNAME;
        pkt.v.connect.connect_flags |= MQTT_CF_PASSWORD;
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
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_CONNECT);
        assert(pkt.v.connect.protocol_version == MQTT_VERSION_5);
        assert(!mqtt_str_strcmp(&pkt.v.connect.protocol_name, mqtt_protocol_name(MQTT_VERSION_5)));
        assert((pkt.v.connect.connect_flags & MQTT_CF_CLEAN_SESSION) != 0);
        assert((pkt.v.connect.connect_flags & MQTT_CF_WILL_FLAG) != 0);
        assert(MQTT_CF_WILL_QOS(pkt.v.connect.connect_flags) == MQTT_QOS_2);
        assert((pkt.v.connect.connect_flags & MQTT_CF_WILL_RETAIN) != 0);
        assert((pkt.v.connect.connect_flags & MQTT_CF_USERNAME) != 0);
        assert((pkt.v.connect.connect_flags & MQTT_CF_PASSWORD) != 0);
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

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // connack
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_CONNACK);
        pkt.v.connack.v5.acknowledge_flags.flags |= MQTT_ACK_SESSION_PRESENT;
        pkt.v.connack.v5.reason_code = MQTT_RC_BAD_AUTHENTICATION_METHOD;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_CONNACK);
        assert((pkt.v.connack.v5.acknowledge_flags.flags & MQTT_ACK_SESSION_PRESENT) != 0);
        assert(pkt.v.connack.v5.reason_code == MQTT_RC_BAD_AUTHENTICATION_METHOD);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // subscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_SUBSCRIBE);
        pkt.v.subscribe.packet_id = 0x03;
        mqtt_subscribe_generate(&pkt, 2);
        pkt.p.subscribe.options[0].flags = (uint8_t)((pkt.p.subscribe.options[0].flags & ~MQTT_SUBOPT_QOS_MASK) | ((MQTT_QOS_2) & MQTT_SUBOPT_QOS_MASK));
        pkt.p.subscribe.options[0].flags |= MQTT_SUBOPT_NL;
        pkt.p.subscribe.options[0].flags &= (uint8_t)~MQTT_SUBOPT_RAP;
        pkt.p.subscribe.options[0].flags = (uint8_t)((pkt.p.subscribe.options[0].flags & ~MQTT_SUBOPT_RH_MASK) | (((1) << 4) & MQTT_SUBOPT_RH_MASK));
        mqtt_str_from(&pkt.p.subscribe.topic_filters[0], "topic_filter_1");
        pkt.p.subscribe.options[1].flags = (uint8_t)((pkt.p.subscribe.options[1].flags & ~MQTT_SUBOPT_QOS_MASK) | ((MQTT_QOS_1) & MQTT_SUBOPT_QOS_MASK));
        pkt.p.subscribe.options[1].flags &= (uint8_t)~MQTT_SUBOPT_NL;
        pkt.p.subscribe.options[1].flags |= MQTT_SUBOPT_RAP;
        pkt.p.subscribe.options[1].flags = (uint8_t)((pkt.p.subscribe.options[1].flags & ~MQTT_SUBOPT_RH_MASK) | (((0) << 4) & MQTT_SUBOPT_RH_MASK));
        mqtt_str_from(&pkt.p.subscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_SUBSCRIBE);
        assert(pkt.v.subscribe.packet_id == 0x03);
        assert(pkt.p.subscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[0], "topic_filter_1"));
        assert((pkt.p.subscribe.options[0].flags& MQTT_SUBOPT_QOS_MASK) == MQTT_QOS_2);
        assert((pkt.p.subscribe.options[0].flags & MQTT_SUBOPT_NL) != 0);
        assert((pkt.p.subscribe.options[0].flags& MQTT_SUBOPT_RAP) == 0);
        assert(MQTT_SUBOPT_RH(pkt.p.subscribe.options[0].flags) == 1);
        assert(!mqtt_str_strcmp(&pkt.p.subscribe.topic_filters[1], "topic_filter_2"));
        assert((pkt.p.subscribe.options[1].flags& MQTT_SUBOPT_QOS_MASK) == MQTT_QOS_1);
        assert((pkt.p.subscribe.options[1].flags& MQTT_SUBOPT_NL) == 0);
        assert((pkt.p.subscribe.options[1].flags & MQTT_SUBOPT_RAP) != 0);
        assert(MQTT_SUBOPT_RH(pkt.p.subscribe.options[1].flags) == 0);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // suback
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_SUBACK);
        pkt.v.suback.packet_id = 0x05;
        mqtt_suback_generate(&pkt, 2);
        pkt.p.suback.v5.reason_codes[0] = MQTT_RC_TOPIC_FILTER_INVALID;
        pkt.p.suback.v5.reason_codes[1] = MQTT_RC_GRANTED_QOS_1;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_SUBACK);
        assert(pkt.v.suback.packet_id == 0x05);
        assert(pkt.p.suback.n == 2);
        assert(pkt.p.suback.v5.reason_codes[0] == MQTT_RC_TOPIC_FILTER_INVALID);
        assert(pkt.p.suback.v5.reason_codes[1] == MQTT_RC_GRANTED_QOS_1);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // unsubscribe
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_UNSUBSCRIBE);
        pkt.v.unsubscribe.packet_id = 0x22;
        mqtt_unsubscribe_generate(&pkt, 2);
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1");
        mqtt_str_from(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_UNSUBSCRIBE);
        assert(pkt.v.unsubscribe.packet_id == 0x22);
        assert(pkt.p.unsubscribe.n == 2);
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[0], "topic_filter_1"));
        assert(!mqtt_str_strcmp(&pkt.p.unsubscribe.topic_filters[1], "topic_filter_2"));

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // unsuback
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_UNSUBACK);
        pkt.v.unsuback.packet_id = 0x05;
        mqtt_unsuback_generate(&pkt, 2);
        pkt.p.unsuback.v5.reason_codes[0] = MQTT_RC_TOPIC_FILTER_INVALID;
        pkt.p.unsuback.v5.reason_codes[1] = MQTT_RC_NO_SUBSCRIPTION_EXISTED;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_UNSUBACK);
        assert(pkt.v.unsuback.packet_id == 0x05);
        assert(pkt.p.unsuback.v5.n == 2);
        assert(pkt.p.unsuback.v5.reason_codes[0] == MQTT_RC_TOPIC_FILTER_INVALID);
        assert(pkt.p.unsuback.v5.reason_codes[1] == MQTT_RC_NO_SUBSCRIPTION_EXISTED);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // publish
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBLISH);
        pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, MQTT_QOS_2, 1);
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        mqtt_str_from(&pkt.p.publish.message, "publish_message");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBLISH);
        assert(MQTT_FH_DUP(pkt.f.flags) == 1);
        assert(MQTT_FH_QOS(pkt.f.flags) == MQTT_QOS_2);
        assert(MQTT_FH_RETAIN(pkt.f.flags) == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(!mqtt_str_strcmp(&pkt.p.publish.message, "publish_message"));

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // puback
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBACK);
        pkt.v.puback.packet_id = 0x22;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBACK);
        assert(pkt.v.puback.packet_id == 0x22);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pubrec
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBREC);
        pkt.v.puback.packet_id = 0x25;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBREC);
        assert(pkt.v.puback.packet_id == 0x25);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pubrel
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBREL);
        pkt.v.puback.packet_id = 0x23;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBREL);
        assert(pkt.v.puback.packet_id == 0x23);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pubcomp
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBCOMP);
        pkt.v.puback.packet_id = 0x30;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBCOMP);
        assert(pkt.v.puback.packet_id == 0x30);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pingreq
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PINGREQ);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PINGREQ);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // pingresp
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PINGRESP);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PINGRESP);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // disconnect
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_DISCONNECT);
        pkt.v.disconnect.v5.reason_code = MQTT_RC_SERVER_BUSY;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_DISCONNECT);
        assert(pkt.v.disconnect.v5.reason_code == MQTT_RC_SERVER_BUSY);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);

        // auth
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_AUTH);
        pkt.f.flags = MQTT_FH_BUILD(MQTT_AUTH, 0, 0, 0);
        pkt.v.auth.v5.reason_code = MQTT_RC_RE_AUTHENTICATE;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_5);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_AUTH);
        assert(pkt.v.auth.v5.reason_code == MQTT_RC_RE_AUTHENTICATE);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

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
        pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, MQTT_QOS_2, 1);
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        pkt.p.publish.message.n = 100;
        pkt.p.publish.message.s = s;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        // mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBLISH);
        assert(MQTT_FH_DUP(pkt.f.flags) == 1);
        assert(MQTT_FH_QOS(pkt.f.flags) == MQTT_QOS_2);
        assert(MQTT_FH_RETAIN(pkt.f.flags) == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(pkt.p.publish.message.n == 100);
        assert(pkt.p.publish.message.s[0] == 'K');
        assert(pkt.p.publish.message.s[99] == 'K');

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);
        free(s);

        s = malloc(10000);
        memset(s, 'K', 10000);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, MQTT_QOS_2, 1);
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        pkt.p.publish.message.n = 10000;
        pkt.p.publish.message.s = s;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        // mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBLISH);
        assert(MQTT_FH_DUP(pkt.f.flags) == 1);
        assert(MQTT_FH_QOS(pkt.f.flags) == MQTT_QOS_2);
        assert(MQTT_FH_RETAIN(pkt.f.flags) == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(pkt.p.publish.message.n == 10000);
        assert(pkt.p.publish.message.s[0] == 'K');
        assert(pkt.p.publish.message.s[9999] == 'K');

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);
        free(s);

        s = malloc(2000000);
        memset(s, 'K', 2000000);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, MQTT_QOS_2, 1);
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        pkt.p.publish.message.n = 2000000;
        pkt.p.publish.message.s = s;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        // mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBLISH);
        assert(MQTT_FH_DUP(pkt.f.flags) == 1);
        assert(MQTT_FH_QOS(pkt.f.flags) == MQTT_QOS_2);
        assert(MQTT_FH_RETAIN(pkt.f.flags) == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(pkt.p.publish.message.n == 2000000);
        assert(pkt.p.publish.message.s[0] == 'K');
        assert(pkt.p.publish.message.s[9999] == 'K');

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

        mqtt_str_free(&bs);
        free(s);

        s = malloc(26800000);
        memset(s, 'K', 26800000);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 1, MQTT_QOS_2, 1);
        pkt.v.publish.packet_id = 0x12;
        mqtt_str_from(&pkt.v.publish.topic_name, "publish_topic");
        pkt.p.publish.message.n = 26800000;
        pkt.p.publish.message.s = s;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);

        // mqtt_str_dump(&bs, 0, 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == 1);
        assert(pkt.ver == MQTT_VERSION_3);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PUBLISH);
        assert(MQTT_FH_DUP(pkt.f.flags) == 1);
        assert(MQTT_FH_QOS(pkt.f.flags) == MQTT_QOS_2);
        assert(MQTT_FH_RETAIN(pkt.f.flags) == 1);
        assert(pkt.v.publish.packet_id == 0x12);
        assert(!mqtt_str_strcmp(&pkt.v.publish.topic_name, "publish_topic"));
        assert(pkt.p.publish.message.n == 26800000);
        assert(pkt.p.publish.message.s[0] == 'K');
        assert(pkt.p.publish.message.s[9999] == 'K');

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);

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

        memset(&pkt, 0, sizeof(pkt));

        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);

        assert(rc == -1);

        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);
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
    pkt.v.connect.flags.flag |= MQTT_SNF_WILL;
    pkt.v.connect.flags.flag |= MQTT_SNF_CLEAN_SESSION;
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
    assert((pkt.v.connect.flags.flag & MQTT_SNF_WILL) != 0);
    assert((pkt.v.connect.flags.flag & MQTT_SNF_CLEAN_SESSION) != 0);
    assert(pkt.v.connect.protocol_id == MQTT_SN_PROTOCOL_VERSION);
    assert(!mqtt_str_strcmp(&pkt.v.connect.client_id, "mqtt_sn_client_id"));
    assert(pkt.v.connect.duration == 900);

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

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

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

    mqtt_str_free(&bs);

    // subscribe
    mqtt_sn_packet_init(&pkt, MQTT_SN_SUBSCRIBE);
    pkt.v.subscribe.flags.flag |= (((MQTT_SN_QOS_2) << 5) & MQTT_SNF_QOS_MASK);
    pkt.v.subscribe.flags.flag |= ((MQTT_SN_TOPIC_ID_TYPE_PREDEFINED) & MQTT_SNF_TID_TYPE_MASK);
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
    assert(MQTT_SNF_QOS(pkt.v.subscribe.flags.flag) == MQTT_SN_QOS_2);
    assert(MQTT_SNF_TID_TYPE(pkt.v.subscribe.flags.flag) == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED);
    assert(pkt.v.subscribe.msg_id == 0x10);
    assert(pkt.v.subscribe.topic.id == 0x20);

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

    mqtt_str_free(&bs);

    // suback
    mqtt_sn_packet_init(&pkt, MQTT_SN_SUBACK);
    pkt.v.suback.flags.flag |= (((MQTT_SN_QOS_1) << 5) & MQTT_SNF_QOS_MASK);
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
    assert(MQTT_SNF_QOS(pkt.v.suback.flags.flag) == MQTT_SN_QOS_1);
    assert(pkt.v.suback.msg_id == 0x30);
    assert(pkt.v.suback.return_code == MQTT_SN_RC_REJECTED_TOPIC_ID);

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

    mqtt_str_free(&bs);

    // unsubscribe
    mqtt_sn_packet_init(&pkt, MQTT_SN_UNSUBSCRIBE);
    pkt.v.unsubscribe.flags.flag |= ((MQTT_SN_TOPIC_ID_TYPE_SHORT) & MQTT_SNF_TID_TYPE_MASK);
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
    assert(MQTT_SNF_TID_TYPE(pkt.v.unsubscribe.flags.flag) == MQTT_SN_TOPIC_ID_TYPE_SHORT);
    assert(pkt.v.unsubscribe.msg_id == 0x40);
    assert(pkt.v.unsubscribe.topic.shor[0] == 'A');
    assert(pkt.v.unsubscribe.topic.shor[1] == 'B');

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

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

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

    mqtt_str_free(&bs);

    // publish
    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBLISH);
    pkt.v.publish.flags.flag |= MQTT_SNF_DUP;
    pkt.v.publish.flags.flag |= (((MQTT_SN_QOS_1) << 5) & MQTT_SNF_QOS_MASK);
    pkt.v.publish.flags.flag |= ((MQTT_SN_TOPIC_ID_TYPE_PREDEFINED) & MQTT_SNF_TID_TYPE_MASK);
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
    assert((pkt.v.publish.flags.flag & MQTT_SNF_DUP) != 0);
    assert(MQTT_SNF_QOS(pkt.v.publish.flags.flag) == MQTT_SN_QOS_1);
    assert(MQTT_SNF_TID_TYPE(pkt.v.publish.flags.flag) == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED);
    assert(pkt.v.publish.msg_id == 0x22);
    assert(pkt.v.publish.topic.id == 0x12);
    assert(!mqtt_str_strcmp(&pkt.v.publish.data, "mqtt_sn_publish"));

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

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

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

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

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

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

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

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

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

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

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

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

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

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

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

    mqtt_str_free(&bs);

    // test length

    char *s;

    s = malloc(65000);
    memset(s, 'K', 65000);

    mqtt_sn_packet_init(&pkt, MQTT_SN_PUBLISH);
    pkt.v.publish.flags.flag |= MQTT_SNF_DUP;
    pkt.v.publish.flags.flag |= (((MQTT_SN_QOS_1) << 5) & MQTT_SNF_QOS_MASK);
    pkt.v.publish.flags.flag |= ((MQTT_SN_TOPIC_ID_TYPE_PREDEFINED) & MQTT_SNF_TID_TYPE_MASK);
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
    assert((pkt.v.publish.flags.flag & MQTT_SNF_DUP) != 0);
    assert(MQTT_SNF_QOS(pkt.v.publish.flags.flag) == MQTT_SN_QOS_1);
    assert(MQTT_SNF_TID_TYPE(pkt.v.publish.flags.flag) == MQTT_SN_TOPIC_ID_TYPE_PREDEFINED);
    assert(pkt.v.publish.msg_id == 0x22);
    assert(pkt.v.publish.topic.id == 0x12);
    pkt.v.publish.data.n = 65000;

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);

    mqtt_str_free(&bs);

    free(s);
}

static void
test_mqtt_random() {
    mqtt_str_t bp = MQTT_STR_INITIALIZER;
    mqtt_packet_t pkt;
    mqtt_parser_t parser;
    int rc;

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

    /* round-trip: a parsed packet must serialize and parse back. */
    if (rc == 1) {
        mqtt_str_t rb = MQTT_STR_INITIALIZER;
        if (mqtt_serialize(&pkt, &rb) == 0) {
            mqtt_packet_t pkt2;
            mqtt_parser_t parser2;
            int rc2;

            memset(&pkt2, 0, sizeof pkt2);
            rb.i = 0;
            mqtt_parser_init(&parser2);
            mqtt_parser_version(&parser2, pkt.ver);
            rc2 = mqtt_parse(&parser2, &rb, &pkt2);
            assert(rc2 == 1);
            mqtt_packet_cleanup(&pkt2);
            mqtt_parser_cleanup(&parser2);
            mqtt_str_free(&rb);
        }
    }

    mqtt_packet_cleanup(&pkt);
    mqtt_parser_cleanup(&parser);
    free(random_data);
}

static void
test_mqtt_sn_random() {
    mqtt_str_t bp = MQTT_STR_INITIALIZER;
    mqtt_sn_packet_t pkt;
    mqtt_sn_parser_t parser;
    int rc;

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

    /* round-trip: a parsed packet must serialize and parse back. */
    if (rc == 1) {
        mqtt_str_t rb = MQTT_STR_INITIALIZER;
        if (mqtt_sn_serialize(&pkt, &rb) == 0) {
            mqtt_sn_packet_t pkt2;
            mqtt_sn_parser_t parser2;
            int rc2;

            memset(&pkt2, 0, sizeof pkt2);
            rb.i = 0;
            mqtt_sn_parser_init(&parser2);
            rc2 = mqtt_sn_parse(&parser2, &rb, &pkt2);
            assert(rc2 == 1);
            mqtt_sn_packet_cleanup(&pkt2);
            mqtt_sn_parser_cleanup(&parser2);
            mqtt_str_free(&rb);
        }
    }

    mqtt_sn_packet_cleanup(&pkt);
    mqtt_sn_parser_cleanup(&parser);
    free(random_data);
}

/* targeted assertions for the hardening fixes. */
static void
test_mqtt_hardening() {
    mqtt_str_t bs = MQTT_STR_INITIALIZER;
    mqtt_str_t bp = MQTT_STR_INITIALIZER;
    mqtt_packet_t pkt;
    mqtt_parser_t parser;
    int rc;

    /* rc0 aliases: v5 SUBACK/DISCONNECT reason 0x00 must round-trip. */
    {
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_SUBACK);
        pkt.v.suback.packet_id = 0x07;
        mqtt_suback_generate(&pkt, 1);
        pkt.p.suback.v5.reason_codes[0] = MQTT_RC_GRANTED_QOS_0;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;
        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == 1);
        assert(pkt.p.suback.v5.reason_codes[0] == MQTT_RC_GRANTED_QOS_0);
        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);
        mqtt_str_free(&bs);

        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_DISCONNECT);
        pkt.v.disconnect.v5.reason_code = MQTT_RC_NORMAL_DISCONNECTION;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;
        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == 1);
        assert(pkt.v.disconnect.v5.reason_code == MQTT_RC_NORMAL_DISCONNECTION);
        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);
        mqtt_str_free(&bs);

        /* invalid reason code rejected on serialize. */
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_DISCONNECT);
        pkt.v.disconnect.v5.reason_code = (mqtt_rc_t)0x03;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == -1);
    }

    /* packet id 0 rejected on serialize. */
    {
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        pkt.f.flags = MQTT_FH_BUILD(MQTT_PUBLISH, 0, MQTT_QOS_1, 0);
        pkt.v.publish.packet_id = 0;
        mqtt_str_from(&pkt.v.publish.topic_name, "t");
        mqtt_str_from(&pkt.p.publish.message, "m");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == -1);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBACK);
        pkt.v.puback.packet_id = 0;
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == -1);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_SUBSCRIBE);
        pkt.v.subscribe.packet_id = 0;
        mqtt_subscribe_generate(&pkt, 1);
        mqtt_str_from(&pkt.p.subscribe.topic_filters[0], "t");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == -1);
    }

    /* packet id 0 rejected on parse. */
    {
        static char raw[] = {0x40, 0x02, 0x00, 0x00};
        mqtt_str_init(&bp, raw, sizeof raw);
        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == -1);
        mqtt_parser_cleanup(&parser);
    }

    /* duplicate non-repeatable property rejected. */
    {
        static char raw[] = {0x20, 0x09, 0x00, 0x00, 0x06, 0x21, 0x00, 0x64, 0x21, 0x00, (char)0xc8};
        mqtt_str_init(&bp, raw, sizeof raw);
        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == -1);
        mqtt_parser_cleanup(&parser);
    }

    /* unknown property code rejected. */
    {
        static char raw[] = {0x20, 0x06, 0x00, 0x00, 0x03, (char)0x99, 0x00, 0x00};
        mqtt_str_init(&bp, raw, sizeof raw);
        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == -1);
        mqtt_parser_cleanup(&parser);
    }

    /* property value range: receive maximum 0 rejected on serialize. */
    {
        uint16_t zero16 = 0;
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_CONNECT);
        mqtt_str_from(&pkt.p.connect.client_id, "mqtt");
        mqtt_properties_add(&pkt.v.connect.v5.properties, MQTT_PROPERTY_RECEIVE_MAXIMUM, &zero16, 0);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == -1);
    }

    /* property order kept, user property may repeat. */
    {
        uint8_t one = 1;
        mqtt_property_t *prop;
        mqtt_packet_init(&pkt, MQTT_VERSION_5, MQTT_PUBLISH);
        mqtt_str_from(&pkt.v.publish.topic_name, "t/order");
        mqtt_str_from(&pkt.p.publish.message, "m");
        mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR, &one, 0);
        mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_RESPONSE_TOPIC, "rt", 0);
        mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_USER_PROPERTY, "v1", "k1");
        mqtt_properties_add(&pkt.v.publish.v5.properties, MQTT_PROPERTY_USER_PROPERTY, "v2", "k2");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;
        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_5);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == 1);
        prop = pkt.v.publish.v5.properties.head;
        assert(prop && prop->code == MQTT_PROPERTY_PAYLOAD_FORMAT_INDICATOR);
        prop = prop->next;
        assert(prop && prop->code == MQTT_PROPERTY_RESPONSE_TOPIC);
        prop = prop->next;
        assert(prop && prop->code == MQTT_PROPERTY_USER_PROPERTY);
        assert(!mqtt_str_strcmp(&prop->pair.name, "k1"));
        prop = prop->next;
        assert(prop && prop->code == MQTT_PROPERTY_USER_PROPERTY);
        assert(!mqtt_str_strcmp(&prop->pair.name, "k2"));
        assert(!prop->next);
        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);
        mqtt_str_free(&bs);
    }

    /* first packet must be CONNECT; CONNECT failure must not set version. */
    {
        static char ping[] = {(char)0xc0, 0x00};
        mqtt_str_init(&bp, ping, sizeof ping);
        mqtt_parser_init(&parser);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == -1);
        mqtt_parser_cleanup(&parser);

        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_CONNECT);
        pkt.v.connect.connect_flags |= MQTT_CF_CLEAN_SESSION;
        mqtt_str_from(&pkt.p.connect.client_id, "mqtt");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == 0);
        bs.s[8] = 0x07; /* invalid protocol version */
        mqtt_str_set(&bp, &bs);
        bp.i = 0;
        mqtt_parser_init(&parser);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == -1);
        assert(parser.version == (mqtt_version_t)0);
        bs.s[8] = 0x04;
        bp.i = 0;
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == 1);
        assert(parser.version == MQTT_VERSION_4);
        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);
        mqtt_str_free(&bs);
    }

    /* utf-8 / topic filter / will topic validation on serialize. */
    {
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_CONNECT);
        mqtt_str_init(&pkt.p.connect.client_id, (char *)"a\0b", 3);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == -1);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_SUBSCRIBE);
        pkt.v.subscribe.packet_id = 0x01;
        mqtt_subscribe_generate(&pkt, 1);
        mqtt_str_from(&pkt.p.subscribe.topic_filters[0], "a#");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == -1);

        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_CONNECT);
        pkt.v.connect.connect_flags |= MQTT_CF_WILL_FLAG;
        mqtt_str_from(&pkt.p.connect.client_id, "mqtt");
        mqtt_str_from(&pkt.p.connect.will_topic, "a#");
        mqtt_str_from(&pkt.p.connect.will_message, "w");
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == -1);
    }

    /* error resets the parser so it can keep consuming. */
    {
        /* bad PUBACK (packet id 0) followed by a PINGREQ. */
        static char raw[] = {0x40, 0x02, 0x00, 0x00, (char)0xc0, 0x00};
        mqtt_str_init(&bp, raw, sizeof raw);
        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == -1);
        rc = mqtt_parse(&parser, &bp, &pkt);
        assert(rc == 1);
        assert(MQTT_FH_TYPE(pkt.f.flags) == MQTT_PINGREQ);
        mqtt_packet_cleanup(&pkt);
        mqtt_parser_cleanup(&parser);
    }

    /* parse with pkt == NULL must not leak. */
    {
        static char ping[] = {(char)0xc0, 0x00};
        mqtt_str_init(&bp, ping, sizeof ping);
        mqtt_parser_init(&parser);
        mqtt_parser_version(&parser, MQTT_VERSION_3);
        rc = mqtt_parse(&parser, &bp, 0);
        assert(rc == 1);
        mqtt_parser_cleanup(&parser);
    }

    /* preset-buffer serialize: success and capacity failure. */
    {
        char buf[64];
        mqtt_str_t bb;
        mqtt_packet_init(&pkt, MQTT_VERSION_3, MQTT_PUBLISH);
        mqtt_str_from(&pkt.v.publish.topic_name, "t");
        mqtt_str_from(&pkt.p.publish.message, "m");
        mqtt_str_init(&bb, buf, sizeof buf);
        rc = mqtt_serialize(&pkt, &bb);
        assert(rc == 0);
        assert(bb.n > 0 && bb.n == bb.i);
        bb.n = 2;
        bb.i = 0;
        rc = mqtt_serialize(&pkt, &bb);
        assert(rc == -1);
        mqtt_packet_cleanup(&pkt);
    }

    /* AUTH only exists in v5. */
    {
        mqtt_packet_init(&pkt, MQTT_VERSION_4, MQTT_AUTH);
        rc = mqtt_serialize(&pkt, &bs);
        mqtt_packet_cleanup(&pkt);
        assert(rc == -1);
    }

    /* fixed packet macros keep the wire format. */
    {
        static const uint8_t pubrel[] = MQTT_P_PUBREL_RC(0x1234, 0x00);
        static const uint8_t pubcomp[] = MQTT_P_PUBCOMP_RC(0x1234, 0x00);
        assert(pubrel[0] == 0x62 && pubrel[1] == 0x04);
        assert(pubcomp[0] == 0x70 && pubcomp[1] == 0x04);
    }

    /* encapsulated sn packet round-trip. */
    {
        mqtt_sn_packet_t sn;
        mqtt_sn_parser_t snp;
        mqtt_sn_packet_init(&sn, MQTT_SN_ENCAPSULATED);
        sn.v.encapsulated.ctrl = MQTT_ENC_RADIUS;
        sn.v.encapsulated.radius = 2;
        mqtt_str_from(&sn.v.encapsulated.message, "wmsg");
        rc = mqtt_sn_serialize(&sn, &bs);
        mqtt_sn_packet_cleanup(&sn);
        assert(rc == 0);
        mqtt_str_set(&bp, &bs);
        bp.i = 0;
        mqtt_sn_parser_init(&snp);
        rc = mqtt_sn_parse(&snp, &bp, &sn);
        assert(rc == 1);
        assert(sn.type == MQTT_SN_ENCAPSULATED);
        assert(sn.v.encapsulated.ctrl == MQTT_ENC_RADIUS);
        assert(sn.v.encapsulated.radius == 2);
        assert(!mqtt_str_strcmp(&sn.v.encapsulated.message, "wmsg"));
        mqtt_sn_packet_cleanup(&sn);
        mqtt_sn_parser_cleanup(&snp);
        mqtt_str_free(&bs);
    }
}

#define MQTT_MEMPOOL_IMPL
#include "mqtt_mempool.h"

static mqtt_mempool_t *g_mempool = NULL;

static void *
mqtt_mempool_malloc_adapter(size_t size) {
    if (g_mempool) {
        return mqtt_mempool_alloc(g_mempool, size);
    }
    return malloc(size);
}

static void
mqtt_mempool_free_adapter(void *ptr) {
    if (g_mempool) {
        mqtt_mempool_free(g_mempool, ptr);
    } else {
        free(ptr);
    }
}

int
main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    g_mempool = mqtt_mempool_create(0);
    if (!g_mempool) {
        printf("Failed to create memory pool\n");
        return -1;
    }

    mqtt_set_allocator(mqtt_mempool_malloc_adapter, mqtt_mempool_free_adapter);

    printf("Memory pool created and allocator set\n");

    test_mqtt();
    test_mqtt_sn();
    test_mqtt_hardening();

    srand(time(NULL));

    for (int i = 0; i < 10000; i++) {
        test_mqtt_random();
    }

    for (int i = 0; i < 10000; i++) {
        test_mqtt_sn_random();
    }

    size_t allocated_size = 0, used_size = 0, total_allocations = 0, total_frees = 0;
    double hit_rate = 0;
    mqtt_mempool_stats(g_mempool, &allocated_size, &used_size, &total_allocations, &total_frees, &hit_rate);

    printf("Memory pool stats:\n");
    printf("  Allocated size: %zu bytes\n", allocated_size);
    printf("  Used size: %zu bytes\n", used_size);
    printf("  Total allocations: %zu\n", total_allocations);
    printf("  Total frees: %zu\n", total_frees);
    printf("  Hit rate: %.2f\n", hit_rate);

    mqtt_mempool_destroy(g_mempool);
    g_mempool = NULL;

    printf("Memory pool destroyed\n");

    return 0;
}
