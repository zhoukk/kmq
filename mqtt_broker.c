#define MQTT_BROKER_IMPL
#include "mqtt_broker.h"

static void usage(void) {
    fprintf(stderr, "Usage: mqtt_broker [config_file]\n");
}

mqtt_broker_t *mqtt_broker_create(const mqtt_broker_config_t *config, uv_loop_t *loop) {
    (void)config; (void)loop;
    return NULL;
}

int mqtt_broker_start(mqtt_broker_t *b) { (void)b; return -1; }

void mqtt_broker_stop(mqtt_broker_t *b)  { (void)b; }

void mqtt_broker_destroy(mqtt_broker_t *b) { (void)b; }

int  mqtt_broker_run(mqtt_broker_t *b) { (void)b; return 0; }

void mqtt_broker_set_auth_callback(mqtt_broker_t *b, mqtt_broker_auth_callback_t cb, void *ud) {
    (void)b; (void)cb; (void)ud;
}

int main(int argc, char *argv[]) {
    mqtt_broker_config_t config;
    mqtt_broker_t *b;
    uv_loop_t *loop;
    int rc;

    if (argc > 2) {
        usage();
        return EXIT_FAILURE;
    }

    loop = uv_default_loop();

    mqtt_broker_config_init(&config);
    b = mqtt_broker_create(&config, loop);
    if (!b) {
        fprintf(stderr, "mqtt_broker_create failed\n");
        return EXIT_FAILURE;
    }

    rc = mqtt_broker_start(b);
    if (rc) {
        fprintf(stderr, "mqtt_broker_start failed\n");
        return EXIT_FAILURE;
    }

    if (argc > 1) {
        /* TODO: load config from file */
        (void)argv[1];
    }

    mqtt_broker_run(b);
    mqtt_broker_destroy(b);

    return EXIT_SUCCESS;
}
