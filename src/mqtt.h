// Minimal MQTT 3.1.1 client (CONNECT / SUBSCRIBE / PUBLISH / PING), over the
// TLS socket exported by http.c.
//
// Only what Tuya's signaling channel needs: one subscription, QoS-1 publishes,
// and a poll loop that hands inbound PUBLISH payloads to a callback. The
// connection parameters themselves (broker, username, password, topics) are
// derived in signaling.c from the app's Java logic.
#ifndef OUTDOOR_CAM_MQTT_H
#define OUTDOOR_CAM_MQTT_H

#include <stddef.h>

typedef struct MqttConn MqttConn;

// Called for each inbound PUBLISH. `payload` is not NUL-terminated.
typedef void (*mqtt_on_message)(const char *topic, const unsigned char *payload,
                                size_t len, void *user);

// Connect + wait for CONNACK. Returns NULL on failure (reason is logged).
MqttConn *mqtt_connect(const char *host, int port, int use_tls,
                       const char *client_id, const char *username, const char *password,
                       int keepalive_sec);

int  mqtt_subscribe(MqttConn *m, const char *topic);
int  mqtt_publish(MqttConn *m, const char *topic, const unsigned char *payload, size_t len);

// Pump the connection for up to `timeout_ms`, dispatching inbound messages and
// sending keepalive pings when due. Returns 0 normally, -1 if the link dropped.
int  mqtt_poll(MqttConn *m, int timeout_ms, mqtt_on_message cb, void *user);

void mqtt_close(MqttConn *m);

#endif
