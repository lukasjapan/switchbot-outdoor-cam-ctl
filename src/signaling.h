// P2P signaling transport.
//
// The native SDK generates its own signaling (offer / candidates / etc.) and
// raises sendMessageThroughMqtt(byLan, topic, json); our job is only to carry
// those messages to the camera and feed the replies back via setSignaling. We do
// NOT implement WebRTC — libThingP2PSDK owns that.
//
// What is reimplemented here is the Java layer around it:
//   - MQTT connect parameters (com.thingclips.sdk.mqtt.dqqbdqb / MqttConnectConfig)
//       broker    ssl://<mobileMqttUrl>:8883        (AZ => m1.tuyaus.com)
//       username  <partnerIdentity>_v1_<appId>_<chKey>_mb_<sid><md5tail>
//                 md5tail = md5hex(md5hex(appId) + ecode)[-16:]
//       password  middle 16 chars of doCommandNative(ctx, 2, ecode)
//       clientId  <pkg>_mb_<username>
//       subTopic  <partnerIdentity>/mb/<uid>
//   - the pv-2.2 binary control frame (com.thingclips.sdk.mqtt.bpqqdpq):
//       "2.2" || crc32BE(body) || int32BE(s) || int32BE(o) || AES-128-ECB(localKey,
//          JSON{data:<signaling>, protocol:302, t:<sec>})
//     with body = int32BE(s) || int32BE(o) || enc, and the SandO sequence
//     (s starts at 2 and is incremented before each send; o random in [1e3,1e6)).
#ifndef OUTDOOR_CAM_SIGNALING_H
#define OUTDOOR_CAM_SIGNALING_H

#include "creds.h"
#include "tuya_sign.h"

typedef struct Signaling Signaling;

// Inbound 302 payload (the decrypted `data` object, as JSON text).
typedef void (*signaling_on_message)(const char *json, void *user);

// Connect to the broker, subscribe to the account and device topics.
Signaling *signaling_start(const TuyaSession *s, const CredDevice *dev,
                           const char *country_code);

// Publish one signaling object (JSON text) to the device, wrapped in a pv-2.2
// 302 frame. `topic` may be NULL to use the default smart/mb/out/<devId>.
int  signaling_publish(Signaling *sg, const char *topic, const char *json);

// Wake a low-power camera: CRC32(localKey) to m/w/<devId>.
int  signaling_wake(Signaling *sg);

// Pump the transport for up to timeout_ms, dispatching inbound 302 payloads.
int  signaling_poll(Signaling *sg, int timeout_ms, signaling_on_message cb, void *user);

void signaling_stop(Signaling *sg);

#endif
