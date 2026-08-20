// Native library loading + the ThingCameraEngine / ThingCamera JNI entry points.
//
// libThingCameraSDK.so exposes 109 static Java_..._* exports (no dynamic
// RegisterNatives), so every entry point is reachable with dlsym once the
// dependency chain is loaded. We drive them through the JNIEnv mock.
#ifndef OUTDOOR_CAM_NATIVE_H
#define OUTDOOR_CAM_NATIVE_H

#include <jni.h>

// Load the full DT_NEEDED chain in dependency order and run JNI_OnLoad on the
// SDKs that have one. Returns 0 on success. Safe to call once per process.
int native_load(void);

// Handle of libThingCameraSDK.so (for dlsym of the Java_..._* exports).
void *native_camera_so(void);
// Handle of libThingP2PSDK.so (transport-level exports: ThingP2PSendData, …).
void *native_p2p_so(void);
// Handle of libthing_security.so (Tuya request signing / response decryption).
void *native_security_so(void);

// ---- ThingCameraEngineNative ----------------------------------------------
// initialize() must run before any camera handle is created; initP2PModule()
// takes the P2P config JSON.
int native_engine_initialize(void);
int native_engine_init_p2p(const char *config_json);
int native_engine_deinit_p2p(void);
int native_engine_deinitialize(void);
const char *native_engine_version(void);   // NULL if unavailable

// ---- ThingP2PSDK ----------------------------------------------------------
// The P2P SDK has its own init that must run before any camera connect. The app
// calls it as ThingIPCSdk.getP2P().init(localId) from
// IPCThingP2PCamera.initNativeOnce, where localId is the Tuya user uid.
// (initP2PModule() above is only used for the legacy p2pType 2 / PPCS path.)
int native_p2p_init(const char *local_id);

// Force software video decoding. Without this the SDK probes Android MediaCodec
// (ThingJavaMediaCodecDecoder) for HEVC, which cannot work here — there is no
// real MediaCodec behind the JNI mock, and it crashes. The app has the same
// switch behind its "ipc_hevc_soft_decode" preference.
int native_engine_set_soft_decode(int on);

#endif
