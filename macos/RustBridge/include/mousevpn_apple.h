#ifndef MOUSEVPN_APPLE_H
#define MOUSEVPN_APPLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __has_feature(nullability)
#pragma clang assume_nonnull begin
#endif

typedef struct MouseVpnAppleSession MouseVpnAppleSession;

typedef struct {
    uint8_t * _Nullable data;
    size_t len;
    size_t capacity;
} MvOwnedBytes;

typedef struct {
    char * _Nullable message;
} MvError;

MouseVpnAppleSession * _Nullable mousevpn_apple_connect(
    const char *endpoint,
    const char *server_public_key,
    const char *client_private_key,
    MvOwnedBytes *parameters_json,
    MvError *error
);

bool mousevpn_apple_send_packet_batch(
    MouseVpnAppleSession *session,
    const uint8_t *framed_packets,
    size_t framed_length,
    MvError *error
);

// Returns 1 for packets, 0 for a timeout, and -1 for an error.
int32_t mousevpn_apple_receive_packet_batch(
    MouseVpnAppleSession *session,
    uint64_t timeout_millis,
    size_t maximum_packets,
    MvOwnedBytes *framed_packets,
    MvError *error
);

bool mousevpn_apple_send_keepalive(
    MouseVpnAppleSession *session,
    MvError *error
);

void mousevpn_apple_session_free(MouseVpnAppleSession *session);
void mousevpn_apple_bytes_free(MvOwnedBytes *bytes);
void mousevpn_apple_error_free(MvError *error);

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
