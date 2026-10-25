// C interface of the vproxy core for the Ratatosk iOS Packet Tunnel.
// Implemented in ffi/src/lib.rs; keep the two in step.

#ifndef RATATOSK_H
#define RATATOSK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Tunnel interface settings the core expects (NEPacketTunnelNetworkSettings):
// the interface address, its mask, and the fake DNS server inside the tunnel.
#define RATATOSK_TUNNEL_ADDRESS "198.18.0.1"
#define RATATOSK_TUNNEL_NETMASK "255.254.0.0"
#define RATATOSK_DNS_ADDRESS "198.18.0.2"

typedef struct RatatoskTunnel RatatoskTunnel;

typedef struct {
    uint64_t active;  // open connections
    uint64_t total;   // connections since start
    uint64_t up;      // bytes towards the server
    uint64_t down;    // bytes from the server
    uint64_t errors;
} RatatoskStats;

// The IP packets the stack sends towards the system, as many as are waiting
// (up to 64): `count` packets, `packets[i]` of `lens[i]` bytes, valid only
// during the call. Write them in one go. Called on a core thread.
typedef void (*RatatoskPacketCallback)(void *ctx, const uint8_t *const *packets,
                                       const size_t *lens, size_t count);
// Each log line, level 1 error .. 5 trace; `line` is valid only during the call.
typedef void (*RatatoskLogCallback)(void *ctx, uint8_t level, const char *line);

// Start for a vless://, h3:// or vpn:// link. NULL on failure, the reason in `error`.
// `ctx` must stay valid until ratatosk_stop returns.
RatatoskTunnel *ratatosk_start(const char *link, uint16_t mtu,
                               RatatoskPacketCallback on_packet, void *ctx,
                               char *error, size_t error_len);

// One IP packet read from the system. False when dropped (queue full).
bool ratatosk_push_packet(const RatatoskTunnel *tunnel, const uint8_t *packet, size_t len);

// The device's network changed (Wi-Fi to cellular, say): an h3 connection
// moves to the new path instead of timing out. Call from the path monitor.
void ratatosk_network_changed(const RatatoskTunnel *tunnel);

void ratatosk_stats(RatatoskStats *out);

// The newest `max` flows, newest first, as a JSON array of
// {id, t (unix ms), proto, host, port, route, up, down, open, failed}.
// Written NUL-terminated into `buf` when it fits; returns the JSON length.
// A result >= buf_len means it did not fit and nothing was written.
size_t ratatosk_flows_json(const RatatoskTunnel *tunnel, size_t max, char *buf, size_t buf_len);

// Stop and free. Not from inside a callback.
void ratatosk_stop(RatatoskTunnel *tunnel);

// Logs to `on_log` up to `max_level`; only the first call in a process counts.
void ratatosk_set_logger(RatatoskLogCallback on_log, void *ctx, uint8_t max_level);

const char *ratatosk_version(void);

// Handshake time to each server of `links_json` (a JSON array of link
// strings), measured at once with `timeout_ms` each: a JSON array of
// milliseconds, null where the link is bad or the server did not answer.
// NULL when the input is not such an array. Blocks. Free with
// ratatosk_string_free. Inside the Packet Tunnel its sockets bypass the
// tunnel; an app with the VPN on should ask the extension instead.
char *ratatosk_ping(const char *links_json, uint32_t timeout_ms);

// Download a subscription: JSON {title, links, skipped, upload, download,
// total, expire, interval_hours} (bytes, unix seconds; title and traffic may
// be null), or {error}. Blocks. Free with ratatosk_string_free.
char *ratatosk_fetch_subscription(const char *url);

void ratatosk_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif
