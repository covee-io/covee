#ifndef COVEE_ENGINE_H
#define COVEE_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Callback is synchronous. JSON maps state names to base64-encoded bytes.
 * Return 0 only after durable persistence succeeds. The caller owns context
 * until destroy returns. The callback must not call back into this engine.
 * Any failure permanently stops this handle; node traffic cannot continue
 * using an identity that was not durably saved. */
typedef int (*covee_persist_callback)(void *context, const char *state_json);

enum {
    COVEE_ERROR = -1,
    COVEE_BUFFER_TOO_SMALL = -2,
    COVEE_CLOSED = -3,
    COVEE_INVALID_ARGUMENT = -4
};

/* config: {controlURL, hostname, authKey?, acceptRoutes?, caPEM?,
 *          requireNetworkAck?, tunnelInterfaceName?}. HTTPS required; HTTP
 * allowed for loopback only. Apple providers must supply the real interface
 * from NEPacketTunnelProvider.virtualInterface.name (macOS15/iOS18+); this
 * preserves forwarded DNS socket binding. The synthetic default is for tests.
 * state_json is an existing state map, or "{}" on first use.
 * Returns a positive handle or 0. last_error(0,...) describes create failure.
 * The engine does not modify host routes, DNS, or install a VPN itself. */
int64_t covee_create(const char *config_json, const char *state_json,
                         covee_persist_callback persist, void *context);
int covee_start(int64_t handle);

/* Raw IPv4/IPv6 packets, without a utun address-family header. write_packet
 * copies its input before returning. It may return ERROR on queue congestion.
 * read_packet blocks until a packet or stop; returns byte count on success.
 * BUFFER_TOO_SMALL preserves the packet for a retry with a larger buffer. */
int covee_write_packet(int64_t handle, const uint8_t *packet, int length);
int covee_read_packet(int64_t handle, uint8_t *packet, int capacity);

/* NUL-terminated JSON event. Return length excludes NUL; 0 means a 250 ms
 * timeout; BUFFER_TOO_SMALL preserves the event. At least 1 MiB+1 capacity is
 * sufficient for all supported events. Network and status payloads are nested:
 * {"type":"network","network":{addresses,routes,excludedRoutes,dnsServers,
 *   matchDomains,searchDomains,mtu,generation}}
 * {"type":"status","status":{backendState,ips,peers,authURL?,error?,
 *   magicDNSSuffix?,exitNodeID,exitNodeAllowLANAccess}}, each peer
 *   {id,name,ips,online,exitNodeOption,exitNode,routes}
 * {"type":"error","error":"...","code"?:"persistence"}.
 * Secrets are never included. Persistence failure supersedes queued events,
 * remains readable once after stop (including short-buffer retries), then
 * returns CLOSED. The handle cannot resume after this failure. */
int covee_next_event(int64_t handle, char *json, int capacity);

/* With requireNetworkAck=true, acknowledge each network event after Apple's
 * setTunnelNetworkSettings completion. Pass NULL/empty error on success.
 * Network callback waits at most 15 seconds for this acknowledgement. */
int covee_ack_network(int64_t handle, uint64_t generation, const char *error);

/* request: {"id":"<peer id from status, or empty for no exit node>",
 * "allowLAN":bool}. A non-empty id must be a peer whose exitNodeOption is
 * true. Returns 0 on success, INVALID_ARGUMENT for a bad handle or buffer,
 * CLOSED after stop, or ERROR with a NUL-terminated, user-presentable reason
 * in message (capacity 1..4096). A refusal never stops the engine. The call
 * may wait for the resulting network settings acknowledgement. */
int covee_set_exit_node(int64_t handle, const char *request_json, char *message, int capacity);

/* request: {"offer":bool}. Offers this device to the network as an exit node,
 * or stops offering it; local networks it offers are kept. Other devices can
 * use it once the coordinator approves it (status exitNodeApproved). Refused
 * on iPhone, and while this device itself uses an exit node. Returns as
 * covee_set_exit_node does. */
int covee_set_offer_exit_node(int64_t handle, const char *request_json, char *message, int capacity);

/* request: {"accept":bool}. Uses the routes other devices offer, such as a
 * network gateway's destinations and local networks, or stops using them
 * (status acceptRoutes). Returns as covee_set_exit_node does. */
int covee_set_accept_routes(int64_t handle, const char *request_json, char *message, int capacity);

/* stop unblocks reads and cancels network work. A stopped handle cannot restart.
 * destroy also releases handle/state; no callbacks run after it returns.
 * These must not be called from the persistence callback. */
int covee_stop(int64_t handle);
int covee_destroy(int64_t handle);

/* Returns required capacity including NUL; writes only when capacity suffices.
 * If handle is invalid, returns a generic error; 0 selects last create error. */
int covee_last_error(int64_t handle, char *message, int capacity);

#ifdef __cplusplus
}
#endif
#endif
