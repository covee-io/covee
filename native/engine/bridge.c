#include "include/CoveeEngine.h"
#include "_cgo_export.h"

int invoke_persist(covee_persist_callback fn, void *ctx, const char *json) {
    return fn(ctx, json);
}

int64_t covee_create(const char *config, const char *state,
                         covee_persist_callback persist, void *context) {
    return GoCoveeCreate((char *)config, (char *)state, persist, context);
}
int covee_start(int64_t h) { return GoCoveeStart(h); }
int covee_write_packet(int64_t h, const uint8_t *p, int n) {
    return GoCoveeWritePacket(h, (uint8_t *)p, n);
}
int covee_read_packet(int64_t h, uint8_t *p, int n) {
    return GoCoveeReadPacket(h, p, n);
}
int covee_next_event(int64_t h, char *p, int n) {
    return GoCoveeNextEvent(h, p, n);
}
int covee_ack_network(int64_t h, uint64_t generation, const char *error) {
    return GoCoveeAckNetwork(h, generation, (char *)error);
}
int covee_set_exit_node(int64_t h, const char *request, char *message, int capacity) {
    return GoCoveeSetExitNode(h, (char *)request, message, capacity);
}
int covee_set_offer_exit_node(int64_t h, const char *request, char *message, int capacity) {
    return GoCoveeSetOfferExitNode(h, (char *)request, message, capacity);
}
int covee_set_accept_routes(int64_t h, const char *request, char *message, int capacity) {
    return GoCoveeSetAcceptRoutes(h, (char *)request, message, capacity);
}
int covee_stop(int64_t h) { return GoCoveeStop(h); }
int covee_destroy(int64_t h) { return GoCoveeDestroy(h); }
int covee_last_error(int64_t h, char *p, int n) {
    return GoCoveeLastError(h, p, n);
}
