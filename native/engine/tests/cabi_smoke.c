#include "CoveeEngine.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *state;
static int writes;
static int persist(void *context, const char *json) {
    if (context != &writes || !json || json[0] != '{') return 1;
    char *copy = strdup(json);
    if (!copy) return 1;
    free(state);
    state = copy;
    writes++;
    return 0;
}

static int fail_persist(void *context, const char *json) {
    int *failures = context;
    if (json && json[0] == '{') (*failures)++;
    return 1;
}

struct reader { int64_t handle; int result; };
static void *read_packet(void *ctx) {
    struct reader *reader = ctx;
    uint8_t packet[65536];
    reader->result = covee_read_packet(reader->handle, packet, sizeof(packet));
    return NULL;
}

static int require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "C ABI smoke failed: %s\n", message); return 0; }
    return 1;
}

int main(void) {
    const char *bad = "{\"controlURL\":\"http://controller.example\",\"hostname\":\"c-abi\"}";
    if (!require(covee_create(bad, "{}", persist, &writes) == 0, "unsafe controller accepted")) return 1;
    char error[2048];
    if (!require(covee_last_error(0, error, sizeof(error)) > 1 && strstr(error, "HTTPS"), "create error unavailable")) return 1;
    const char *config = "{\"controlURL\":\"http://127.0.0.1:9\",\"hostname\":\"covee-c-abi\",\"acceptRoutes\":true}";
    if (!require(covee_create(config, "{}", NULL, NULL) == 0, "missing durable persistence accepted")) return 1;
    int64_t handle = covee_create(config, "{}", persist, &writes);
    if (!require(handle > 0, "valid create failed")) return 1;
    if (!require(covee_start(handle) == 0, "real backend failed to start")) return 1;
    if (!require(writes > 0 && state != NULL, "state callback was not invoked")) return 1;
    char short_event[2];
    if (!require(covee_next_event(handle, short_event, sizeof(short_event)) == COVEE_BUFFER_TOO_SMALL, "short event was not preserved")) return 1;
    char *event = malloc(1024 * 1024 + 1);
    if (!require(event != NULL, "allocation failed")) return 1;
    int n = covee_next_event(handle, event, 1024 * 1024 + 1);
    if (!require(n > 0 && event[n] == 0 && strstr(event, "\"type\""), "event retry or NUL termination failed")) return 1;
    uint8_t invalid[20] = {0};
    if (!require(covee_write_packet(handle, invalid, sizeof(invalid)) != 0, "malformed packet accepted")) return 1;
    char reason[256];
    if (!require(covee_set_exit_node(handle, "{\"id\":\"nNoSuchPeer\",\"allowLAN\":false}", reason, sizeof(reason)) == COVEE_ERROR && strstr(reason, "exit node"), "unknown exit node accepted")) return 1;
    if (!require(covee_set_exit_node(handle, "not json", reason, sizeof(reason)) == COVEE_ERROR, "malformed exit node request accepted")) return 1;
    if (!require(covee_set_exit_node(handle, "{\"id\":\"\",\"allowLAN\":false}", reason, sizeof(reason)) == 0, "clearing the exit node failed")) return 1;
    if (!require(covee_set_exit_node(handle, "{\"id\":\"\"}", NULL, 0) == COVEE_INVALID_ARGUMENT, "missing reason buffer accepted")) return 1;
    if (!require(covee_set_exit_node(987654, "{\"id\":\"\"}", reason, sizeof(reason)) == COVEE_INVALID_ARGUMENT, "unknown handle accepted")) return 1;
    if (!require(covee_set_offer_exit_node(handle, "{\"offer\":1}", reason, sizeof(reason)) == COVEE_ERROR && strstr(reason, "offer"), "malformed offer accepted")) return 1;
    if (!require(covee_set_offer_exit_node(handle, "{\"offer\":false}", reason, sizeof(reason)) == 0, "withdrawing the offer failed")) return 1;
    if (!require(covee_set_offer_exit_node(handle, "{\"offer\":false}", NULL, 0) == COVEE_INVALID_ARGUMENT, "missing offer reason buffer accepted")) return 1;
    if (!require(covee_set_accept_routes(handle, "{\"accept\":\"yes\"}", reason, sizeof(reason)) == COVEE_ERROR && strstr(reason, "routes"), "malformed routes request accepted")) return 1;
    if (!require(covee_set_accept_routes(handle, "{\"accept\":false}", reason, sizeof(reason)) == 0, "turning off the network's routes failed")) return 1;
    if (!require(covee_set_accept_routes(handle, "{\"accept\":true}", reason, sizeof(reason)) == 0, "turning on the network's routes failed")) return 1;
    if (!require(covee_set_offer_exit_node(987654, "{\"offer\":false}", reason, sizeof(reason)) == COVEE_INVALID_ARGUMENT, "offer on unknown handle accepted")) return 1;
    struct reader reader = { .handle = handle, .result = 0 };
    pthread_t thread;
    if (!require(pthread_create(&thread, NULL, read_packet, &reader) == 0, "reader thread failed")) return 1;
    if (!require(covee_stop(handle) == 0, "stop failed")) return 1;
    pthread_join(thread, NULL);
    if (!require(reader.result == COVEE_CLOSED, "stop did not unblock read")) return 1;
    if (!require(covee_destroy(handle) == 0, "destroy failed")) return 1;
    if (!require(covee_stop(handle) == COVEE_INVALID_ARGUMENT, "destroy retained stale handle")) return 1;
    int64_t restored = covee_create(config, state, persist, &writes);
    if (!require(restored > 0, "persisted state could not be restored")) return 1;
    covee_destroy(restored);
    int failures = 0;
    int64_t failed = covee_create(config, "{}", fail_persist, &failures);
    if (!require(failed > 0, "failing callback could not create engine")) return 1;
    if (!require(covee_start(failed) == COVEE_ERROR && failures > 0, "failed persistence did not fail start")) return 1;
    if (!require(covee_last_error(failed, error, sizeof(error)) > 1 && strstr(error, "Durable client identity"), "fatal storage error was overwritten")) return 1;
    if (!require(covee_next_event(failed, short_event, sizeof(short_event)) == COVEE_BUFFER_TOO_SMALL, "fatal event was lost after stop or short buffer")) return 1;
    n = covee_next_event(failed, event, 1024 * 1024 + 1);
    if (!require(n > 0 && event[n] == 0 && strstr(event, "\"code\":\"persistence\""), "fatal persistence event missing after stop")) return 1;
    if (!require(covee_next_event(failed, event, 1024 * 1024 + 1) == COVEE_CLOSED, "events continued after fatal storage failure")) return 1;
    uint8_t valid[20] = {0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1};
    if (!require(covee_write_packet(failed, valid, sizeof(valid)) == COVEE_CLOSED, "packet accepted after fatal storage failure")) return 1;
    if (!require(covee_read_packet(failed, valid, sizeof(valid)) == COVEE_CLOSED, "packet delivered after fatal storage failure")) return 1;
    if (!require(covee_destroy(failed) == 0, "failed engine destroy failed")) return 1;
    printf("{\"result\":\"passed\",\"platform\":\"macos-arm64\",\"realBackendStart\":true,\"stateCallbackWrites\":%d,\"stateRestore\":true,\"eventRetry\":true,\"stopUnblocksPacketRead\":true,\"persistenceFailureStopsTunnel\":true,\"persistenceErrorAfterStop\":true,\"hostTunnelOpened\":false,\"dataplaneConnectivityTested\":false}\n", writes);
    free(event);
    free(state);
    return 0;
}
