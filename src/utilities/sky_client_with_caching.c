#include <stdio.h>
#include "sky_client_with_caching.h"
#include "sky_cache.h"

// Called by the client to query location with the scan caching support.
// - sky_query_location() with scan caching to save power.
// @param rq [in] - client's location request
// @param rpc_send [in] - callback function for sending out data buffer
// @param url [in] - destination server and port in the format of "elg://host:port/"
// @param rsp [out] - server's location response
// @param rpc_recv [in] - callback function for receiving data
// @param rpc_handle [in] - the RPC call handle for tx and rx
// @param cache_match_percentage - the percentage to match for scan caching
// @return true for success, or false for failure
bool sky_query_location_with_caching(
        struct location_rq_t * rq, sky_client_send_fn rpc_send, char * url,
        struct location_rsp_t *rsp, sky_client_recv_fn rpc_recv, void * rpc_handle,
        float cache_match_percentage) {

    sky_cache_create(MAC_SIZE, sizeof(int8_t));
    if (sky_cache_match(rq, DATA_TYPE_AP, cache_match_percentage)) {
        printf("cache match: same location\n");
        return true;
    }
    bool rc = sky_query_location(rq, rpc_send, url, rsp, rpc_recv, rpc_handle);
    if (rsp->payload_ext.payload.type == LOCATION_UNABLE_TO_DETERMINE) {
        sky_cache_cleanup(DATA_TYPE_AP);
    }
    return rc;
}
