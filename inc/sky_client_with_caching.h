/************************************************
 * Authors: Liang Zhao and Ted Boinske
 * 
 * Company: Skyhook
 *
 ************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_CLIENT_WITH_CACHING_H
#define SKY_CLIENT_WITH_CACHING_H

#include "sky_protocol.h"

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
        float cache_match_percentage);

#endif

#ifdef __cplusplus
}
#endif
