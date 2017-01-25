#ifndef SKY_CACHE_H
#define SKY_CACHE_H

#include <stdbool.h>
#include <string.h>
#include "sky_protocol.h"

#define MAX_CACHE_SIZE               100
#define MIN_CACHE_APS                5
#define MAX_CACHE_TIME               3600 // in seconds
#define SKY_AP_CACHE_FILENAME        "sky_ap_cache_file.data"

typedef struct cache_entry_t {
    char * key;
    char * value;
} cache_entry_t;

typedef struct sky_cache_t {
    enum SKY_DATA_TYPE type;
    cache_entry_t buf[MAX_CACHE_SIZE];
    uint32_t buf_size;    // actual size of cache
    uint32_t key_size;
    uint32_t value_size;
    uint32_t timestamp;   // in seconds
} sky_cache_t;

/**
 * Create a cache in memory.
 * @param type : cache data type
 * @param cache_size : the size of the cache
 * @param key_size : the size of key
 * @param value_size : the size of value
 */
void create_cache(enum SKY_DATA_TYPE type, uint32_t cache_size, uint32_t key_size, uint32_t value_size);

/**
 * Delete a cache.
 * @param type : cache data type
 */
void delete_cache(enum SKY_DATA_TYPE type);

/**
 * Check if cache is empty.
 * @return true on empty; false on not empty.
 */
bool is_cache_empty();

/**
 * Look up the key in cache.
 * @param key : the key to look up
 * @return the cache entry associated with the key on success;
 *         or NULL on failure.
 */
cache_entry_t * sky_cache_lookup(const char * key);

/**
 * Add key-value pairs into the cache.
 * @param idx : index in cache to add
 * @param key : key to add
 * @param value : value to add
 * @return true on success; false on failure.
 */
bool sky_cache_add(uint32_t idx, const char * key, const char * value);

/**
 * Create and cache an array of APs.
 * Note: automatically truncate the APs more than MAX_CACHE_SIZE.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 */
void cache_aps(const struct ap_t * aps, uint32_t aps_size);

/**
 * Check if the cache matching is satisfied.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 * @param p : percentage to satisfy matching criteria
 * @return true on matching; false on not-matching.
 */
bool is_ap_cache_match(const struct ap_t * aps, uint32_t aps_size, float p);

/**
 * Initialize cache with proper memory allocation.
 * @param key_size : the size of key in bytes
 * @param value_size : the size of value in bytes
 * @return true on success; false on failure.
 */
bool sky_cache_init(uint32_t key_size, uint32_t value_size);

/**
 * Deinitialize cache with proper memory reclamation.
 */
void sky_cache_deinit();

/**
 * Check if cache matching is satisfied.
 * If so, it is not necessary to query locations.
 * @param req : location request structure
 * @param type : cache data type
 * @param match_percentage : the percentage to satisfy matching criteria
 * @return true on matching; false on not matching.
 */
bool check_cache_match(const struct location_rq_t * req, enum SKY_DATA_TYPE type, float match_percentage);

#endif // #ifndef SKY_CACHE_H
