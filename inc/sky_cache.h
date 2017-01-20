#include <stdbool.h>
#include <string.h>
#include "uthash.h" // git cloned from https://github.com/troydhanson/uthash
#include "sky_protocol.h"

// LRU cache in C using uthash

#define MAX_CACHE_SIZE 100

struct cache_entry {
    char *key;
    char *value;
    UT_hash_handle hh;
};

/**
 * Create a cache in memory.
 * @param size : the size of the cache
 * @return true on success; false on failure.
 */
bool create_cache(uint32_t size);

/**
 * Delete a cache.
 */
void delete_cache();

/**
 * Check if cache is empty.
 * @return true on empty; false on not empty.
 */
bool isCacheEmpty();

/**
 * Look up the key in cache.
 * @param key : the key to look up
 * @return the value associated with the key on success;
 *         or NULL on failure.
 */
char * sky_cache_lookup(const char *key);

/**
 * Add key-value pairs into the cache.
 * @param key : key to add
 * @param value : value to add
 */
void sky_cache_add(const char *key, const char *value);

/**
 * Create and cache an array of APs.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 */
void cacheAPs(const struct ap_t *aps, uint32_t aps_size);

/**
 * Check if the cache matching is satisfied.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 * @param p : percentage to satisfy matching criteria
 * @return true on matching; false on not-matching.
 */
bool isCacheMatch(const struct ap_t *aps, uint32_t aps_size, float p);

/**
 * Check if caching matching is satisfied.
 * If so, it is not necessary to query locations.
 * @param req : location request structure
 * @param match_percentage : the percentage to satisfy matching criteria
 * @return true on matching; false on not matching.
 */
bool checkCacheMatch(const struct location_rq_t* req, float match_percentage);
