#include "sky_cache.h"

// cache array
static struct cache_entry *cache = NULL;

// cache array size
static uint32_t cache_size = 0;

/**
 * Create a cache in memory.
 * @param size : the size of the cache
 * @return true on success; false on failure.
 */
bool create_cache(uint32_t size) {
    cache_size = size;
    cache = (struct cache_entry *)malloc(sizeof(struct cache_entry) * size);
    if (cache) {
        return false; // failure
    } else {
        return true; // success
    }
}

/**
 * Delete a cache.
 */
void delete_cache() {
    if (cache != NULL) {
        free(cache);
        cache = NULL;
    }
    cache_size = 0;
}

/**
 * Check if cache is empty.
 * @return true on empty; false on not empty.
 */
bool isCacheEmpty() {
    if (cache == NULL && cache_size == 0) {
        return true;
    } else {
        return false;
    }
}

/**
 * Look up the key in cache.
 * @param key : the key to look up
 * @return the value associated with the key on success;
 *         or NULL on failure.
 */
char * sky_cache_lookup(const char *key) {
    struct cache_entry * entry = NULL;
    HASH_FIND_STR(cache, key, entry);
    if (entry) {
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh, cache, entry);
        HASH_ADD_KEYPTR(hh, cache, entry->key, strlen(entry->key), entry);
        return entry->value;
    }
    return NULL;
}

/**
 * Add key-value pairs into the cache.
 * @param key : key to add
 * @param value : value to add
 */
void sky_cache_add(const char *key, const char *value) {
    struct cache_entry *entry, *tmp_entry;
    entry = malloc(sizeof(struct cache_entry));
    entry->key = strdup(key);
    entry->value = strdup(value);
    HASH_ADD_KEYPTR(hh, cache, entry->key, strlen(entry->key), entry);

    // prune the cache to MAX_CACHE_SIZE
    if (HASH_COUNT(cache) >= MAX_CACHE_SIZE) {
        HASH_ITER(hh, cache, entry, tmp_entry) {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
            HASH_DELETE(hh, cache, entry);
            free(entry->key);
            free(entry->value);
            free(entry);
            break;
        }
    }
}

/**
 * Create and cache an array of APs.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 */
void cacheAPs(const struct ap_t *aps, uint32_t aps_size) {
    if (aps_size > MAX_CACHE_SIZE) {
        aps_size = MAX_CACHE_SIZE;
    }
    create_cache(aps_size);
    uint32_t i = 0;
    for (i=0; i<aps_size; ++i) {
        sky_cache_add((char *)aps[i].MAC, (char *)&aps[i].rssi);
    }
}

/**
 * Check if the cache matching is satisfied.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 * @param p : percentage to satisfy matching criteria
 * @return true on matching; false on not-matching.
 */
bool isCacheMatch(const struct ap_t *aps, uint32_t aps_size, float p) {
    if (aps_size > MAX_CACHE_SIZE) {
        aps_size = MAX_CACHE_SIZE;
    }
    uint32_t n = 0, i;
    for (i=0; i<aps_size; ++i) {
        if (!sky_cache_lookup((char *)aps[i].MAC)) {
            ++n;
        }
    }
    if ((float)n/aps_size < p) {
        return false; // not matching
    } else {
        return true; // matching
    }
}

/**
 * Check if caching matching is satisfied.
 * If so, it is not necessary to query locations.
 * @param req : location request structure
 * @param match_percentage : the percentage to satisfy matching criteria
 * @return true on matching; false on not matching.
 */
bool checkCacheMatch(const struct location_rq_t* req, float match_percentage) {
    if (isCacheEmpty()) {
        cacheAPs(req->aps, req->ap_count);
        return false;
    } else {
        if (isCacheMatch(req->aps, req->ap_count, match_percentage)) {
            return true; // same location, no need to send out location request.
        } else {
            delete_cache();
            cacheAPs(req->aps, req->ap_count);
            return false;
        }
    }
}
