#include <stdio.h>
#include "sky_cache.h"
#include "sky_util.h"

// cache array
static sky_cache_t cache;

/**
 * Copy byte array.
 * @param to : destination array
 * @param from : source array
 * @param size : size of the array to copy
 * @return true on success; false on failure.
 */
bool copy_bytes(char * to, const char * from, uint32_t size) {
    if (!to || !from) {
        return false;
    }
    uint32_t i = 0;
    for (; i<size; ++i) {
        to[i] = from[i];
    }
    return true;
}

/**
 * Compare the key in cache.
 * @param idx : index in cache to compare
 * @param key : the key to compare
 * @return true on equivalent; false on different.
 */
bool compare_cache_key(uint32_t idx, const char * key) {
    if (idx >= MAX_CACHE_SIZE) {
        return false;
    }
    uint8_t i = 0;
    for (; i<sizeof(cache.buf[idx].key); ++i) {
        if (cache.buf[idx].key[i] != key[i]) {
            return false;
        }
    }
    return true;
}

/**
 * Compare the value in cache.
 * @param idx : index in cache to compare
 * @param value : the value to compare
 * @return true on equivalent; false on different.
 */
bool compare_cache_value(uint32_t idx, int8_t value) {
    if (cache.buf[idx].value == value) {
        return true;
    } else {
        return false;
    }
}

/**
 * Create a cache in memory.
 * @param size : the size of the cache
 * @return true on success; false on failure.
 */
void create_cache(uint32_t size) {
    cache.buf_size = size;
}

/**
 * Delete a cache.
 */
void delete_cache() {
    cache.buf_size = 0;
}

/**
 * Save cache in file.
 * @return true on success; false on failure.
 */
bool save_cache() {
    FILE *fp = fopen(SKY_CACHE_FILENAME, "w");
    if (!fp) {
        return false;
    }
    fprintf(fp, "%d\n", cache.buf_size);
    uint32_t i = 0;
    for (; i<cache.buf_size; ++i) {
        uint8_t j = 0;
        for (; j<sizeof(cache.buf[i].key); ++j) {
            fprintf(fp, "%02X", cache.buf[i].key[j] & 0xFF);
        }
        fprintf(fp, " %" SCNd8 "\n", cache.buf[i].value);
        // SCNd8 - http://stackoverflow.com/questions/26618443/how-to-use-int16-t-or-int32-t-with-functions-like-scanf
    }
    fclose(fp);
    return true;
}

/**
 * Load file into cache.
 * @return true on success; false on failure.
 */
bool load_cache() {
    FILE *fp = fopen(SKY_CACHE_FILENAME, "r");
    if (!fp) {
        return false;
    }
    fscanf(fp, "%d", &cache.buf_size);
    uint32_t i = 0;
    for (; i<cache.buf_size; ++i) {
        char mac[sizeof(cache.buf[i].key) * 2 + 1];
        fscanf(fp, "%s %" SCNd8, mac, &cache.buf[i].value);
        // SCNd8 - http://stackoverflow.com/questions/26618443/how-to-use-int16-t-or-int32-t-with-functions-like-scanf
        // fscanf uses white space to separate string.
        hex2bin(mac, sizeof(mac), (uint8_t *)cache.buf[i].key, sizeof(cache.buf[i].key));
    }
    fclose(fp);
    return true;
}

/**
 * Check if cache is empty.
 * @return true on empty; false on not empty.
 */
bool is_cache_empty() {
    load_cache();
    if (cache.buf_size == 0) {
        return true;
    } else {
        return false;
    }
}

/**
 * Look up the key in cache.
 * @param key : the key to look up
 * @return the cache entry associated with the key on success;
 *         or NULL on failure.
 */
cache_entry_t * sky_cache_lookup(const char *key) {
    uint32_t i = 0;
    for (; i<cache.buf_size; ++i) {
        if (compare_cache_key(i, key)) {
            return &cache.buf[i];
        }
    }
    return NULL;
}

/**
 * Add key-value pairs into the cache.
 * @param idx : index in cache to add
 * @param key : key to add
 * @param value : value to add
 * @return true on success; false on failure.
 */
bool sky_cache_add(uint32_t idx, const char *key, int8_t value) {
    if (idx >= cache.buf_size) {
        return false;
    }
    copy_bytes(cache.buf[idx].key, key, sizeof(cache.buf[idx].key));
    cache.buf[idx].value = value;
    return true;
}

/**
 * Create and cache an array of APs.
 * Note: automatically truncate the APs more than MAX_CACHE_SIZE.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 */
void cache_aps(const struct ap_t *aps, uint32_t aps_size) {
    if (aps_size > MAX_CACHE_SIZE) {
        aps_size = MAX_CACHE_SIZE;
    }
    create_cache(aps_size);
    uint32_t i = 0;
    for (; i<aps_size; ++i) {
        sky_cache_add(i, (char *)aps[i].MAC, aps[i].rssi);
    }
    save_cache();
}

/**
 * Check if the cache matching is satisfied.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 * @param p : percentage to satisfy matching criteria
 * @return true on matching; false on not-matching.
 */
bool is_cache_match(const struct ap_t *aps, uint32_t aps_size, float p) {
    if (aps_size > MAX_CACHE_SIZE) {
        aps_size = MAX_CACHE_SIZE;
    }
    uint32_t n = 0, i;
    for (i=0; i<aps_size; ++i) {
        if (sky_cache_lookup((char *)aps[i].MAC) != NULL) {
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
bool check_cache_match(const struct location_rq_t* req, float match_percentage) {
    if (is_cache_empty()) {
        cache_aps(req->aps, req->ap_count);
        return false;
    } else {
        if (is_cache_match(req->aps, req->ap_count, match_percentage)) {
            return true; // same location, no need to send out location request.
        } else {
            delete_cache();
            cache_aps(req->aps, req->ap_count);
            return false;
        }
    }
}
