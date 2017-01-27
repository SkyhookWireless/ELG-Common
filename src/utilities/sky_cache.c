#include <stdio.h>
#include <stdlib.h>
#include <time.h>
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

//
// Note: for all seters and getters, it is assumed that the cache memory (heap) has been allocated.
//

bool ap_get_cache_key(uint32_t idx, char * key) {
    if (cache.type != DATA_TYPE_AP || idx >= cache.buf_size || key == NULL) {
        return false;
    }
    copy_bytes(key, cache.buf[idx].key, cache.key_size);
    return true;
}

bool ap_set_cache_key(uint32_t idx, const char * key) {
    if (cache.type != DATA_TYPE_AP || idx >= cache.buf_size || key == NULL) {
        return false;
    }
    copy_bytes(cache.buf[idx].key, key, cache.key_size);
    return true;
}

bool ap_get_cache_value(uint32_t idx, int8_t value) {
    if (cache.type != DATA_TYPE_AP || idx >= cache.buf_size) {
        return false;
    }
    value = *(int8_t *)cache.buf[idx].value;
    return true;
}

bool ap_set_cache_value(uint32_t idx, int8_t value) {
    if (cache.type != DATA_TYPE_AP || idx >= cache.buf_size) {
        return false;
    }
    *(int8_t *)cache.buf[idx].value = value;
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
    for (; i<cache.key_size; ++i) {
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
bool compare_cache_value(uint32_t idx, const char * value) {
    if (idx >= MAX_CACHE_SIZE) {
        return false;
    }
    uint8_t i = 0;
    for (; i<cache.value_size; ++i) {
        if (cache.buf[idx].value[i] != value[i]) {
            return false;
        }
    }
    return true;
}

/**
 * Initialize a cache.
 * @param type : cache data type
 * @param cache_size : the size of the cache
 * @param key_size : the size of key
 * @param value_size : the size of value
 */
void sky_cache_init(enum SKY_DATA_TYPE type, uint32_t cache_size,
        uint32_t key_size, uint32_t value_size) {
    cache.type = type;
    cache.buf_size = cache_size;
    cache.key_size = key_size;
    cache.value_size = value_size;
    cache.timestamp = (uint32_t)time(NULL); // in seconds
}

/**
 * Reset a cache.
 * @param type : cache data type
 */
void sky_cache_reset(enum SKY_DATA_TYPE type) {
    cache.type = DATA_TYPE_PAD;
    cache.buf_size = 0;
    cache.key_size = 0;
    cache.value_size = 0;
    cache.timestamp = 0;
}

/**
 * Save cache in file.
 * @param type : cache data type
 * @return true on success; false on failure.
 */
bool save_cache(enum SKY_DATA_TYPE type) {
    switch (type) {
    case DATA_TYPE_AP: {
        FILE *fp = fopen(SKY_AP_CACHE_FILENAME, "w");
        if (!fp) {
            return false;
        }
        fprintf(fp, "%d\n", cache.buf_size);
        uint32_t i = 0;
        for (; i<cache.buf_size; ++i) {
            uint8_t j = 0;
            for (; j<cache.key_size; ++j) {
                fprintf(fp, "%02X", cache.buf[i].key[j] & 0xFF);
            }
            fprintf(fp, " %" SCNd8 "\n", *(int8_t *)cache.buf[i].value);
            // SCNd8 - http://stackoverflow.com/questions/26618443/how-to-use-int16-t-or-int32-t-with-functions-like-scanf
        }
        fclose(fp);
        return true;
    }
    default:
        return false;
    }
}

/**
 * Load file into cache.
 * @param type : cache data type
 * @return true on success; false on failure.
 */
bool load_cache(enum SKY_DATA_TYPE type) {
    switch (type) {
    case DATA_TYPE_AP: {
        FILE *fp = fopen(SKY_AP_CACHE_FILENAME, "r");
        if (!fp) {
            return false;
        }
        fscanf(fp, "%d", &cache.buf_size);
        uint32_t i = 0;
        for (; i<cache.buf_size; ++i) {
            char mac[cache.key_size * 2 + 1];
            fscanf(fp, "%s %" SCNd8, mac, (int8_t *)cache.buf[i].value);
            // SCNd8 - http://stackoverflow.com/questions/26618443/how-to-use-int16-t-or-int32-t-with-functions-like-scanf
            // fscanf uses white space to separate string.
            hex2bin(mac, sizeof(mac), (uint8_t *)cache.buf[i].key, cache.key_size);
        }
        fclose(fp);
        return true;
    }
    default:
        return false;
    }
}

/**
 * Check if cache is empty.
 * @return true on empty; false on not empty.
 */
bool is_sky_cache_empty() {
    load_cache(DATA_TYPE_AP);
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
bool sky_cache_add(uint32_t idx, const char * key, const char * value) {
    if (idx >= cache.buf_size) {
        return false;
    }
    copy_bytes(cache.buf[idx].key, key, cache.key_size);
    copy_bytes(cache.buf[idx].value, value, cache.value_size);
    return true;
}

/**
 * Create and cache an array of APs.
 * Note: automatically truncate the APs more than MAX_CACHE_SIZE.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 */
void cache_aps(const struct ap_t * aps, uint32_t aps_size) {
    if (aps_size > MAX_CACHE_SIZE) {
        aps_size = MAX_CACHE_SIZE;
    }
    sky_cache_init(DATA_TYPE_AP, aps_size, MAC_SIZE, sizeof(int8_t));
    uint32_t i = 0;
    for (; i<aps_size; ++i) {
        sky_cache_add(i, (char *)aps[i].MAC, (char *)&aps[i].rssi);
    }
    save_cache(DATA_TYPE_AP);
}

/**
 * Check if the cache matching is satisfied.
 * @param aps : array pointer of APs
 * @param aps_size : the size of the array of APs
 * @param p : percentage to satisfy matching criteria
 * @return true on matching; false on not-matching.
 */
bool is_ap_cache_match(const struct ap_t * aps, uint32_t aps_size, float p) {
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
 * Create cache with proper memory allocation.
 * @param key_size : the size of key in bytes
 * @param value_size : the size of value in bytes
 * @return true on success; false on failure.
 */
bool sky_cache_create(uint32_t key_size, uint32_t value_size) {
    uint32_t i = 0;
    for (; i<MAX_CACHE_SIZE; ++i) {
        cache.buf[i].key = (char *)malloc(key_size);
        if (cache.buf[i].key == NULL) {
            return false;
        }
        cache.buf[i].value = (char *)malloc(value_size);
        if (cache.buf[i].value == NULL) {
            return false;
        }
    }
    return true;
}

/**
 * Free cache with proper memory reclamation.
 */
void sky_cache_free() {
    uint32_t i = 0;
    for (; i<MAX_CACHE_SIZE; ++i) {
        if (cache.buf[i].key != NULL) {
            free(cache.buf[i].key);
        }
        if (cache.buf[i].value != NULL) {
            free(cache.buf[i].value);
        }
    }
}

/**
 * Check if cache matching is satisfied.
 * If so, it is not necessary to query locations.
 * @param req : location request structure
 * @param type : cache data type
 * @param match_percentage : the percentage to satisfy matching criteria
 * @return true on matching; false on not matching.
 */
bool check_cache_match(const struct location_rq_t * req, enum SKY_DATA_TYPE type, float match_percentage) {
    switch (type) {
    case DATA_TYPE_AP:
        if ((cache.buf_size < MIN_CACHE_APS)
                || (time(NULL) - cache.timestamp > MAX_CACHE_TIME)) {
            // delete cache if cache size is too small or cache timestamp is too long
            sky_cache_reset(type);
        }
        if (is_sky_cache_empty()) {
            cache_aps(req->aps, req->ap_count);
            return false;
        } else {
            if (is_ap_cache_match(req->aps, req->ap_count, match_percentage)) {
                return true; // same location, no need to send out location request.
            } else {
                sky_cache_reset(type);
                cache_aps(req->aps, req->ap_count);
                return false;
            }
        }
    default:
        return false;
    }
}
