#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sky_cache.h"
#include "sky_util.h"

// cache array
static sky_cache_t cache;

//
// Note: for all setters and getters, it is assumed that the cache memory
// (heap) has already been allocated.
//

bool sky_ap_get_cache_key(uint32_t idx, char * key) {
    if (cache.type != DATA_TYPE_AP || idx >= cache.num_entries || key == NULL) {
        return false;
    }
    memcpy(key, cache.entry[idx].key, cache.key_size);
    return true;
}

bool sky_ap_set_cache_key(uint32_t idx, const char * key) {
    if (cache.type != DATA_TYPE_AP || idx >= cache.num_entries || key == NULL) {
        return false;
    }
    memcpy(cache.entry[idx].key, key, cache.key_size);
    return true;
}

bool sky_ap_get_cache_value(uint32_t idx, int8_t value) {
    if (cache.type != DATA_TYPE_AP || idx >= cache.num_entries) {
        return false;
    }
    value = *(int8_t *)cache.entry[idx].value;
    return true;
}

bool sky_ap_set_cache_value(uint32_t idx, int8_t value) {
    if (cache.type != DATA_TYPE_AP || idx >= cache.num_entries) {
        return false;
    }
    *(int8_t *)cache.entry[idx].value = value;
    return true;
}

/**
 * Compare the key in cache.
 *
 * @param idx : index in cache to compare
 * @param key : the key to compare
 * @return true on equivalent; false on different.
 */
bool sky_compare_cache_key(uint32_t idx, const char * key) {
    if (idx >= MAX_CACHE_ELEMENTS) {
        return false;
    }
    uint8_t i = 0;
    for (; i<cache.key_size; ++i) {
        if (cache.entry[idx].key[i] != key[i]) {
            return false;
        }
    }
    return true;
}

/**
 * Compare the value in cache.
 *
 * @param idx : index in cache to compare
 * @param value : the value to compare
 * @return true on equivalent; false on different.
 */
bool sky_compare_cache_value(uint32_t idx, const char * value) {
    if (idx >= MAX_CACHE_ELEMENTS) {
        return false;
    }
    uint8_t i = 0;
    for (; i<cache.value_size; ++i) {
        if (cache.entry[idx].value[i] != value[i]) {
            return false;
        }
    }
    return true;
}

void sky_cache_init(enum SKY_DATA_TYPE type, uint32_t num_entries) {
    cache.type = type;
    cache.num_entries = num_entries;
    cache.timestamp = (uint32_t)time(NULL); // in seconds
}

void sky_cache_clear(enum SKY_DATA_TYPE type) {
    cache.type = DATA_TYPE_PAD;
    cache.num_entries = 0;
    cache.timestamp = 0;
}

/**
 * Save cache in file.
 *
 * @param type : cache data type
 * @return true on success; false on failure.
 */
bool save_cache(enum SKY_DATA_TYPE type) {
#ifdef SKY_FILE_SYSTEM_EXISTS
    switch (type) {
    case DATA_TYPE_AP: {
        FILE *fp = fopen(SKY_AP_CACHE_FILENAME, "w");
        if (!fp) {
            return false;
        }
        fprintf(fp, "%d\n", cache.timestamp);
        fprintf(fp, "%d\n", cache.num_entries);
        uint32_t i = 0;
        for (; i<cache.num_entries; ++i) {
            uint8_t j = 0;
            for (; j<cache.key_size; ++j) {
                fprintf(fp, "%02X", cache.entry[i].key[j] & 0xFF);
            }
            fprintf(fp, " %" SCNd8 "\n", *(int8_t *)cache.entry[i].value);
            // SCNd8 - http://stackoverflow.com/questions/26618443/how-to-use-int16-t-or-int32-t-with-functions-like-scanf
        }
        fclose(fp);
        return true;
    }
    default:
        return false;
    }
#else
    (void)type; // suppress the warning of unused variables
    return true;
#endif
}

/**
 * Load file into cache.
 *
 * @param type : cache data type
 * @return true on success; false on failure.
 */
bool load_cache(enum SKY_DATA_TYPE type) {
#ifdef SKY_FILE_SYSTEM_EXISTS
    switch (type) {
    case DATA_TYPE_AP: {
        FILE *fp = fopen(SKY_AP_CACHE_FILENAME, "r");
        if (!fp) {
            return false;
        }
        if (fscanf(fp, "%d", &cache.timestamp) != 1) {
            return false;
        }
        if (fscanf(fp, "%d", &cache.num_entries) != 1) {
            return false;
        }
        uint32_t i = 0;
        for (; i<cache.num_entries; ++i) {
            char mac[cache.key_size * 2 + 1];
            if (fscanf(fp, "%s %" SCNd8, mac, (int8_t *)cache.entry[i].value) != 2) {
                return false;
            }
            // SCNd8 - http://stackoverflow.com/questions/26618443/how-to-use-int16-t-or-int32-t-with-functions-like-scanf
            // fscanf uses white space to separate string.
            hex2bin(mac, sizeof(mac), (uint8_t *)cache.entry[i].key, cache.key_size);
        }
        fclose(fp);
        return true;
    }
    default:
        return false;
    }
#else
    (void)type; // suppress the warning of unused variables
    return true;
#endif
}

bool sky_is_cache_empty() {
    if (cache.num_entries == 0) {
        return true;
    } else {
        return false;
    }
}

cache_entry_t * sky_cache_lookup(const char *key) {
    uint32_t i = 0;
    for (; i<cache.num_entries; ++i) {
        if (sky_compare_cache_key(i, key)) {
            return &cache.entry[i];
        }
    }
    return NULL;
}

bool sky_cache_add(uint32_t idx, const char * key, const char * value) {
    if (idx >= cache.num_entries) {
        return false;
    }
    memcpy(cache.entry[idx].key, key, cache.key_size);
    memcpy(cache.entry[idx].value, value, cache.value_size);
    return true;
}

void sky_cache_aps(const struct ap_t * aps, uint32_t aps_size) {
    if (aps_size > MAX_CACHE_ELEMENTS) {
        aps_size = MAX_CACHE_ELEMENTS;
    }
    sky_cache_init(DATA_TYPE_AP, aps_size);
    uint32_t i = 0;
    for (; i<aps_size; ++i) {
        sky_cache_add(i, (char *)aps[i].MAC, (char *)&aps[i].rssi);
    }
    save_cache(DATA_TYPE_AP);
}

bool sky_is_ap_cache_match(const struct ap_t * aps, uint32_t aps_size, float p) {
    if (aps_size > MAX_CACHE_ELEMENTS) {
        aps_size = MAX_CACHE_ELEMENTS;
    }
    uint32_t n = 0, i;
    for (i=0; i<aps_size; ++i) {
        if (sky_cache_lookup((char *)aps[i].MAC) != NULL) {
            ++n;
        }
    }
    if ((float)n/aps_size < p) {
        return false; // doesn't match
    } else {
        return true;  // matches
    }
}

bool sky_cache_create(uint32_t key_size, uint32_t value_size) {
    if (cache.is_created) {
        return true;
    }
    cache.key_size = key_size;
    cache.value_size = value_size;
    uint32_t i = 0;
    for (; i<MAX_CACHE_ELEMENTS; ++i) {
        cache.entry[i].key = (char *)malloc(key_size);
        if (cache.entry[i].key == NULL) {
            return false;
        }
        cache.entry[i].value = (char *)malloc(value_size);
        if (cache.entry[i].value == NULL) {
            return false;
        }
    }
    cache.is_created = true;
    return true;
}

void sky_cache_free() {
    uint32_t i = 0;
    for (; i<MAX_CACHE_ELEMENTS; ++i) {
        if (cache.entry[i].key != NULL) {
            free(cache.entry[i].key);
            cache.entry[i].key = NULL;
        }
        if (cache.entry[i].value != NULL) {
            free(cache.entry[i].value);
            cache.entry[i].value = NULL;
        }
    }
    cache.key_size = 0;
    cache.value_size = 0;
    cache.is_created = false;
}

bool sky_cache_match(const struct location_rq_t * req, enum SKY_DATA_TYPE type, float match_percentage) {
    switch (type) {
    case DATA_TYPE_AP:
        load_cache(type);
        if ((cache.num_entries < MIN_CACHE_APS)
                || (time(NULL) - cache.timestamp > MAX_CACHE_TIME)) {
            // clear the cache if the set of cached scans is too small or too stale
            sky_cache_clear(type);
        }
        if (sky_is_cache_empty()) {
            sky_cache_aps(req->aps, req->ap_count);
            return false;
        } else {
            if (sky_is_ap_cache_match(req->aps, req->ap_count, match_percentage)) {
                return true; // new scan is essentially the same as the previous scan
            } else {
                sky_cache_clear(type);
                sky_cache_aps(req->aps, req->ap_count);
                return false;
            }
        }
    default:
        return false;
    }
}
