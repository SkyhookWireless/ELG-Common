#include <string.h>
#include <uthash.h> // git cloned from https://github.com/troydhanson/uthash

// LRU cache in C using uthash

#define MAX_CACHE_SIZE 100

struct cache_entry {
    char *key;
    char *value;
    UT_hash_handle hh;
};

struct cache_entry *cache = NULL;

char * sky_cache_lookup(char *key) {
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

void sky_cache_add(char *key, char *value) {
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
