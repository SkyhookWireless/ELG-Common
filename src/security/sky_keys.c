#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "sky_util.h"
#include "sky_keys.h"

int32_t cmp_keys(const void *pa, const void *pb) {
    struct sky_key_t *ka, *kb;

    ka = (struct sky_key_t *) pa;
    kb = (struct sky_key_t *) pb;

    if (ka->userid < kb->userid)
        return -1;
    if (ka->userid > kb->userid)
        return 1;

    return 0;
}

/* key file format
 * 0 - userid
 * 1 - aes key
 * 2 - keyid (api key)
 * 3 - relay url
 * 4 - relay port
 */
int32_t parse_key(char *line, struct sky_key_t *key, int32_t field_count) {
    int32_t v, slen;
    int32_t ix = 0;
    char *pEnd;

    //if (field_count != 2 && field_count != 3) return -1;
    --field_count;

    // split csv line
    char *record = strtok(line, ",");

    if (record == NULL)
        return PARSE_ERR_BAD_RECORD;

    while (record != NULL) {
        if (ix > field_count)
            return 0; // stop at field_count

        switch (ix) {
            case 0: // userid
            {
                errno = 0;
                key->userid = (uint32_t) strtol(record, &pEnd, 10); // convert record to 10 base int
                if (errno)
                    return PARSE_ERR_USERID;
                break;
            }
            case 1: // aes key
            {
                v = hex2bin(record, (int32_t) strlen(record), key->aes_key,
                        sizeof(key->aes_key));
                if (v < 16)
                    return PARSE_ERR_AESKEY; // has to be at least 16 byte/32char
                break;
            }
            case 2: // api key
            {
                slen = (int32_t) strlen(record);
                if (slen == 0)
                    return PARSE_ERR_FIELDSHORT;
                v = trimc(key->keyid, sizeof(key->keyid), record, slen);
                if (v <= 0)
                    return PARSE_ERR_APIKEY;
                break;
            }
            /* the following fields are optional */
            case 3: // url
            {
                slen = (int32_t) strlen(record);
                if (slen == 0)
                    break;

                int32_t end;
                int32_t start = trim(record, slen, &end);
                char *url = &record[start];
                strncpy(key->relay.srv.url, url, strlen(url));
                key->relay.srv.url[strlen(url)] = '\0';
                key->relay.valid = 1; // mark it valid
                break;
            }
            case 4: // echo server credential
            {
                slen = (int32_t) strlen(record);
                if (slen == 0) {
                    key->relay.valid = 0;
                    return PARSE_ERR_CRED;
                }

                int32_t end;
                int32_t start = trim(record, slen, &end);
                char *cred = &record[start];
                strncpy(key->relay.srv.cred, cred, strlen(cred));
                key->relay.srv.cred[strlen(cred)] = '\0';
                break;
            }
        }

        record = strtok(NULL, ","); // get next item
        ix++;
    }

    return 0;
}

int32_t load_key(char *path, struct sky_key_t *key) {
    int32_t res = -1;

    FILE *fp;
    char line[1024]; // 10 uid + 128 key id + 16 aes key + 16 x 16 iv

    if (access(path, F_OK | R_OK) == -1) {
        fprintf(stderr, "cannot access key file %s\n", path);
        return -1;
    }

    fp = fopen(path, "r");

    if (fp == NULL) {
        fprintf(stderr, "Can't open key file: %s\n", path);
        return -1;
    }

    // read key file line by line
    while (fgets(line, sizeof(line), fp) != NULL) {
        // once we found the key stop searching
        res = parse_key(line, key, 2);
        if (res < 0)
            break;
    }

    if (fclose(fp)) {
        perror("could not close key file");
        return -1;
    }

    return res;
}

/* load keys from csv file and stores them into root binary tree */
int32_t load_keys_from_file(char *path, void **root) {
    /* LOAD KEYS FILE */
    /* CSV file format
     id, id_key, aes_key
     id -- stored as decimal
     id_key -- char string
     aes_key -- hex string
     relay url -- char string
     relay port -- decimal
     */

    FILE *fp;

    char line[1024]; // 10 uid + 128 key id + 16 aes key + 16 x 16 iv

    if (access(path, F_OK | R_OK) == -1) {
        fprintf(stderr, "cannot access key file %s\n", path);
        return -1;
    }

    fp = fopen(path, "r");

    if (fp == NULL) {
        fprintf(stderr, "Can't open key file: %s\n", path);
        return -1;
    }

    int32_t count = 0;

    // read key file line by line
    while (fgets(line, sizeof(line), fp) != NULL) {
        struct sky_key_t k;
        k.relay.valid = 0;

        int32_t res = parse_key(line, &k, 5);

        if (res < 0)
            continue;

        // key will be freed by free_keystore (tdestroy, twalk)
        struct sky_key_t *key = (struct sky_key_t*) malloc(
                sizeof(struct sky_key_t));

        if (key == NULL) {
            perror("out of memory");
            return (-1);
        }

        memcpy(key, &k, sizeof(k));

        /* add key to binary tree */
        void *p = tsearch(key, root, cmp_keys);

        if (p == NULL) {
            perror("NULL key\n");
            return -1;
        }
        count++;
    }

    if (fclose(fp)) {
        perror("could not close key file");
    }

    return count;
}
/*
 void walk_free(const void *node, const VISIT which, const int depth)
 {
 struct aes_key_t *k;
 k = *(struct aes_key_t **)node;

 if (k->relay.url != NULL)
 {
 printf("free url [%d] %p\n", k->userid, k->relay.url);
 free(k->relay.url);
 }
 }
 */

// release the key storage mem
void free_keystore(void *root) {

    if (root == NULL) {
        printf("keystore is empty\n");
        return;
    }

    //printf("free keystore %p\n", root);
    //twalk(root, walk_free);
    tdestroy(root, free);
}

struct sky_key_t *find_key(void *root, uint32_t userid) {
    // TODO decrypt key
    // for extra safety the aes keys are stored in memory xored
    struct sky_key_t key;
    key.userid = userid;
    void *ret = tfind(&key, &root, cmp_keys);

    if (ret == NULL)
        return NULL;
    return *(struct sky_key_t **) ret;
}

void print_key(struct sky_key_t *k) {
    puts("------------------------");
    printf("%p\nuserid: %d\n", k, k->userid);

    printf("AES key: ");
    print_buff(k->aes_key, 16);

    printf("api key: %s\n", k->keyid);

    printf("relay ip: ");

    if (k->relay.valid)
        printf("%s\n",k->relay.srv.url);
    else
        printf("\n");

    printf("relay port: %s\n", k->relay.srv.cred);
}

void walker(const void *node, const VISIT which, const int32_t depth) {
    struct sky_key_t *k;
    k = *(struct sky_key_t **) node;
    print_key(k);
}

void print_key_tree(void *root) {
    puts("********************");
    printf("KEY TREE\n");
    puts("********************");
    twalk(root, walker);
}
