/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/
/**************************************
 manages AES key storage and lookup

 TODO for more secure operations remove key
 from memory after each use
 ***************************************/
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_KEYES_H
#define SKY_KEYES_H

#include <inttypes.h>
#include <search.h>
#include "sky_protocol.h"

#define PARSE_ERR_BAD_RECORD    -1
#define PARSE_ERR_USERID        -2
#define PARSE_ERR_AESKEY        -3
#define PARSE_ERR_APIKEY        -4
#define PARSE_ERR_FIELDSHORT    -5
#define PARSE_ERR_URL           -6
#define PARSE_ERR_PORT          -7
#define PARSE_ERR_OUTOFMEM      -8
#define PARSE_ERR_HOSTNOTFOUND  -9

int load_key(char *path, struct sky_key_t *key);
int load_keys_from_file(char *path, void **root);
void free_keystore(void *root);

void print_key(struct sky_key_t *k);
struct sky_key_t *find_key(void *root, uint32_t userid);
void print_key_tree(void *root);

#endif

#ifdef __cplusplus
}
#endif
