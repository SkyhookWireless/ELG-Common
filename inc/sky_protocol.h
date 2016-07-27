/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_PROTOCOL_H
#define SKY_PROTOCOL_H

#include "sky_types.h"

#define SKY_PROTOCOL_VERSION    1

#define SERVER_ERR              0xFF

#define IV_OFFSET_1    8

#ifndef ENOBUFS
#define ENOBUFS (ENOMEM)
#endif


// Note: For multi-byte integers, the server code runs on little-endian machines.
//       As the protocol requires little-endianness, server code does not need to
//       concern about byte ordering.
typedef struct sky_protocol_packet_header {
    uint8_t version;           // protocol version
    uint8_t unused;            // padding byte
    uint16_t payload_length;   // payload length
    uint32_t user_id;          // user id
    uint8_t iv[16];            // initialization vector
} sky_header;

typedef struct sky_protocol_data_entry {
    uint8_t data_type;         // data type enum (i.e. SkyDataType)
    uint8_t data_type_count;   // data type count
} sky_entry;

// read and write in place in buffer
typedef struct sky_protocol_data_entry_ex {
    sky_entry * entry;         // entry without data
    uint8_t * data;            // array size = sizeof(data type) * count
} sky_entry_ex;

typedef struct sky_protocol_packet_payload {
    uint8_t sw_version;         // client sw version for request and server sw version for response
    uint8_t mac[6];             // client device MAC address
    uint8_t type;               // payload type
    uint8_t ipv6[16];           // client ip address: ipv4 is set at the first 4 bytes with
                                // the rest 12 bytes being set to zeros.
    uint8_t timestamp[8];       // timestamp in milliseconds
} sky_payload;

typedef struct sky_protocol_packet_payload_ex {
    sky_payload payload;        // payload without data entries
    sky_entry_ex data_entry;    // data_entry is updated to iterate over an unbounded array of data entries in buffer
} sky_payload_ex;

typedef uint16_t sky_checksum;


/***********************************************
 BINARY REQUEST PROTOCOL FORMAT
 ************************************************
 0  - protocol version 0
 1  - client id 0
 2  - client id 1
 3  - client id 2
 4  - client id 3
 5  - entire payload length 0 - LSB count includes byte 0
 6  - entire payload length 1 - MSB
 7  - iv 0
 8  - iv 1
 9  - iv 2
 10 - iv 3
 11 - iv 4
 12 - iv 5
 13 - iv 6
 14 - iv 7
 15 - iv 8
 16 - iv 9
 17 - iv 10
 18 - iv 11
 19 - iv 12
 20 - iv 13
 21 - iv 14
 22 - iv 15
 --- encrypted after this ---
 23 - client software version
 24 - client MAC 0
 25 - client MAC 1
 26 - client MAC 2
 27 - client MAC 3
 28 - clinet MAC 4
 29 - clinet MAC 5
 30 - payload type -- e.g. location request
 -------------------
 payload data can be out of order (type,count/size,data)
 31 - data type -- refers to DATA_TYPE enum and struct
 32 - data type count -- this a the number of structs (0 - 255)
 33 - data... memcopied data struct (ap, cell, ble, gps)
 ...
 n - 2 verify 0 fletcher 16
 n - 1 verify 1 fletcher 16
 *************************************************/

/***********************************************
 BINARY RESPONSE PROTOCOL FORMAT
 ************************************************
 0  - protocol version
 1  - entire payload length 0 - LSB count includes byte 0
 2  - entire payload length 1 - MSB
 3  - iv 0
 4  - iv 1
 5  - iv 2
 6  - iv 3
 7  - iv 4
 8  - iv 5
 9  - iv 6
 10 - iv 7
 11 - iv 8
 12 - iv 9
 13 - iv 10
 14 - iv 11
 15 - iv 12
 16 - iv 13
 17 - iv 14
 18 - iv 15
 --- encrypted after this ---
 19 - server software version
 20 - timestamp 0
 21 - timestamp 1
 22 - timestamp 2
 23 - timestamp 3
 24 - timestamp 4
 25 - timestamp 5
 26 - payload type -- e.g. location request
 27 - lat 8 bytes
 35 - lon 8 bytes
 43 - hpe 4 bytes
 (47) optional 6 - byte device MAC
 -------------------
 payload data can be out of order (type,count/size,data)
 47 - data type -- refers to DATA_TYPE enum and struct
 48 - data type count -- this a the number of structs (0 - 255)
 49 - data... memcopied data struct (ap, cell, ble, gps)
 ...
 n - 2 verify 0 fletcher 16
 n - 1 verify 1 fletcher 16
 *************************************************/

// find aes key  based on userid in key root and set it
//int sky_set_key(void *key_root, struct location_head_t *head);
uint32_t sky_get_userid(uint8_t *buff, int32_t buff_len);

// received by the server from the client
// decode binary data from client, result is in the location_req_t struct
int32_t sky_decode_req_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_req_t *creq);

// sent by the server to the client
// encodes the loc struct into binary formatted packet sent to client
// returns the packet len or -1 when fails
int32_t sky_encode_resp_bin(uint8_t *buff, uint32_t buff_len,
        struct location_resp_t *cresp);

// sent by the client to the server
/* encodes the request struct into binary formatted packet */
// returns the packet len or -1 when fails
int32_t sky_encode_req_bin(uint8_t *buff, uint32_t buff_len,
        struct location_req_t *creq);

// received by the client from the server
/* decodes the binary data and the result is in the location_resp_t struct */
int32_t sky_decode_resp_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_resp_t *cresp);

#endif

#ifdef __cplusplus
}
#endif
