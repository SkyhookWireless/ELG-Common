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

#include <inttypes.h>
#include <netinet/in.h>

#define SKY_PROTOCOL_VERSION    1

#define SERVER_ERR              0xFF

#define IV_OFFSET_1    8

#ifndef ENOBUFS
#define ENOBUFS (ENOMEM)
#endif


// stored in one byte
enum SKY_DATA_TYPE {
    DATA_TYPE_PAD = 0,      // padding byte
    DATA_TYPE_AP = 1,       // access point
    DATA_TYPE_GPS,          // gps
    DATA_TYPE_GSM,          // cell gsm
    DATA_TYPE_CDMA,         // cell cdma
    DATA_TYPE_UMTS,         // cell umts
    DATA_TYPE_LTE,          // cell lte
    DATA_TYPE_BLE,          // bluetooth

    DATA_TYPE_BASIC,        // lat and lon
    DATA_TYPE_STREET_NUM,
    DATA_TYPE_ADDRESS,
    DATA_TYPE_CITY,
    DATA_TYPE_STATE,
    DATA_TYPE_STATE_CODE,
    DATA_TYPE_METRO1,
    DATA_TYPE_METRO2,
    DATA_TYPE_POSTAL_CODE,
    DATA_TYPE_COUNTY,
    DATA_TYPE_COUNTRY,
    DATA_TYPE_COUNTRY_CODE,
    DATA_TYPE_DIST_POINT,

    DATA_TYPE_IPV4,         // ipv4 address
    DATA_TYPE_IPV6,         // ipv6 address
    DATA_TYPE_MAC,          // device MAC address
};

/* request payload types */
enum SKY_REQ_PAYLOAD_TYPE {
    REQ_PAYLOAD_TYPE_NONE = 0,  // initialization value

    LOCATION_RQ,                // location request
    LOCATION_RQ_ADDR,           // location request full
    PROBE_REQUEST,              // probe test
};

/* response payload types */
enum SKY_RSP_PAYLOAD_TYPE {
    RSP_PAYLOAD_TYPE_NONE = 0,  // initialization value

    /* success code */
    LOCATION_RQ_SUCCESS,
    LOCATION_RQ_ADDR_SUCCESS,
    PROBE_REQUEST_SUCCESS,

    /* error code */
    LOCATION_RQ_ERROR = 100,
    LOCATION_GATEWAY_ERROR,
    LOCATION_API_ERROR,
};

// internal error codes
enum STATUS {
    OK = 0,
    ZLOG_INIT_PERM,
    ZLOG_INIT_ERR,
    LOAD_CONFIG_FAILED,
    HOST_UNKNOWN,
    LOAD_KEYS_FAILED,
    BAD_KEY,
    CREATE_THREAD_FAILED,
    SETSOCKOPT_FAILED,
    SOCKET_OPEN_FAILED,
    SOCKET_CONN_FAILED,
    SOCKET_BIND_FAILED,
    SOCKET_LISTEN_FAILED,
    SOCKET_ACCEPT_FAILED,
    SOCKET_RECV_FAILED,
    SOCKET_READ_FAILED,
    SOCKET_WRITE_FAILED,
    SOCKET_TIMEOUT_FAILED,
    MSG_TOO_SHORT,
    SEND_PROBE_FAILED,
    SEND_UDF_PROT_FAILED,
    SENDTO_FAILED,
    DECRYPT_BIN_FAILED,
    ENCODE_XML_FAILED,
    DECODE_BIN_FAILED,
    ENCODE_BIN_FAILED,
    ENCRYPT_BIN_FAILED,
    DECODE_XML_FAILED,
    CREATE_META_FAILED,

    /* HTTP response codes >= 100 */
    /* http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html */
};

// Note: For multi-byte integers, the server code runs on little-endian machines.
//       As the protocol requires little-endianness, server code does not need to
//       concern about byte ordering.
typedef struct sky_protocol_packet_header {
    uint8_t version;           // protocol version
    uint8_t unused;            // padding byte
    uint16_t payload_length;   // payload length
    uint32_t user_id;          // user id
    uint8_t iv[16];            // initialization vector
} sky_header_t;

typedef struct sky_protocol_data_entry {
    uint8_t data_type;         // data type enum (i.e. SkyDataType)
    uint8_t data_type_count;   // data type count
} sky_entry_t;

// read and write in place in buffer
typedef struct sky_protocol_data_entry_ex {
    sky_entry_t * entry;       // entry without data
    uint8_t * data;            // array size = sizeof(data type) * count
} sky_entry_ext_t;

typedef struct sky_protocol_packet_payload {
    uint8_t sw_version;        // client sw version for request and server sw version for response
    uint8_t mac[6];            // client device MAC address
    uint8_t type;              // payload type
    uint8_t ipv6[16];          // client ip address: ipv4 is set at the first 4 bytes with
                               // the rest 12 bytes being set to zeros.
    uint8_t timestamp[8];      // timestamp in milliseconds
} sky_payload_t;

typedef struct sky_protocol_packet_payload_ex {
    sky_payload_t payload;     // payload without data entries
    sky_entry_ext_t data_entry;// data_entry is updated to iterate over an unbounded array of data entries in buffer
} sky_payload_ext_t;

typedef uint16_t sky_checksum;


/* response relay settings and tracking */
struct relay_t {
    struct sockaddr_in host;
    uint8_t valid;
// runtime data
//int fail_count; // count of fw failiures (increment on each failiure decrement failure count every second)
//uint64_t timestamp; // in ms, last successful send
};

/* stores keys in a binary tree */
struct aes_key_t {
    uint32_t userid;
    uint8_t aes_key[16]; // 128 bit aes key
    char keyid[128]; // api key
    struct relay_t relay; // relay responses
};

/* WARNING
 it is important to keep the order
 the larger size vars first in the structs
 because the compiler pads the struct to align
 to the largest size */

/* access point struct */
struct ap_t // 7
{
    uint8_t MAC[6];
    int8_t rssi;
};

// http://wiki.opencellid.org/wiki/API
struct gsm_t {
    uint32_t ci;
    uint32_t age;
    uint16_t mcc; // country
    uint16_t mnc;
    uint16_t lac;
    int8_t rssi; // -255 unkonwn - map it to - 128
};

struct cdma_t {
    uint32_t age;
    double lat;
    double lon;
    uint16_t sid;
    uint16_t nid;
    uint16_t bsid;
    int8_t rssi;
};

struct umts_t {
    uint32_t ci;
    uint32_t age;
    uint16_t mcc; // country
    uint16_t mnc;
    uint16_t lac;
    int8_t rssi;
};

struct lte_t {
    uint32_t age;
    uint32_t eucid;
    uint16_t mcc;
    uint16_t mnc;
    int8_t rssi;
};

struct gps_t // 38
{
    double lat;
    double lon;
    float alt; // altitude
    float hpe;
    uint32_t age; // last seen in ms
    float speed;
    uint8_t nsat;
    uint8_t fix;
};

struct ble_t {
    uint16_t major;
    uint16_t minor;
    uint8_t MAC[6];
    uint8_t uuid[16];
    int8_t rssi;
};

/* location result struct */
// define indicates struct size
// that could vary between 32 vs 64 bit systems
#define LOCATION_T_SIZE 20
struct location_t {
    double lat;
    double lon;
    float hpe;
};

/* extended location data */
struct location_ext_t {
    float distance_to_point;

    uint8_t ip_type; // DATA_TYPE_IPV4 or DATA_TYPE_IPV6
    uint8_t ip_addr[16]; // used for ipv4 (4 bytes) or ipv6 (16 bytes)

    uint8_t street_num_len;
    char *street_num;

    uint8_t address_len;
    char *address;

    uint8_t city_len;
    char *city;

    uint8_t state_len;
    char *state;

    uint8_t state_code_len;
    char *state_code;

    uint8_t metro1_len;
    char *metro1;

    uint8_t metro2_len;
    char *metro2;

    uint8_t postal_code_len;
    char *postal_code;

    uint8_t county_len;
    char *county;

    uint8_t country_len;
    char *country;

    uint8_t country_code_len;
    char *country_code;
};

struct location_req_t {

    /* user key */
    struct aes_key_t key;

    /* protocol version number */
    uint8_t protocol;

    /* client software version */
    uint8_t version;

    /* client device MAC identifier */
    uint8_t MAC[6];

    /* payload type */
    uint8_t payload_type;

    /* client IP address */
    uint8_t ip_addr[16];

    /* timestamp */
    uint8_t timestamp[6]; // in ms

    /* wifi access points */
    uint8_t ap_count;
    struct ap_t *aps;

    /* ble beacons */
    uint8_t ble_count;
    struct ble_t *bles;

    /* cell */
// cell count refers to one of the struct count below
    uint8_t cell_count;
    uint8_t cell_type; // SKY_DATA_TYPE

// TODO use a union for cell types
    struct gsm_t *gsm;
    struct cdma_t *cdma;
    struct lte_t *lte;
    struct umts_t *umts;

    /* gps */
    uint8_t gps_count;
    struct gps_t *gps;

    /* http server settings */
    char *http_url;
    char *http_uri;

    /* api server version number (string 2.34) */
    char *api_version;
};

struct location_resp_t {

    /* user key */
    struct aes_key_t key;

    /* protocol version number */
    uint8_t protocol;

    /* server software version */
    uint8_t version;

    /* client device MAC identifier */
    uint8_t MAC[6];

    /* payload type */
    uint8_t payload_type;

    /* timestamp */
    uint8_t timestamp[6]; // in ms

    /* location result */
    struct location_t location;

    /* ext location res, adress etc */
    struct location_ext_t location_ex;
};

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
