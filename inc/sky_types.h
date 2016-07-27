/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_TYPES_H
#define SKY_TYPES_H

#include <inttypes.h>
#include <netinet/in.h>

// server error
#define SERVER_ERR 0xFF

// server cannot handle more than preset process limit using http error code numbers for simplicity
#define SERVICE_UNAVAILABLE_503 {SERVER_ERR, 0xF7, 0x01}
#define PROTOCOL_NOT_ACCEPTABLE_406 {SERVER_ERR, 0x96, 0x01}

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

// stored in one byte
enum SKY_PAYLOAD_TYPE {

    /* request payload types */
    LOCATION_RQ = 0,        // location request
    LOCATION_RQ_ADDR,       // location request full
    PROBE_REQUEST,

    /* response payload types */
    LOCATION_RQ_SUCCESS = 100,
    LOCATION_RQ_ERROR,
    LOCATION_GATEWAY_ERROR,
    LOCATION_API_ERROR,
};

// error codes
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
    DECRYPT_BIN_FAILED = 211,
    ENCODE_XML_FAILED,
    DECODE_BIN_FAILED,
    ENCODE_BIN_FAILED,
    ENCRYPT_BIN_FAILED,
    DECODE_XML_FAILED,
    CREATE_META_FAILED,

    /* HTTP response codes */
    /*http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html */
};

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
    uint64_t timestamp; // in ms

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
    uint64_t timestamp; // in ms

    /* location result */
    struct location_t location;

    /* ext location res, adress etc */
    struct location_ext_t location_ex;
};

#endif

#ifdef __cplusplus
}
#endif
