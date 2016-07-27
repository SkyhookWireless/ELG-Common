/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sky_crypt.h>
#include <sky_protocol.h>
#include <sky_types.h>
#include <sky_util.h>
#include <stdbool.h>
#include "sky_keys.hpp"

// Return the number to add to become a multiple of 16.
inline
uint8_t pad_16(uint32_t num) {
    uint8_t residual_16 = num & 0X0F;
    return (residual_16 == 0) ? 0 : (~residual_16 & 0X0F) + 1;
}

// Return data entry by parameter "sky_entry & entry".
inline
bool adjust_data_entry(const uint8_t * buff, uint32_t buff_len, uint32_t offset, sky_entry_ex * p_entry) {
    if (offset >= buff_len) {
        return false;
    }
    // The "entry" attributes point to buffer address;
    // so read and write "entry" means read and write in buffer in place.
    p_entry->entry = (sky_entry *)(buff + offset);
    p_entry->data = (uint8_t *)buff + offset + sizeof(sky_entry);
    return true;
}

// Return header by parameter "header & h".
inline
bool sky_get_header(const uint8_t * buff, uint32_t buff_len, sky_header * p_header) {
    if (buff_len < sizeof(sky_header)) {
        perror("buffer too small");
        return false;
    }
    memcpy(p_header, buff, sizeof(sky_header));
    return true;
}

// Return payload content by parameter "sky_payload_ex & payload".
// Note: payload_ex.data_entry is a pointer referring to an address in buffer.
inline
bool sky_get_payload(const uint8_t * buff, uint32_t buff_len, sky_payload_ex * p_payload_ex, uint16_t payload_length) {
    if (buff_len < sizeof(sky_header) + payload_length) {
        perror("buffer too small");
        return false;
    }
    memcpy(&p_payload_ex->payload, buff + sizeof(sky_header), sizeof(sky_payload));
    // initialize payload_ex.data_entry
    adjust_data_entry(buff, buff_len, sizeof(sky_header) + sizeof(sky_payload), &p_payload_ex->data_entry);
    return true;
}

// Verify checksum.
inline
bool sky_verify_checksum(const uint8_t * buff, uint32_t buff_len, uint16_t payload_length) {
    if (buff_len < sizeof(sky_header) + payload_length + sizeof(sky_checksum)) {
        perror("buffer too small");
        return false;
    }
    sky_checksum cs = *(sky_checksum *)(buff + sizeof(sky_header) + payload_length); // little endianness
    if (cs == fletcher16(buff, sizeof(sky_header) + payload_length))
        return 1;
    else {
        perror("invalid checksum");
        return true;
    }
}

// Set header in parameter "uint8_t * buff".
inline
bool sky_set_header(uint8_t * buff, uint32_t buff_len, const sky_header * p_header) {
    if (buff_len < sizeof(sky_header)) {
        perror("buffer too small");
        return false;
    }
    memcpy(buff, p_header, sizeof(sky_header));
    return true;
}

// Set payload in parameter "uint8_t * buff".
// Only set the payload without data entries; the data entries needs to be filled in place in buffer
// by using "payload_ex.data_entry".
inline
bool sky_set_payload(uint8_t * buff, uint32_t buff_len, sky_payload_ex * p_payload_ex, uint16_t payload_length) {
    if (buff_len < sizeof(sky_header) + payload_length) {
        perror("buffer too small");
        return false;
    }
    memcpy(buff + sizeof(sky_header), &p_payload_ex->payload, sizeof(sky_payload));
    // initialize payload_ex.data_entry
    adjust_data_entry(buff, buff_len, sizeof(sky_header) + sizeof(sky_payload), &p_payload_ex->data_entry);
    return true;
}

// Set checksum in parameter "uint8_t * buff".
inline
bool sky_set_checksum(uint8_t * buff, uint32_t buff_len, uint16_t payload_length) {
    if (buff_len < sizeof(sky_header) + payload_length + sizeof(sky_checksum)) {
        perror("buffer too small");
        return false;
    }
    sky_checksum cs = fletcher16(buff, sizeof(sky_header) + payload_length);
    *(sky_checksum *)(buff + sizeof(sky_header) + payload_length) = cs; // little endianness
    return true;
}

// find aes key  based on userid in key root and set it
//int sky_set_key(void *key_root, struct location_head_t *head);
uint32_t sky_get_userid(uint8_t *buff, int32_t buff_len) {
    sky_header header;
    memset(&header, 0, sizeof(header));
    if (sky_get_header(buff, buff_len, &header)) {
        return header.user_id;
    }
    return 0;
}

// received by the server from the client
/* decode binary data from client, result is in the location_req_t struct */
/* binary encoded data in buff from client with data */
int32_t sky_decode_req_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_req_t *creq) {

    sky_header header;
    memset(&header, 0, sizeof(header));
    if (!sky_get_header(buff, buff_len, &header))
        return -1;
    if (!sky_verify_checksum(buff, buff_len, header.payload_length))
        return -1;
    sky_payload_ex payload_ex;
    memset(&payload_ex, 0, sizeof(payload_ex));
    if (!sky_get_payload(buff, buff_len, &payload_ex, header.payload_length))
        return -1;

    /* binary protocol description in sky_protocol.h */
    creq->protocol = header.version; // protocol version
    creq->key.userid = header.user_id;
    creq->version = payload_ex.payload.sw_version; // client software version
    memcpy(creq->MAC, payload_ex.payload.mac, sizeof(creq->MAC)); // device mac address
    memcpy(creq->ip_addr, payload_ex.payload.ipv6, sizeof(creq->ip_addr));
    creq->payload_type = payload_ex.payload.type;
    memcpy(&creq->timestamp, payload_ex.payload.timestamp, sizeof(payload_ex.payload.timestamp));

    if (creq->payload_type != LOCATION_RQ && creq->payload_type != LOCATION_RQ_ADDR) {
        fprintf(stderr, "Unknown payload type %d\n", creq->payload_type);
        return -1;
    }

    // read data entries from buffer
    sky_entry_ex * p_entry_ex = &payload_ex.data_entry;
    uint32_t payload_offset = sizeof(sky_payload);
    while (payload_offset < header.payload_length) {
        uint32_t sz = 0;
        switch (p_entry_ex->entry->data_type) {
        case DATA_TYPE_AP:
            creq->ap_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct ap_t) * p_entry_ex->entry->data_type_count;
            creq->aps = (struct ap_t *)malloc(sz);
            memcpy(creq->aps, p_entry_ex->data, sz);
            break;
        case DATA_TYPE_BLE:
            creq->ble_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct ble_t) * p_entry_ex->entry->data_type_count;
            creq->bles = (struct ble_t *)malloc(sz);
            memcpy(creq->bles, p_entry_ex->data, sz);
            break;
        case DATA_TYPE_GSM:
            creq->cell_count = p_entry_ex->entry->data_type_count;
            creq->cell_type = DATA_TYPE_GSM;
            sz = sizeof(struct gsm_t) * p_entry_ex->entry->data_type_count;
            creq->gsm = (struct gsm_t *)malloc(sz);
            memcpy(creq->gsm, p_entry_ex->data, sz);
            break;
        case DATA_TYPE_CDMA:
            creq->cell_count = p_entry_ex->entry->data_type_count;
            creq->cell_type = DATA_TYPE_CDMA;
            sz = sizeof(struct cdma_t) * p_entry_ex->entry->data_type_count;
            creq->cdma = (struct cdma_t *)malloc(sz);
            memcpy(creq->cdma, p_entry_ex->data, sz);
            break;
        case DATA_TYPE_UMTS:
            creq->cell_count = p_entry_ex->entry->data_type_count;
            creq->cell_type = DATA_TYPE_UMTS;
            sz = sizeof(struct umts_t) * p_entry_ex->entry->data_type_count;
            creq->umts = (struct umts_t *)malloc(sz);
            memcpy(creq->umts, p_entry_ex->data, sz);
            break;
        case DATA_TYPE_LTE:
            creq->cell_count = p_entry_ex->entry->data_type_count;
            creq->cell_type = DATA_TYPE_LTE;
            sz = sizeof(struct lte_t) * p_entry_ex->entry->data_type_count;
            creq->lte = (struct lte_t *)malloc(sz);
            memcpy(creq->lte, p_entry_ex->data, sz);
            break;
        case DATA_TYPE_GPS:
            creq->gps_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct gps_t) * p_entry_ex->entry->data_type_count;
            creq->gps = (struct gps_t *)malloc(sz);
            memcpy(creq->gps, p_entry_ex->data, sz);
            break;
        case DATA_TYPE_PAD:
            return 0; // success
        default:
            perror("unknown data type");
            return -1;
        }
        payload_offset += sizeof(sky_entry) + sz;
        adjust_data_entry(buff, buff_len, sizeof(sky_header) + payload_offset, p_entry_ex);
    }
    return 0;
}

// sent by the server to the client
/* encodes the loc struct into binary formatted packet sent to client */
// returns the packet len or -1 when fails
int32_t sky_encode_resp_bin(uint8_t *buff, uint32_t buff_len, struct location_resp_t *cresp) {

    uint32_t payload_length = sizeof(sky_payload);

    // count bytes of data entries
    payload_length += sizeof(sky_entry) + sizeof(struct location_t); // latitude and longitude
    payload_length += sizeof(sky_entry) + sizeof(float); // distance to point
    if (cresp->payload_type == LOCATION_RQ_ADDR) {
        if (cresp->location_ex.street_num_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.street_num_len;
        if (cresp->location_ex.address_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.address_len;
        if (cresp->location_ex.city_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.city_len;
        if (cresp->location_ex.state_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.state_len;
        if (cresp->location_ex.state_code_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.state_code_len;
        if (cresp->location_ex.metro1_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.metro1_len;
        if (cresp->location_ex.metro2_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.metro2_len;
        if (cresp->location_ex.postal_code_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.postal_code_len;
        if (cresp->location_ex.county_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.county_len;
        if (cresp->location_ex.country_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.country_len;
        if (cresp->location_ex.country_code_len > 0)
            payload_length += sizeof(sky_entry) + cresp->location_ex.country_code_len;
    }

    // payload length must be a multiple of 16 bytes
    uint8_t pad_len = pad_16(payload_length);
    payload_length += pad_len;

    // Note that buffer contains the legacy date for location request,
    // so some fields (e.g. user id) are correct already.
    // update fields in buffer
    sky_header header;
    header.version = cresp->protocol;
    header.payload_length = payload_length;
    header.user_id = cresp->key.userid;
    sky_gen_iv(header.iv); // 16 byte initialization vector
    if (!sky_set_header(buff, buff_len, &header))
        return -1;

    sky_payload_ex payload_ex;
    payload_ex.payload.sw_version = cresp->version;
    memcpy(payload_ex.payload.mac, cresp->MAC, sizeof(payload_ex.payload.mac));
    memcpy(payload_ex.payload.ipv6, cresp->location_ex.ip_addr, sizeof(payload_ex.payload.ipv6));
    payload_ex.payload.type = cresp->payload_type;
    memcpy(payload_ex.payload.timestamp, &cresp->timestamp, sizeof(payload_ex.payload.timestamp));
    if (!sky_set_payload(buff, buff_len, &payload_ex, header.payload_length))
        return -1;

    // fill in data entries in place in buffer
    if (cresp->payload_type == LOCATION_RQ) {
        // add basic location: latitude and longitude
        sky_entry_ex * p_entry_ex = &payload_ex.data_entry;
        p_entry_ex->entry->data_type = DATA_TYPE_BASIC;
        p_entry_ex->entry->data_type_count = sizeof(cresp->location);
        memcpy(p_entry_ex->data, &cresp->location, sizeof(cresp->location));
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
    }
    if (cresp->payload_type == LOCATION_RQ_ADDR) {

        // add basic location: latitude and longitude
        sky_entry_ex * p_entry_ex = &payload_ex.data_entry;
        p_entry_ex->entry->data_type = DATA_TYPE_BASIC;
        p_entry_ex->entry->data_type_count = sizeof(cresp->location);
        memcpy(p_entry_ex->data, &cresp->location, sizeof(cresp->location));
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);

        p_entry_ex->entry->data_type = DATA_TYPE_DIST_POINT;
        p_entry_ex->entry->data_type_count = sizeof(float);
        memcpy(p_entry_ex->data, &cresp->location_ex.distance_to_point, sizeof(float));
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);

        if (cresp->location_ex.street_num_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_STREET_NUM;
            p_entry_ex->entry->data_type_count = cresp->location_ex.street_num_len;
            memcpy(p_entry_ex->data, cresp->location_ex.street_num, cresp->location_ex.street_num_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ex.address_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_ADDRESS;
            p_entry_ex->entry->data_type_count = cresp->location_ex.address_len;
            memcpy(p_entry_ex->data, cresp->location_ex.address, cresp->location_ex.address_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ex.city_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_CITY;
            p_entry_ex->entry->data_type_count = cresp->location_ex.city_len;
            memcpy(p_entry_ex->data, cresp->location_ex.city, cresp->location_ex.city_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ex.state_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_STATE;
            p_entry_ex->entry->data_type_count = cresp->location_ex.state_len;
            memcpy(p_entry_ex->data, cresp->location_ex.state, cresp->location_ex.state_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ex.state_code_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_STATE_CODE;
            p_entry_ex->entry->data_type_count = cresp->location_ex.state_code_len;
            memcpy(p_entry_ex->data, cresp->location_ex.state_code, cresp->location_ex.state_code_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ex.metro1_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_METRO1;
            p_entry_ex->entry->data_type_count = cresp->location_ex.metro1_len;
            memcpy(p_entry_ex->data, cresp->location_ex.metro1, cresp->location_ex.metro1_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ex.metro2_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_METRO2;
            p_entry_ex->entry->data_type_count = cresp->location_ex.metro2_len;
            memcpy(p_entry_ex->data, cresp->location_ex.metro2, cresp->location_ex.metro2_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ex.postal_code_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_POSTAL_CODE;
            p_entry_ex->entry->data_type_count = cresp->location_ex.postal_code_len;
            memcpy(p_entry_ex->data, cresp->location_ex.postal_code, cresp->location_ex.postal_code_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);;
        }

        if (cresp->location_ex.county_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_COUNTY;
            p_entry_ex->entry->data_type_count = cresp->location_ex.county_len;
            memcpy(p_entry_ex->data, cresp->location_ex.county, cresp->location_ex.county_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ex.country_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_COUNTRY;
            p_entry_ex->entry->data_type_count = cresp->location_ex.country_len;
            memcpy(p_entry_ex->data, cresp->location_ex.country, cresp->location_ex.country_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ex.country_code_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_COUNTRY_CODE;
            p_entry_ex->entry->data_type_count = cresp->location_ex.country_code_len;
            memcpy(p_entry_ex->data, cresp->location_ex.country_code, cresp->location_ex.country_code_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }
    }

    // fill in padding bytes
    if (pad_len > 0) {
        uint8_t * pad_bytes = buff + sizeof(sky_header) + header.payload_length - pad_len;
        memset(pad_bytes, DATA_TYPE_PAD, pad_len);
    }

    sky_set_checksum(buff, buff_len, header.payload_length);

    return sizeof(sky_header) + header.payload_length + sizeof(sky_checksum);
}

// sent by the client to the server
/* encodes the request struct into binary formatted packet sent to server */
// returns the packet len or -1 when fails
int32_t sky_encode_req_bin(uint8_t *buff, uint32_t buff_len, struct location_req_t *creq) {

    if (creq->payload_type != LOCATION_RQ
            && creq->payload_type != LOCATION_RQ_ADDR) {
        fprintf(stderr, "sky_encode_req_bin: unknown payload type %d\n", creq->payload_type);
        return -1;
    }

    uint8_t acnt = creq->ap_count;
    uint8_t bcnt = creq->ble_count;
    uint8_t ccnt = creq->cell_count;
    uint8_t gcnt = creq->gps_count;
    uint32_t payload_length = sizeof(sky_payload);
    if (acnt > 0)
        payload_length += sizeof(sky_entry) + acnt * sizeof(struct ap_t);
    if (bcnt > 0)
        payload_length += sizeof(sky_entry) + bcnt * sizeof(struct ble_t);
    if (gcnt > 0)
        payload_length += sizeof(sky_entry) + gcnt * sizeof(struct gps_t);
    if (ccnt > 0) {
        uint32_t sz;
        switch (creq->cell_type) {
        case DATA_TYPE_GSM:
            sz = sizeof(struct gsm_t);
            break;
        case DATA_TYPE_CDMA:
            sz = sizeof(struct cdma_t);
            break;
        case DATA_TYPE_UMTS:
            sz = sizeof(struct umts_t);
            break;
        case DATA_TYPE_LTE:
            sz = sizeof(struct lte_t);
            break;
        default:
            perror("unknown data type");
            return -1;
        }
        payload_length += ccnt * sz + sizeof(sky_entry);
    }

    // payload length must be a multiple of 16 bytes
    uint8_t pad_len = pad_16(payload_length);
    payload_length += pad_len;

    sky_header header;
    header.version = creq->protocol;
    header.payload_length = payload_length;
    header.user_id = creq->key.userid;
    // 16 byte initialization vector
    sky_gen_iv(header.iv);
    if (!sky_set_header(buff, buff_len, &header))
        return -1;

    sky_payload_ex payload_ex;
    payload_ex.payload.sw_version = creq->version; // client firmware version
    memcpy(payload_ex.payload.mac, creq->MAC, sizeof(payload_ex.payload.mac));
    memcpy(payload_ex.payload.ipv6, creq->ip_addr, sizeof(payload_ex.payload.ipv6));
    payload_ex.payload.type = creq->payload_type;
    memcpy(payload_ex.payload.timestamp, &creq->timestamp, sizeof(payload_ex.payload.timestamp));
    if (!sky_set_payload(buff, buff_len, &payload_ex, header.payload_length))
        return -1;

    // fill in data entries in buffer
    sky_entry_ex * p_entry_ex = &payload_ex.data_entry;
    uint32_t sz = 0;
    if (creq->ap_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_AP;
        p_entry_ex->entry->data_type_count = acnt;
        sz = (int32_t) sizeof(struct ap_t) * acnt;
        memcpy(p_entry_ex->data, creq->aps, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    if (creq->ble_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_BLE;
        p_entry_ex->entry->data_type_count = bcnt;
        sz = (int32_t) sizeof(struct ble_t) * bcnt;
        memcpy(p_entry_ex->data, creq->bles, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    if (creq->cell_count > 0) {
        p_entry_ex->entry->data_type = creq->cell_type;
        p_entry_ex->entry->data_type_count = ccnt;
        switch (creq->cell_type) {
        case DATA_TYPE_GSM:
            sz = sizeof(struct gsm_t) * ccnt;
            memcpy(p_entry_ex->data, creq->gsm, sz);
            break;
        case DATA_TYPE_LTE:
            sz = sizeof(struct lte_t) * ccnt;
            memcpy(p_entry_ex->data, creq->lte, sz);
            break;
        case DATA_TYPE_CDMA:
            sz = sizeof(struct cdma_t) * ccnt;
            memcpy(p_entry_ex->data, creq->cdma, sz);
            break;
        case DATA_TYPE_UMTS:
            sz = sizeof(struct umts_t) * ccnt;
            memcpy(p_entry_ex->data, creq->umts, sz);
            break;
        default:
            perror("unknown data type");
            return -1;
        }
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }

    if (creq->gps_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_GPS;
        p_entry_ex->entry->data_type_count = gcnt;
        sz = (int32_t) sizeof(struct gps_t) * gcnt;
        memcpy(p_entry_ex->data, creq->gps, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }

    // fill in padding bytes
    if (pad_len > 0) {
        uint8_t * pad_bytes = p_entry_ex->data - sizeof(sky_entry);
        memset(pad_bytes, DATA_TYPE_PAD, pad_len);
    }

    if (!sky_set_checksum(buff, buff_len, header.payload_length))
        return -1;

    return sizeof(sky_header) + header.payload_length + sizeof(sky_checksum);
}

// received by the client from the server
/* decodes the binary data and the result is in the location_resp_t struct */
int32_t sky_decode_resp_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_resp_t *cresp) {

    sky_header header;
    memset(&header, 0, sizeof(header));
    if (!sky_get_header(buff, buff_len, &header))
        return -1;
    if (!sky_verify_checksum(buff, buff_len, header.payload_length))
        return -1;
    sky_payload_ex payload_ex;
    if (!sky_get_payload(buff, buff_len, &payload_ex, header.payload_length))
        return -1;

    cresp->protocol = header.version; // protocol version
    cresp->version = payload_ex.payload.sw_version;
    memcpy(cresp->MAC, payload_ex.payload.mac, sizeof(cresp->MAC));
    memcpy(cresp->location_ex.ip_addr, payload_ex.payload.ipv6, sizeof(cresp->location_ex.ip_addr));
    cresp->payload_type = payload_ex.payload.type;
    memcpy(&cresp->timestamp, payload_ex.payload.timestamp, sizeof(payload_ex.payload.timestamp));

    // read data entries from buffer
    if (cresp->payload_type == LOCATION_RQ) {
        // get basic location (i.e. latitude and longitude) from buffer
        sky_entry_ex * p_entry_ex = &payload_ex.data_entry;
        if (p_entry_ex->entry->data_type == DATA_TYPE_BASIC) {
            memcpy(&cresp->location, p_entry_ex->data, p_entry_ex->entry->data_type_count);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }
        return 0; // success
    }

    if (cresp->payload_type == LOCATION_RQ_ADDR) {
        sky_entry_ex * p_entry_ex = &payload_ex.data_entry;
        uint32_t payload_offset = sizeof(sky_payload);
        while (payload_offset < header.payload_length) {
            switch (p_entry_ex->entry->data_type) {
            case DATA_TYPE_BASIC:
                memcpy(&cresp->location, p_entry_ex->data, p_entry_ex->entry->data_type_count);
                break;
            case DATA_TYPE_STREET_NUM:
                cresp->location_ex.street_num_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.street_num = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_ADDRESS:
                cresp->location_ex.address_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.address = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_CITY:
                cresp->location_ex.city_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.city = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_STATE:
                cresp->location_ex.state_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.state = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_STATE_CODE:
                cresp->location_ex.state_code_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.state_code = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_METRO1:
                cresp->location_ex.metro1_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.metro1 = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_METRO2:
                cresp->location_ex.metro2_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.metro2 = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_POSTAL_CODE:
                cresp->location_ex.postal_code_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.postal_code = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_COUNTY:
                cresp->location_ex.county_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.county = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_COUNTRY:
                cresp->location_ex.country_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.country = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_COUNTRY_CODE:
                cresp->location_ex.country_code_len = p_entry_ex->entry->data_type_count;
                cresp->location_ex.country_code = (char *)p_entry_ex->data;
                break;
            case DATA_TYPE_IPV4:
                cresp->location_ex.ip_type = DATA_TYPE_IPV4;
                memcpy(cresp->location_ex.ip_addr, p_entry_ex->data, p_entry_ex->entry->data_type_count);
                break;
            case DATA_TYPE_IPV6:
                cresp->location_ex.ip_type = DATA_TYPE_IPV6;
                memcpy(cresp->location_ex.ip_addr, p_entry_ex->data, p_entry_ex->entry->data_type_count);
                break;
            case DATA_TYPE_DIST_POINT:
                memcpy(&cresp->location_ex.distance_to_point, p_entry_ex->data, p_entry_ex->entry->data_type_count);
                break;
            case DATA_TYPE_PAD:
                return 0; // success
            default:
                perror("unknown data type");
                return -1;
            }
            payload_offset += sizeof(sky_entry) + p_entry_ex->entry->data_type_count;
            adjust_data_entry(buff, buff_len, sizeof(sky_header) + payload_offset, p_entry_ex);
        }
    }
    return 0;
}
