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
#include <stdbool.h>
#include "sky_crypt.h"
#include "sky_protocol.h"
#include "sky_util.h"

// Return the number to add to become a multiple of 16.
inline
uint8_t pad_16(uint32_t num) {
    uint8_t residual_16 = num & 0X0F;
    return (residual_16 == 0) ? 0 : (~residual_16 & 0X0F) + 1;
}

// Return data entry by parameter "sky_entry & entry".
inline
bool adjust_data_entry(const uint8_t * buff, uint32_t buff_len, uint32_t offset, sky_entry_ext_t * p_entry) {
    if (offset >= buff_len) {
        return false;
    }
    // The "entry" attributes point to buffer address;
    // so read and write "entry" means read and write in buffer in place.
    p_entry->entry = (sky_entry_t *)(buff + offset);
    p_entry->data = (uint8_t *)buff + offset + sizeof(sky_entry_t);
    return true;
}

// Return header by parameter "header & h".
inline
bool sky_get_header(const uint8_t * buff, uint32_t buff_len, uint8_t * p_header, uint32_t header_len) {
    if (buff_len < header_len) {
        perror("buffer too small");
        return false;
    }
    memcpy(p_header, buff, header_len);
    return true;
}

// Return payload content by parameter "sky_payload_ex & payload".
// Note: payload_ex.data_entry is a pointer referring to an address in buffer.
inline
bool sky_get_payload(const uint8_t * buff, uint32_t buff_len, uint8_t header_len,
        sky_payload_ext_t * p_payload_ex, uint16_t payload_len) {
    if (buff_len < header_len + payload_len) {
        perror("buffer too small");
        return false;
    }
    memcpy(&p_payload_ex->payload, buff + header_len, sizeof(sky_payload_t));
    // initialize payload_ex.data_entry
    adjust_data_entry(buff, buff_len, header_len + sizeof(sky_payload_t), &p_payload_ex->data_entry);
    return true;
}

// Verify checksum.
inline
bool sky_verify_checksum(const uint8_t * buff, uint32_t buff_len, uint8_t header_len, uint16_t payload_len) {
    if (buff_len < header_len + payload_len + sizeof(sky_checksum_t)) {
        perror("buffer too small");
        return false;
    }
    sky_checksum_t cs = *(sky_checksum_t *)(buff + header_len + payload_len); // little endianness
    if (cs == fletcher16(buff, header_len + payload_len))
        return 1;
    else {
        perror("invalid checksum");
        return true;
    }
}

// Set header in parameter "uint8_t * buff".
inline
bool sky_set_header(uint8_t * buff, uint32_t buff_len, const uint8_t * p_header, uint32_t header_len) {
    if (buff_len < header_len) {
        perror("buffer too small");
        return false;
    }
    memcpy(buff, p_header, header_len);
    return true;
}

// Set payload in parameter "uint8_t * buff".
// Only set the payload without data entries; the data entries needs to be filled in place in buffer
// by using "payload_ex.data_entry".
inline
bool sky_set_payload(uint8_t * buff, uint32_t buff_len, uint8_t header_len,
        sky_payload_ext_t * p_payload_ex, uint16_t payload_len) {
    if (buff_len < header_len + payload_len) {
        perror("buffer too small");
        return false;
    }
    memcpy(buff + header_len, &p_payload_ex->payload, sizeof(sky_payload_t));
    // initialize payload_ex.data_entry
    adjust_data_entry(buff, buff_len, header_len + sizeof(sky_payload_t), &p_payload_ex->data_entry);
    return true;
}

// Set checksum in parameter "uint8_t * buff".
inline
bool sky_set_checksum(uint8_t * buff, uint32_t buff_len, uint8_t header_len, uint16_t payload_len) {
    if (buff_len < header_len + payload_len + sizeof(sky_checksum_t)) {
        perror("buffer too small");
        return false;
    }
    sky_checksum_t cs = fletcher16(buff, header_len + payload_len);
    *(sky_checksum_t *)(buff + header_len + payload_len) = cs; // little endianness
    return true;
}

inline
uint8_t sky_get_ip_type(const struct location_rq_t * p_loc_rq) {
    uint8_t zero_12[12];
    memset(zero_12, 0, sizeof(zero_12));
    if (memcmp(p_loc_rq->ip_addr + 4, zero_12, sizeof(zero_12)) == 0)
        return DATA_TYPE_IPV4;
    else
        return DATA_TYPE_IPV6;
}

inline
uint8_t sky_get_ipaddr_len(const struct location_rq_t * p_loc_rq) {
    return (sky_get_ip_type(p_loc_rq) == DATA_TYPE_IPV4) ? 4 : 16;
}

// find aes key  based on userid in key root and set it
//int sky_set_key(void *key_root, struct location_head_t *head);
uint32_t sky_get_userid_from_rq_header(uint8_t *buff, uint32_t buff_len) {
    sky_rq_header_t header;
    memset(&header, 0, sizeof(header));
    if (sky_get_header(buff, buff_len, (uint8_t *)&header, sizeof(header))) {
        return header.user_id;
    }
    return 0;
}

// received by the server from the client
/* decode binary data from client, result is in the location_req_t struct */
/* binary encoded data in buff from client with data */
int32_t sky_decode_req_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_rq_t *creq) {

    memset(&creq->header, 0, sizeof(creq->header));
    if (!sky_get_header(buff, buff_len, (uint8_t *)&creq->header, sizeof(creq->header)))
        return -1;
    if (!sky_verify_checksum(buff, buff_len, (uint8_t)sizeof(creq->header), creq->header.payload_length))
        return -1;
    memset(&creq->payload_ext, 0, sizeof(creq->payload_ext));
    if (!sky_get_payload(buff, buff_len, sizeof(sky_rq_header_t), &creq->payload_ext, creq->header.payload_length))
        return -1;

    /* binary protocol description in sky_protocol.h */
    creq->key.userid = creq->header.user_id;

    if (creq->payload_ext.payload.type != LOCATION_RQ
            && creq->payload_ext.payload.type != LOCATION_RQ_ADDR) {
        fprintf(stderr, "Unknown payload type %d\n", creq->payload_ext.payload.type);
        return -1;
    }

    // read data entries from buffer
    sky_entry_ext_t * p_entry_ex = &creq->payload_ext.data_entry;
    uint32_t payload_offset = sizeof(sky_payload_t);
    while (payload_offset < creq->header.payload_length) {
        uint32_t sz = 0;
        switch (p_entry_ex->entry->data_type) {
        case DATA_TYPE_MAC:
            creq->ap_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(creq->MAC) * p_entry_ex->entry->data_type_count;
            memcpy(creq->MAC, p_entry_ex->data, sz);
            break;
        case DATA_TYPE_IPV4:
            creq->ap_count = p_entry_ex->entry->data_type_count;
            sz = IPV4_SIZE * p_entry_ex->entry->data_type_count;
            memset(creq->ip_addr, 0, sizeof(creq->ip_addr));
            memcpy(creq->ip_addr, p_entry_ex->data, sz);
            break;
        case DATA_TYPE_AP:
            creq->ap_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct ap_t) * p_entry_ex->entry->data_type_count;
            creq->aps = (struct ap_t *)p_entry_ex->data;
            break;
        case DATA_TYPE_BLE:
            creq->ble_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct ble_t) * p_entry_ex->entry->data_type_count;
            creq->bles = (struct ble_t *)p_entry_ex->data;
            break;
        case DATA_TYPE_GSM:
            creq->cell_count = p_entry_ex->entry->data_type_count;
            creq->cell_type = DATA_TYPE_GSM;
            sz = sizeof(struct gsm_t) * p_entry_ex->entry->data_type_count;
            creq->gsm = (struct gsm_t *)p_entry_ex->data;
            break;
        case DATA_TYPE_CDMA:
            creq->cell_count = p_entry_ex->entry->data_type_count;
            creq->cell_type = DATA_TYPE_CDMA;
            sz = sizeof(struct cdma_t) * p_entry_ex->entry->data_type_count;
            creq->cdma = (struct cdma_t *)p_entry_ex->data;
            break;
        case DATA_TYPE_UMTS:
            creq->cell_count = p_entry_ex->entry->data_type_count;
            creq->cell_type = DATA_TYPE_UMTS;
            sz = sizeof(struct umts_t) * p_entry_ex->entry->data_type_count;
            creq->umts = (struct umts_t *)p_entry_ex->data;
            break;
        case DATA_TYPE_LTE:
            creq->cell_count = p_entry_ex->entry->data_type_count;
            creq->cell_type = DATA_TYPE_LTE;
            sz = sizeof(struct lte_t) * p_entry_ex->entry->data_type_count;
            creq->lte = (struct lte_t *)p_entry_ex->data;
            break;
        case DATA_TYPE_GPS:
            creq->gps_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct gps_t) * p_entry_ex->entry->data_type_count;
            creq->gps = (struct gps_t *)p_entry_ex->data;
            break;
        case DATA_TYPE_PAD:
            return 0; // success
        default:
            perror("unknown data type");
            return -1;
        }
        payload_offset += sizeof(sky_entry_t) + sz;
        adjust_data_entry(buff, buff_len, sizeof(sky_rq_header_t) + payload_offset, p_entry_ex);
    }
    return 0;
}

// sent by the server to the client
/* encodes the loc struct into binary formatted packet sent to client */
// returns the packet len or -1 when fails
int32_t sky_encode_resp_bin(uint8_t *buff, uint32_t buff_len, struct location_rsp_t *cresp) {

    uint32_t payload_length = sizeof(sky_payload_t);

    // count bytes of data entries
    payload_length += sizeof(sky_entry_t) + sizeof(cresp->MAC)
            + sizeof(sky_entry_t) + IPV4_SIZE;
    payload_length += sizeof(sky_entry_t) + sizeof(struct location_t); // latitude and longitude
    if (cresp->payload_ext.payload.type == LOCATION_RQ_ADDR_SUCCESS) {
        if (cresp->location_ext.street_num_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.street_num_len;
        if (cresp->location_ext.address_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.address_len;
        if (cresp->location_ext.city_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.city_len;
        if (cresp->location_ext.state_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.state_len;
        if (cresp->location_ext.state_code_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.state_code_len;
        if (cresp->location_ext.metro1_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.metro1_len;
        if (cresp->location_ext.metro2_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.metro2_len;
        if (cresp->location_ext.postal_code_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.postal_code_len;
        if (cresp->location_ext.county_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.county_len;
        if (cresp->location_ext.country_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.country_len;
        if (cresp->location_ext.country_code_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.country_code_len;
    }

    // payload length must be a multiple of 16 bytes
    uint8_t pad_len = pad_16(payload_length);
    payload_length += pad_len;

    // Note that buffer contains the legacy date for location request,
    // so some fields (e.g. user id) are correct already.
    // update fields in buffer
    cresp->header.payload_length = payload_length;
    sky_gen_iv(cresp->header.iv); // 16 byte initialization vector
    if (!sky_set_header(buff, buff_len, (uint8_t *)&cresp->header, sizeof(cresp->header)))
        return -1;

    if (!sky_set_payload(buff, buff_len, sizeof(sky_rsp_header_t), &cresp->payload_ext, cresp->header.payload_length))
        return -1;

    // fill in data entries in place in buffer

    // MAC
    {
        sky_entry_ext_t * p_entry_ex = &cresp->payload_ext.data_entry;
        p_entry_ex->entry->data_type = DATA_TYPE_MAC;
        p_entry_ex->entry->data_type_count = sizeof(cresp->MAC);
        memcpy(p_entry_ex->data, cresp->MAC, p_entry_ex->entry->data_type_count);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
    }
    // IPV4
    {
        sky_entry_ext_t * p_entry_ex = &cresp->payload_ext.data_entry;
        p_entry_ex->entry->data_type = DATA_TYPE_IPV4;
        p_entry_ex->entry->data_type_count = IPV4_SIZE;
        memcpy(p_entry_ex->data, cresp->location_ext.ip_addr, p_entry_ex->entry->data_type_count);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
    }
    // latitude and longitude
    if (cresp->payload_ext.payload.type == LOCATION_RQ_SUCCESS) {
        sky_entry_ext_t * p_entry_ex = &cresp->payload_ext.data_entry;
        p_entry_ex->entry->data_type = DATA_TYPE_LAT_LON;
        p_entry_ex->entry->data_type_count = sizeof(cresp->location);
        memcpy(p_entry_ex->data, &cresp->location, sizeof(cresp->location));
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
    }
    // latitude, longitude, and full address, etc.
    if (cresp->payload_ext.payload.type == LOCATION_RQ_ADDR_SUCCESS) {
        sky_entry_ext_t * p_entry_ex = &cresp->payload_ext.data_entry;
        p_entry_ex->entry->data_type = DATA_TYPE_LAT_LON;
        p_entry_ex->entry->data_type_count = sizeof(cresp->location);
        memcpy(p_entry_ex->data, &cresp->location, sizeof(cresp->location));
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);

        if (cresp->location_ext.street_num_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_STREET_NUM;
            p_entry_ex->entry->data_type_count = cresp->location_ext.street_num_len;
            memcpy(p_entry_ex->data, cresp->location_ext.street_num, cresp->location_ext.street_num_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.address_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_ADDRESS;
            p_entry_ex->entry->data_type_count = cresp->location_ext.address_len;
            memcpy(p_entry_ex->data, cresp->location_ext.address, cresp->location_ext.address_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.city_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_CITY;
            p_entry_ex->entry->data_type_count = cresp->location_ext.city_len;
            memcpy(p_entry_ex->data, cresp->location_ext.city, cresp->location_ext.city_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.state_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_STATE;
            p_entry_ex->entry->data_type_count = cresp->location_ext.state_len;
            memcpy(p_entry_ex->data, cresp->location_ext.state, cresp->location_ext.state_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.state_code_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_STATE_CODE;
            p_entry_ex->entry->data_type_count = cresp->location_ext.state_code_len;
            memcpy(p_entry_ex->data, cresp->location_ext.state_code, cresp->location_ext.state_code_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.metro1_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_METRO1;
            p_entry_ex->entry->data_type_count = cresp->location_ext.metro1_len;
            memcpy(p_entry_ex->data, cresp->location_ext.metro1, cresp->location_ext.metro1_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.metro2_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_METRO2;
            p_entry_ex->entry->data_type_count = cresp->location_ext.metro2_len;
            memcpy(p_entry_ex->data, cresp->location_ext.metro2, cresp->location_ext.metro2_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.postal_code_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_POSTAL_CODE;
            p_entry_ex->entry->data_type_count = cresp->location_ext.postal_code_len;
            memcpy(p_entry_ex->data, cresp->location_ext.postal_code, cresp->location_ext.postal_code_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);;
        }

        if (cresp->location_ext.county_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_COUNTY;
            p_entry_ex->entry->data_type_count = cresp->location_ext.county_len;
            memcpy(p_entry_ex->data, cresp->location_ext.county, cresp->location_ext.county_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.country_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_COUNTRY;
            p_entry_ex->entry->data_type_count = cresp->location_ext.country_len;
            memcpy(p_entry_ex->data, cresp->location_ext.country, cresp->location_ext.country_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.country_code_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_COUNTRY_CODE;
            p_entry_ex->entry->data_type_count = cresp->location_ext.country_code_len;
            memcpy(p_entry_ex->data, cresp->location_ext.country_code, cresp->location_ext.country_code_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }
    }

    // fill in padding bytes
    if (pad_len > 0) {
        uint8_t * pad_bytes = buff + sizeof(sky_rsp_header_t) + cresp->header.payload_length - pad_len;
        memset(pad_bytes, DATA_TYPE_PAD, pad_len);
    }

    sky_set_checksum(buff, buff_len, (uint8_t)sizeof(cresp->header), cresp->header.payload_length);

    return sizeof(sky_rsp_header_t) + cresp->header.payload_length + sizeof(sky_checksum_t);
}

// sent by the client to the server
/* encodes the request struct into binary formatted packet sent to server */
// returns the packet len or -1 when fails
int32_t sky_encode_req_bin(uint8_t *buff, uint32_t buff_len, struct location_rq_t *creq) {

    if (creq->payload_ext.payload.type != LOCATION_RQ
            && creq->payload_ext.payload.type != LOCATION_RQ_ADDR) {
        fprintf(stderr, "sky_encode_req_bin: unknown payload type %d\n", creq->payload_ext.payload.type);
        return -1;
    }

    uint32_t payload_length = sizeof(sky_payload_t);
    payload_length += sizeof(sky_entry_t) + sizeof(creq->MAC)
            + sizeof(sky_entry_t) + sky_get_ipaddr_len(creq);

    uint8_t acnt = creq->ap_count;
    uint8_t bcnt = creq->ble_count;
    uint8_t ccnt = creq->cell_count;
    uint8_t gcnt = creq->gps_count;
    if (acnt > 0)
        payload_length += sizeof(sky_entry_t) + acnt * sizeof(struct ap_t);
    if (bcnt > 0)
        payload_length += sizeof(sky_entry_t) + bcnt * sizeof(struct ble_t);
    if (gcnt > 0)
        payload_length += sizeof(sky_entry_t) + gcnt * sizeof(struct gps_t);
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
        payload_length += ccnt * sz + sizeof(sky_entry_t);
    }

    // payload length must be a multiple of 16 bytes
    uint8_t pad_len = pad_16(payload_length);
    payload_length += pad_len;

    creq->header.payload_length = payload_length;
    creq->header.user_id = creq->key.userid;
    // 16 byte initialization vector
    sky_gen_iv(creq->header.iv);
    if (!sky_set_header(buff, buff_len, (uint8_t *)&creq->header, sizeof(creq->header)))
        return -1;

    if (!sky_set_payload(buff, buff_len, sizeof(sky_rq_header_t), &creq->payload_ext, creq->header.payload_length))
        return -1;

    // fill in data entries in buffer
    sky_entry_ext_t * p_entry_ex = &creq->payload_ext.data_entry;
    uint32_t sz = 0;
    // MAC
    {
        p_entry_ex->entry->data_type = DATA_TYPE_MAC;
        p_entry_ex->entry->data_type_count = 1;
        sz = sizeof(creq->MAC) * p_entry_ex->entry->data_type_count;
        memcpy(p_entry_ex->data, creq->MAC, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // IPv4
    {
        p_entry_ex->entry->data_type = DATA_TYPE_IPV4;
        p_entry_ex->entry->data_type_count = 1;
        sz = IPV4_SIZE * p_entry_ex->entry->data_type_count;
        memcpy(p_entry_ex->data, creq->ip_addr, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // Access Point
    if (creq->ap_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_AP;
        p_entry_ex->entry->data_type_count = acnt;
        sz = sizeof(struct ap_t) * acnt;
        memcpy(p_entry_ex->data, creq->aps, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // Blue Tooth
    if (creq->ble_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_BLE;
        p_entry_ex->entry->data_type_count = bcnt;
        sz = sizeof(struct ble_t) * bcnt;
        memcpy(p_entry_ex->data, creq->bles, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // Cell
    if (creq->cell_count > 0) {
        p_entry_ex->entry->data_type = creq->cell_type;
        p_entry_ex->entry->data_type_count = ccnt;
        switch (creq->cell_type) {
        case DATA_TYPE_GSM:
            sz = sizeof(struct gsm_t) * ccnt;
            memcpy(p_entry_ex->data, &creq->cell->gsm, sz);
            break;
        case DATA_TYPE_LTE:
            sz = sizeof(struct lte_t) * ccnt;
            memcpy(p_entry_ex->data, &creq->cell->lte, sz);
            break;
        case DATA_TYPE_CDMA:
            sz = sizeof(struct cdma_t) * ccnt;
            memcpy(p_entry_ex->data, &creq->cell->cdma, sz);
            break;
        case DATA_TYPE_UMTS:
            sz = sizeof(struct umts_t) * ccnt;
            memcpy(p_entry_ex->data, &creq->cell->umts, sz);
            break;
        default:
            perror("unknown data type");
            return -1;
        }
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // GPS
    if (creq->gps_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_GPS;
        p_entry_ex->entry->data_type_count = gcnt;
        sz = sizeof(struct gps_t) * gcnt;
        memcpy(p_entry_ex->data, creq->gps, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }

    // fill in padding bytes
    if (pad_len > 0) {
        uint8_t * pad_bytes = p_entry_ex->data - sizeof(sky_entry_t);
        memset(pad_bytes, DATA_TYPE_PAD, pad_len);
    }

    if (!sky_set_checksum(buff, buff_len, (uint8_t)sizeof(creq->header), creq->header.payload_length))
        return -1;

    return sizeof(sky_rq_header_t) + creq->header.payload_length + sizeof(sky_checksum_t);
}

// received by the client from the server
/* decodes the binary data and the result is in the location_resp_t struct */
int32_t sky_decode_resp_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_rsp_t *cresp) {

    memset(&cresp->header, 0, sizeof(cresp->header));
    if (!sky_get_header(buff, buff_len, (uint8_t *)&cresp->header, sizeof(cresp->header)))
        return -1;
    if (!sky_verify_checksum(buff, buff_len, (uint8_t)sizeof(cresp->header), cresp->header.payload_length))
        return -1;
    if (!sky_get_payload(buff, buff_len, sizeof(sky_rsp_header_t), &cresp->payload_ext, cresp->header.payload_length))
        return -1;

    if (cresp->payload_ext.payload.type != LOCATION_RQ_SUCCESS
            && cresp->payload_ext.payload.type != LOCATION_RQ_ADDR_SUCCESS) {
        fprintf(stderr, "Unknown payload type %d\n", cresp->payload_ext.payload.type);
        return -1;
    }

    // read data entries from buffer
    // latitude, longitude and full address, etc.
    sky_entry_ext_t * p_entry_ex = &cresp->payload_ext.data_entry;
    uint32_t payload_offset = sizeof(sky_payload_t);
    while (payload_offset < cresp->header.payload_length) {
        switch (p_entry_ex->entry->data_type) {
        case DATA_TYPE_MAC:
            memcpy(cresp->MAC, p_entry_ex->data, p_entry_ex->entry->data_type_count);
            break;
        case DATA_TYPE_IPV4:
            cresp->location_ext.ip_type = DATA_TYPE_IPV4;
            memcpy(cresp->location_ext.ip_addr, p_entry_ex->data, p_entry_ex->entry->data_type_count);
            break;
        case DATA_TYPE_IPV6:
            cresp->location_ext.ip_type = DATA_TYPE_IPV6;
            memcpy(cresp->location_ext.ip_addr, p_entry_ex->data, p_entry_ex->entry->data_type_count);
            break;
        case DATA_TYPE_LAT_LON:
            memcpy(&cresp->location, p_entry_ex->data, p_entry_ex->entry->data_type_count);
            break;
        case DATA_TYPE_STREET_NUM:
            cresp->location_ext.street_num_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.street_num = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_ADDRESS:
            cresp->location_ext.address_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.address = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_CITY:
            cresp->location_ext.city_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.city = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_STATE:
            cresp->location_ext.state_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.state = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_STATE_CODE:
            cresp->location_ext.state_code_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.state_code = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_METRO1:
            cresp->location_ext.metro1_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.metro1 = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_METRO2:
            cresp->location_ext.metro2_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.metro2 = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_POSTAL_CODE:
            cresp->location_ext.postal_code_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.postal_code = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_COUNTY:
            cresp->location_ext.county_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.county = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_COUNTRY:
            cresp->location_ext.country_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.country = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_COUNTRY_CODE:
            cresp->location_ext.country_code_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.country_code = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_PAD:
            return 0; // success
        default:
            perror("unknown data type");
            return -1;
        }
        payload_offset += sizeof(sky_entry_t) + p_entry_ex->entry->data_type_count;
        adjust_data_entry(buff, buff_len, sizeof(sky_rsp_header_t) + payload_offset, p_entry_ex);
    }
    return 0; // success
}
