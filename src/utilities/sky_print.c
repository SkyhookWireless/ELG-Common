/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "sky_types.h"
#include "sky_util.h"
#include "sky_print.h"

void print_location_rq(struct location_resp_t* cr) {
    puts("LOCATION_RQ");
    printf("latitude: %f\n", cr->location.lat);
    printf("longitude: %f\n", cr->location.lon);
    printf("hpe: %f\n", cr->location.hpe);
}

void print_location_rq_addr(struct location_resp_t* cr) {
    puts("LOCATION_RQ_ADDR");
    printf("distance_to_point: %f\n", cr->location_ex.distance_to_point);
    printf("street num: ");
    print_s(cr->location_ex.street_num, cr->location_ex.street_num_len);
    printf("address: ");
    print_s(cr->location_ex.address, cr->location_ex.address_len);
    printf("city: ");
    print_s(cr->location_ex.city, cr->location_ex.city_len);
    printf("state: ");
    print_s(cr->location_ex.state, cr->location_ex.state_len);
    printf("state code: ");
    print_s(cr->location_ex.state_code, cr->location_ex.state_code_len);
    printf("postal code: ");
    print_s(cr->location_ex.postal_code, cr->location_ex.postal_code_len);
    printf("county: ");
    print_s(cr->location_ex.county, cr->location_ex.county_len);
    printf("country: ");
    print_s(cr->location_ex.country, cr->location_ex.country_len);
    printf("country code: ");
    print_s(cr->location_ex.country_code, cr->location_ex.country_code_len);
    printf("metro1: ");
    print_s(cr->location_ex.metro1, cr->location_ex.metro1_len);
    printf("metro2: ");
    print_s(cr->location_ex.metro2, cr->location_ex.metro2_len);
    printf("ip: ");
    {
        uint8_t zero_12[12];
        memset(zero_12, 0, sizeof(zero_12));
        if (memcmp(cr->location_ex.ip_addr + 4, zero_12, sizeof(zero_12)) == 0)
            cr->location_ex.ip_type = DATA_TYPE_IPV4;
        else
            cr->location_ex.ip_type = DATA_TYPE_IPV6;
    }
    print_ip(cr->location_ex.ip_addr, cr->location_ex.ip_type);
}

void print_location_resp(struct location_resp_t *cr) {
    int32_t i;
    printf("\n");
    printf("timestamp: %lu\n", cr->timestamp);
    printf("protocol: %d\n", cr->protocol);
    printf("server version: %d\n", cr->version);
    printf("payload type no: %d\n", cr->payload_type);

    printf("Device MAC: ");
    for (i = 0; i < 6; i++)
        printf("%02X", cr->MAC[i]);
    printf("\n");

    switch (cr->payload_type) {
    case LOCATION_RQ_SUCCESS:
        puts("LOCATION_RQ_SUCCESS");
        print_location_rq(cr);
        break;
    case LOCATION_RQ_ADDR_SUCCESS:
        puts("LOCATION_RQ_SUCCESS");
        print_location_rq(cr);
        print_location_rq_addr(cr);
        break;
    case PROBE_REQUEST_SUCCESS:
        puts("PROBE_REQUEST");
        break;
    case LOCATION_API_ERROR:
        puts("PAYLOAD_API_ERROR");
        break;
    case LOCATION_GATEWAY_ERROR:
        puts("SERVER_ERROR");
        break;
    case LOCATION_RQ_ERROR:
        puts("LOCATION_RQ_ERROR");
        break;
    }
}

void print_location_req(struct location_req_t *cr) {
    int32_t i, j;

    printf("protocol: %d\n", cr->protocol);
    printf("payload type: %d\n", cr->payload_type);
    printf("firmware version: %d\n", cr->version);

    printf("userid: %d\n", cr->key.userid);

    printf("Device MAC: ");
    for (i = 0; i < 6; i++)
        printf("%02X", cr->MAC[i]);
    printf("\n");

    printf("Access points %d\n", cr->ap_count);
    for (i = 0; i < cr->ap_count; i++) {
        printf("MAC: ");
        for (j = 0; j < 6; j++)
            printf("%02X", cr->aps[i].MAC[j]);
        printf("\n");
        printf("rssi: %d\n", cr->aps[i].rssi);
    }

    printf("BLE %d\n", cr->ble_count);

    for (i = 0; i < cr->ble_count; i++) {
        printf("MAC: ");
        for (j = 0; j < 6; j++)
            printf("%02X", cr->bles[i].MAC[j]);
        printf("\n");
        printf("major: %d\n", cr->bles[i].major);
        printf("minor: %d\n", cr->bles[i].minor);

        printf("uuid: ");
        for (j = 0; j < 16; j++)
            printf("%02X", cr->bles[i].uuid[j]);
        printf("\n");
    }

    printf("CELL %d\n", cr->cell_count);

    switch (cr->cell_type) {
    case DATA_TYPE_GSM:
        puts("CELL TYPE: GSM");
        break;
    case DATA_TYPE_CDMA:
        puts("CELL TYPE: CDMA");
        break;
    case DATA_TYPE_UMTS:
        puts("CELL TYPE: UMTS");
        break;
    case DATA_TYPE_LTE:
        puts("CELL TYPE: LTE");
        break;
    default:
        puts("CELL TYPE: NONE");
    }

    for (i = 0; i < cr->cell_count; i++) {
        switch (cr->cell_type) {
        case DATA_TYPE_GSM:
            printf("age: %d\n", cr->gsm[i].age);
            printf("ci: %d\n", cr->gsm[i].ci);
            printf("mcc: %d\n", cr->gsm[i].mcc);
            printf("mnc: %d\n", cr->gsm[i].mnc);
            printf("lac: %d\n", cr->gsm[i].lac);
            printf("rssi: %d\n", cr->gsm[i].rssi);
            break;

        case DATA_TYPE_UMTS:
            printf("age: %d\n", cr->umts[i].age);
            printf("ci: %d\n", cr->umts[i].ci);
            printf("mcc: %d\n", cr->umts[i].mcc);
            printf("mnc: %d\n", cr->umts[i].mnc);
            printf("lac: %d\n", cr->umts[i].lac);
            printf("rssi: %d\n", cr->umts[i].rssi);
            break;

        case DATA_TYPE_CDMA:
            printf("age: %d\n", cr->cdma[i].age);
            printf("lat: %f\n", cr->cdma[i].lat);
            printf("lon: %f\n", cr->cdma[i].lon);
            printf("sid: %d\n", cr->cdma[i].sid);
            printf("nid: %d\n", cr->cdma[i].nid);
            printf("bsid: %d\n", cr->cdma[i].bsid);
            printf("rssi: %d\n", cr->cdma[i].rssi);
            break;

        case DATA_TYPE_LTE:
            printf("age: %d\n", cr->lte[i].age);
            printf("eucid: %d\n", cr->lte[i].eucid);
            printf("mcc: %d\n", cr->lte[i].mcc);
            printf("mnc: %d\n", cr->lte[i].mnc);
            printf("rssi: %d\n", cr->lte[i].rssi);
            break;

        default:
            printf("unknown cell type %d\n", cr->cell_type);
        }
    }

    printf("GPS %d\n", cr->gps_count);

    for (i = 0; i < cr->gps_count; i++) {
        printf("lat: %f\n", cr->gps[i].lat);
        printf("lon: %f\n", cr->gps[i].lon);
        printf("alt: %f\n", cr->gps[i].alt);
        printf("hpe: %f\n", cr->gps[i].hpe);
        printf("speed: %f\n", cr->gps[i].speed);
        printf("nsat: %d\n", cr->gps[i].nsat);
        printf("fix: %d\n", cr->gps[i].fix);
        printf("age: %d\n", cr->gps[i].age);
    }

}
