#ifndef ADDRESSES_H_
#define ADDRESSES_H_

#include <stdint.h>

#define E164_ADDRESS_SIZE 8
#define E164_MAX_LENGTH 15

/* Struct holding an E.164 address
 *
 * just a normal phone number
 */
struct E164_address {
    uint8_t address[E164_ADDRESS_SIZE];
};

/*
 * Struct holding an ATM address per E.191
 *
 * We only support E.164 AESA which means that the idi is an E.164 address
 */
struct E191_address {
    uint8_t idp;
    struct E164_address idi;
    uint8_t ho_dsp[4];
    uint8_t esi[6];
    uint8_t sel;
} __packed;

#endif
