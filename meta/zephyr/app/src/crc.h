#include <stddef.h>
#include <stdint.h>

#define CRC_INITIAL_VALUE 0xFFFFFFFF
#define CRC_FINISH(crc) (~(crc))

uint32_t update_crc(uint32_t crc, const uint8_t *data, size_t length);
