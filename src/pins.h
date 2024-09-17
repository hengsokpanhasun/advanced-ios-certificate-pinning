/* Compiled-in obfuscated pin set (see pins.c). */
#ifndef AICP_PINS_H
#define AICP_PINS_H

#include <stdint.h>
#include "aicp.h"

#define AICP_PIN_COUNT 2
#define AICP_SECRET_LEN 12 /* "aicp/mask/v1", "aicp/root/v1" */

extern const uint8_t AICP_MASK_SECRET[AICP_SECRET_LEN];
extern const uint8_t AICP_ROOT_SECRET[AICP_SECRET_LEN];
extern const uint8_t AICP_MASKED_PINS[AICP_PIN_COUNT][AICP_PIN_LEN];

#endif
