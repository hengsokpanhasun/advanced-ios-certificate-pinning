/*
 * Obfuscated pin set.
 *
 * Each 32-byte SHA-256 SPKI pin is stored XOR-masked with
 *     mask[i] = SHA-256(AICP_MASK_SECRET || i)[0:32]
 * so no plaintext pin appears in the binary. On iOS this matters a lot: an
 * analyst who dumps the app's __TEXT/__DATA cannot grep a 32-byte pin table, and
 * cannot diff the binary against a published pin set to locate the check.
 *
 * NOTE: obfuscation only hides where the pins are. The tamper-resistance comes
 * from aicp_bind_key() binding the pin to key material (aicp.c / docs).
 */
#include "pins.h"

const uint8_t AICP_MASK_SECRET[AICP_SECRET_LEN] = {
    'a', 'i', 'c', 'p', '/', 'm', 'a', 's', 'k', '/', 'v', '1'};
const uint8_t AICP_ROOT_SECRET[AICP_SECRET_LEN] = {
    'a', 'i', 'c', 'p', '/', 'r', 'o', 'o', 't', '/', 'v', '1'};

/* Two masked pins (demo issuer public keys). Replace with your own and
 * regenerate with tools/gen_pins (see docs/HARDENING_IOS.md, "provisioning"). */
const uint8_t AICP_MASKED_PINS[AICP_PIN_COUNT][AICP_PIN_LEN] = {
    {/* masked pin[0] */
     0xe7, 0xcc, 0x27, 0x71, 0x90, 0x77, 0xf8, 0x1b, 0x06, 0xf9, 0xb2, 0x2a,
     0x5d, 0x4b, 0xb7, 0xde, 0x9f, 0x15, 0x47, 0xc6, 0xa0, 0xf0, 0xbd, 0x9e,
     0x28, 0x4e, 0x9d, 0x92, 0x38, 0x02, 0xd5, 0x5a},
    {/* masked pin[1] */
     0x7e, 0xe3, 0xa4, 0xec, 0x0c, 0xe6, 0x47, 0xb4, 0x5c, 0x8c, 0x15, 0x7b,
     0x4a, 0xe0, 0x4f, 0xb3, 0xbb, 0x70, 0x8e, 0x8a, 0x78, 0x6b, 0x4d, 0x19,
     0xba, 0xde, 0x4f, 0x15, 0xc7, 0xfc, 0x71, 0x54},
};
