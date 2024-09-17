/*
 * Advanced iOS Certificate Pinning — portable core.
 *
 *   1. Hard mode has NO verdict branch. aicp_bind_key derives
 *          key = HMAC(master, SHA256(presented_pin || self_digest || info))
 *      where master is bound to the whole pin table and self_digest to the
 *      obfuscated pin/secret bytes. A wrong public key, a patched pin or a patched
 *      secret all just change the key. There is nothing to flip.
 *   2. The weak boolean mode is constant-time with no early-exit loop, so the only
 *      patchable point is the caller's use of the final bool.
 *   3. Pins are stored obfuscated (pins.c) and folded into the integrity surfaces.
 */
#include "aicp.h"
#include "pins.h"
#include "sha256.h"
#include "hmac_sha256.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t AICP_ANCHOR[16] = {0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a,
                                        0x7c, 0x15, 0xf3, 0x9c, 0xc0, 0x60,
                                        0x5c, 0xed, 0xc8, 0x34};

struct aicp_ctx {
  uint8_t pins[AICP_PIN_COUNT][AICP_PIN_LEN];
  uint8_t master[32];
  uint8_t self_digest[32];
};

static void derive_mask(uint8_t i, uint8_t out[32]) {
  uint8_t buf[AICP_SECRET_LEN + 1];
  memcpy(buf, AICP_MASK_SECRET, AICP_SECRET_LEN);
  buf[AICP_SECRET_LEN] = i;
  sha256(buf, sizeof buf, out);
}

static void compute_self_digest(uint8_t out[32]) {
  sha256_ctx c;
  sha256_init(&c);
  sha256_update(&c, (const uint8_t *)AICP_MASKED_PINS, sizeof AICP_MASKED_PINS);
  sha256_update(&c, AICP_MASK_SECRET, AICP_SECRET_LEN);
  sha256_update(&c, AICP_ROOT_SECRET, AICP_SECRET_LEN);
  sha256_update(&c, AICP_ANCHOR, sizeof AICP_ANCHOR);
  sha256_final(&c, out);
}

/* Constant-time equality: 1 if equal, 0 otherwise. No early exit. */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t d = 0;
  size_t i;
  for (i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
  return (int)(1u & (((uint32_t)d - 1u) >> 8)); /* d==0 -> 1, else 0 */
}

aicp_ctx *aicp_create(void) {
  aicp_ctx *ctx = (aicp_ctx *)calloc(1, sizeof *ctx);
  uint8_t mask[32];
  size_t i, j;
  if (!ctx) return NULL;

  for (i = 0; i < AICP_PIN_COUNT; i++) {
    derive_mask((uint8_t)i, mask);
    for (j = 0; j < AICP_PIN_LEN; j++)
      ctx->pins[i][j] = (uint8_t)(AICP_MASKED_PINS[i][j] ^ mask[j]);
  }
  hmac_sha256(AICP_ROOT_SECRET, AICP_SECRET_LEN, (const uint8_t *)ctx->pins,
              sizeof ctx->pins, ctx->master);
  compute_self_digest(ctx->self_digest);

  memset(mask, 0, sizeof mask);
  return ctx;
}

void aicp_destroy(aicp_ctx *ctx) {
  if (ctx) {
    memset(ctx, 0, sizeof *ctx);
    free(ctx);
  }
}

void aicp_spki_pin(const uint8_t *spki, size_t spki_len, uint8_t out[AICP_PIN_LEN]) {
  sha256(spki, spki_len, out);
}

int aicp_evaluate_spki(const aicp_ctx *ctx, const uint8_t *spki, size_t spki_len) {
  uint8_t pin[AICP_PIN_LEN];
  unsigned found = 0;
  size_t i;
  if (!ctx || !spki) return 0;

  sha256(spki, spki_len, pin);
  for (i = 0; i < AICP_PIN_COUNT; i++) /* OR-accumulate, no early return */
    found |= (unsigned)ct_eq(pin, ctx->pins[i], AICP_PIN_LEN);
  memset(pin, 0, sizeof pin);
  return (int)(found & 1u);
}

int aicp_bind_key(const aicp_ctx *ctx, const uint8_t *spki, size_t spki_len,
                  const uint8_t *info, size_t info_len, uint8_t out_key[AICP_KEY_LEN]) {
  uint8_t pin[AICP_PIN_LEN];
  uint8_t inner[32];
  sha256_ctx s;
  if (!ctx || !spki || !out_key) return -1;

  sha256(spki, spki_len, pin);

  sha256_init(&s);
  sha256_update(&s, pin, AICP_PIN_LEN);
  sha256_update(&s, ctx->self_digest, sizeof ctx->self_digest);
  if (info && info_len) sha256_update(&s, info, info_len);
  sha256_final(&s, inner);

  hmac_sha256(ctx->master, sizeof ctx->master, inner, sizeof inner, out_key);

  memset(pin, 0, sizeof pin);
  memset(inner, 0, sizeof inner);
  return 0;
}

void aicp_self_digest(const aicp_ctx *ctx, uint8_t out[AICP_DIGEST_LEN]) {
  memcpy(out, ctx->self_digest, AICP_DIGEST_LEN);
}

void aicp_text_checksum(const void *fn, size_t len, uint8_t out[AICP_DIGEST_LEN]) {
  sha256((const uint8_t *)fn, len, out);
}
