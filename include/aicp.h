/*
 * Advanced iOS Certificate Pinning (aicp) — portable core.
 *
 * This is the C core shared by the iOS integration layer (see ios/). It performs
 * public-key (SPKI) certificate pinning in a way that is hard to defeat with a
 * static binary patch — the usual way pinning is broken on iOS: find the single
 * verdict branch in the app's TLS core and flip it, or stub the verify routine to
 * return "trusted". See docs/HARDENING_IOS.md.
 *
 * The iOS layer extracts the server's SubjectPublicKeyInfo from the SecTrust
 * handed to a URLSession challenge, then calls into this core.
 *
 * Two modes:
 *   - aicp_evaluate_spki(): a classic boolean verdict. Constant-time and
 *     branch-reduced, but still a single boolean — the thing an attacker patches.
 *   - aicp_bind_key(): the hard mode. Derive a key cryptographically BOUND to the
 *     presented public key and this module's integrity. No accept/reject branch.
 */
#ifndef AICP_H
#define AICP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AICP_PIN_LEN 32 /* SHA-256 of the DER SubjectPublicKeyInfo */
#define AICP_KEY_LEN 32
#define AICP_DIGEST_LEN 32

typedef struct aicp_ctx aicp_ctx;

aicp_ctx *aicp_create(void);
void aicp_destroy(aicp_ctx *ctx);

/* SHA-256 pin of a DER SubjectPublicKeyInfo. */
void aicp_spki_pin(const uint8_t *spki, size_t spki_len, uint8_t out[AICP_PIN_LEN]);

/*
 * WEAK (compat) mode. Returns 1 if the SPKI matches a pin, 0 otherwise.
 * Constant-time, no early-exit — but still one boolean. Prefer aicp_bind_key().
 */
int aicp_evaluate_spki(const aicp_ctx *ctx, const uint8_t *spki, size_t spki_len);

/*
 * HARD mode. Derive a 32-byte key bound to the presented SPKI and this module's
 * integrity. The key equals the provisioned key ONLY when the SPKI matches a pin
 * AND the module is unpatched. There is no verdict branch to flip.
 * Returns 0 on success, -1 on bad arguments.
 */
int aicp_bind_key(const aicp_ctx *ctx, const uint8_t *spki, size_t spki_len,
                  const uint8_t *info, size_t info_len, uint8_t out_key[AICP_KEY_LEN]);

/* Module integrity digest folded into aicp_bind_key (data, + optional code). */
void aicp_self_digest(const aicp_ctx *ctx, uint8_t out[AICP_DIGEST_LEN]);

/* SHA-256 over `len` bytes of code at `fn` — fold into derivation for text
 * integrity (platform-specific; see docs/HARDENING_IOS.md). */
void aicp_text_checksum(const void *fn, size_t len, uint8_t out[AICP_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* AICP_H */
