/* A narrated walk through both modes of the portable core. Target: aicp_demo. */
#include "aicp.h"
#include "sha256.h"
#include "vectors.h"
#include <stdio.h>
#include <string.h>

static void hex(const char *label, const uint8_t *b, size_t n) {
  size_t i;
  printf("%s", label);
  for (i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

static void seal(const uint8_t key[32], const uint8_t *in, uint8_t *out, size_t n) {
  size_t i;
  uint8_t block[36], stream[32];
  for (i = 0; i < n; i++) {
    if ((i & 31u) == 0) {
      uint32_t ctr = (uint32_t)(i >> 5);
      memcpy(block, key, 32);
      block[32] = (uint8_t)(ctr >> 24); block[33] = (uint8_t)(ctr >> 16);
      block[34] = (uint8_t)(ctr >> 8);  block[35] = (uint8_t)ctr;
      sha256(block, sizeof block, stream);
    }
    out[i] = (uint8_t)(in[i] ^ stream[i & 31u]);
  }
}

int main(void) {
  aicp_ctx *ctx = aicp_create();
  uint8_t kReal[32], kMitm[32];
  const char *cfg = "api=https://real.example;token=PROVISIONED-SECRET";
  size_t n = strlen(cfg);
  uint8_t sealed[64], openReal[64], openMitm[64];

  if (!ctx) { fprintf(stderr, "init failed\n"); return 1; }

  puts("== Advanced iOS Certificate Pinning — core demo ==\n");
  puts("(This is the portable C core the iOS URLSession layer calls into.)\n");

  puts("[weak mode] boolean verdict (patchable at the call site):");
  printf("  real server key   -> evaluate = %d\n", aicp_evaluate_spki(ctx, SPKI_A, sizeof SPKI_A));
  printf("  attacker MITM key -> evaluate = %d\n\n", aicp_evaluate_spki(ctx, SPKI_MITM, sizeof SPKI_MITM));

  puts("[hard mode] the public key is bound to key material (no verdict branch):");
  aicp_bind_key(ctx, SPKI_A, sizeof SPKI_A, (const uint8_t *)"session", 7, kReal);
  aicp_bind_key(ctx, SPKI_MITM, sizeof SPKI_MITM, (const uint8_t *)"session", 7, kMitm);
  hex("  key(real key) = ", kReal, 32);
  hex("  key(MITM key) = ", kMitm, 32);
  puts("  -> different keys. Nothing decided accept/reject; the key simply differs.\n");

  puts("[proof-of-possession] a config sealed under the real key's derived key:");
  seal(kReal, (const uint8_t *)cfg, sealed, n);
  seal(kReal, sealed, openReal, n);
  seal(kMitm, sealed, openMitm, n);
  printf("  real key unseals -> \"%.*s\"\n", (int)n, openReal);
  printf("  MITM key unseals -> ");
  { size_t i; for (i = 0; i < n; i++) putchar((openMitm[i] >= 32 && openMitm[i] < 127) ? openMitm[i] : '.'); }
  puts("\n  -> garbage, and no branch exists to turn it back into the real config.");

  aicp_destroy(ctx);
  return 0;
}
