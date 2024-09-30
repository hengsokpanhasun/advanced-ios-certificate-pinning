# Threat model

## Who we defend against

A capable analyst with the app's decrypted iOS binary and a MITM proxy, who wants
to read or modify its TLS traffic. On iOS their cheapest tools are **static patching
of the decrypted Mach-O** (sideloaded) and, on a jailbroken device, **runtime
hooking** (Frida / injected dylib). This library is built to make the cheap static
attack fail and to blunt the runtime one.

## In scope

| Attack | Mitigation |
|--------|------------|
| Flip the pin-compare verdict branch | Hard mode has no verdict branch (`aicp_bind_key`) |
| Stub the chain-verify gate to "trusted" | No "verified" return; a forced constant is a wrong key |
| Anchor on the pinning error string | No strings at the decision point |
| Grep / diff the plaintext pin table | Pins XOR-masked and folded into the key |
| Swap in an attacker's pin | Pins bound into `master` → a swap breaks the app |
| Add a trusted CA via a config profile | Key-binding ignores the OS trust decision for the pin |
| Hook the delegate to always accept | App-layer MAC / sealed config keyed by the bound key still fails |

## Out of scope (pair with other controls)

- **Runtime memory extraction** on a jailbroken, instrumented device (dumping the
  unsealed secret or the derived key). Mitigate with jailbreak/debugger/hook
  detection and **App Attest** / DeviceCheck — not this library alone.
- **Lifting the symmetric secrets** compiled into the binary. They are obfuscated
  and split, which raises cost; a static bypass is still prevented by the binding.
- **A mis-issued or compromised real certificate.** Pin the issuer and keep backup
  pins; that is a PKI problem.

## Residual risk

The honest ceiling is a runtime attacker on a jailbroken device. The design goal
is to move the fight off the trivially-cheap static-patch plane and onto the
runtime plane, where defenders have real tools (attestation, integrity, detection).
