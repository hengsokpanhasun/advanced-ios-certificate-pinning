# Hardening notes — pinning that resists patching on iOS

On iOS, certificate pinning is usually broken not by attacking the crypto but by
**patching the decrypted app binary** (App Store binaries are FairPlay-encrypted;
an attacker works from a decrypted copy and sideloads it) or by **hooking at
runtime** on a jailbroken device. Either way, the target is the one place the
code turns the TLS result into *accept vs reject*. This document lists those
attacks and the choices here that blunt each one.

Guiding principle, same as the portable core: **never let the trust decision be a
single boolean.** Bind the pinned public key into key material the app needs, so a
wrong certificate yields the wrong key and the app simply stops working.

---

## Attack 1 — Flip the verdict branch in the TLS core

A modern TLS stack ends pin checking at a small routine that compares the
presented certificate's SPKI hash against a hardcoded table, then branches:

```asm
    ; ... compare SPKI hash to pin[i] ...
    cbnz  w?, match_exit     ; <- flip to an unconditional branch = always "match"
    ; ... build "Pinning validation failed" error ...
match_exit:
    ; ... set verdict register = success ...
```

Forcing that per-pin branch to the match exit makes **any** certificate pass. A
two-byte, same-size in-place edit.

**Defense here.** Hard mode (`aicp_bind_key`) has **no verdict branch**. The
public key is an input to a key derivation, not an operand of a comparison, so
there is no `cbnz`/`cbz`/`b.ne` to force.

## Attack 2 — Stub the chain-verify gate to "trusted"

Many stacks route trust through an exported `X509_verify_cert`-style symbol. An
analyst finds it by name and overwrites its first instructions with
`mov w0, #1 ; ret` — now every chain "verifies".

**Defense here.** There is no function here that returns "verified". Forcing
`aicp_bind_key` to return a constant just returns a constant *wrong key*, which
fails to unseal the provisioned data. (Standard chain validation still happens in
the delegate via `SecTrustEvaluateWithError` — pinning is **in addition** to it,
not a replacement.)

## Attack 3 — Anchor on the on-screen error string

The fastest way to *locate* the check: the stack builds a user-visible string like
`"Pinning validation failed."`. It has exactly one cross-reference, pointing
straight at the branch from Attack 1.

**Defense here.** The hard path emits no strings at the decision point — there is
no decision and no message to anchor on. Keep any pinning-failure UI text far from
the comparison and behind opaque codes.

## Attack 4 — Scan or diff the pin table

Pins are often a plaintext array of 32-byte SHA-256 hashes in `__DATA`/`__TEXT`.
An analyst greps the decrypted Mach-O for the table, or diffs against a published
pin set, to find and neutralize the check — or swaps in their own pin.

**Defense here.** Pins are stored XOR-masked (`src/pins.c`); no 32-byte pin
appears in the binary, and they are folded into `master` and `self_digest`, so
**swapping a pin changes every derived key** — a substitution breaks the app.

## Attack 5 — Hook at runtime (jailbreak + Frida/dylib)

On a jailbroken device the attacker skips static patching and hooks the verify
function, or injects a dylib that forces acceptance.

**Defense here.** A hook that forces the *delegate* to accept still cannot make
the connection produce a valid **bound key**: `aicp_bind_key` derives from the
real presented SPKI, so a MITM session's key is wrong and app-layer MACs / sealed
configs fail. This pushes the attacker to dumping the already-unsealed secret from
live memory — the runtime plane, where you add anti-debug/anti-hook/attestation.

## Attack 6 — Trust-store / profile manipulation

Installing a configuration profile with a trusted CA makes the OS trust a MITM
cert.

**Defense here.** Public-key pinning bound to a specific SPKI ignores the OS trust
decision for the pinning step, so a newly trusted CA does not satisfy the pin.

---

## Where the real guarantee lives on iOS

A `URLSession` delegate **must** end in accept or cancel, so there is
unavoidably a boolean in the Objective-C layer that an attacker can patch. Do not
rely on it alone. Use `keyBoundHandler` to derive a key with `aicp_bind_key` and
key your app-layer protection with it — request signing, a sealed config, a
derived session secret. Then "always accept" buys the attacker nothing, because
the MITM key is wrong. **The boolean is the weak link; the key binding is the
strong one.**

## Provisioning (your own pins)

```sh
openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der > spki.der
./build/gen_pins 0 spki.der   # paste the row into src/pins.c
```

Pin the **issuer/intermediate** public key and keep a backup pin so certificate
rotation doesn't brick the app.

## Text integrity in production

The default folds **data** integrity (pins + secrets) into the key. To also bind
the **code**, checksum the derive routine and fold it into provisioning. On
Mach-O, hash a dedicated `__TEXT` section via `getsectiondata`, and derive the
provisioned key with that checksum included — then any patch to the routine
changes the key.

## What this does and does not buy you

- **Does:** remove the single-branch / `mov w0,#1;ret` / string-anchor / pin-swap
  static-patch targets; make a patch self-defeating (wrong key); keep the pin
  independent of the OS trust store and configuration profiles.
- **Does not:** stop a determined attacker on a jailbroken device who dumps the
  unsealed secret or derived key from memory. Pair with jailbreak/debugger/hook
  detection and app attestation. Being honest about this boundary is part of the
  design.
