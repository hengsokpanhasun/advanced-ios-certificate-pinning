# Advanced iOS Certificate Pinning

Public-key (SPKI) certificate pinning for iOS that is **hard to defeat with a
static binary patch** — the way pinning is usually broken on iOS. A `URLSession`
delegate does the pinning; a small, dependency-free C core makes the trust
decision something an attacker can't simply flip.

The usual iOS bypass never touches the crypto: find the one branch in the app's
TLS core that means "trusted", patch the decrypted binary, re-sign, sideload. This
library removes that single point of failure.

> Objective-C `URLSession` layer · portable C99 core (no deps) · CMake + CTest · MIT

## The idea in one line

Don't make the trust decision a boolean an attacker can flip — **bind the pinned
public key into key material the app actually needs**, so a MITM certificate
yields the wrong key and request signing / sealed config / the session itself
fails.

## iOS usage

```objc
AICPPinningDelegate *pinner = [AICPPinningDelegate new];
pinner.pinnedHosts = [NSSet setWithObject:@"api.yourservice.com"];
NSURLSession *session =
    [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.defaultSessionConfiguration
                                  delegate:pinner delegateQueue:nil];

// Strong path: key app-layer protection to the matched certificate.
pinner.keyBoundHandler = ^(NSString *host, NSData *key) {
    // derive your request-signing HMAC key / unseal a provisioned config from `key`
};
```

The delegate validates the chain (`SecTrustEvaluateWithError`), extracts the
server SPKI (`AICPSPKI`), and pins it through the core. Full iOS integration
notes: **[ios/README.md](ios/README.md)**.

## Why it resists patching

| Standard iOS attack | What this does instead |
|---------------------|------------------------|
| Flip the pin-compare verdict branch (`cbnz`↔`b`) | Hard mode has **no branch** — the key is derived from the public key |
| Stub the chain-verify gate to `mov w0,#1; ret` | No "verified" return exists; a forced constant is a wrong key |
| Anchor on the `"Pinning validation failed."` string | No strings at the decision point |
| Grep / diff the plaintext pin table in the Mach-O | Pins stored **XOR-masked**; folded into the key |
| Swap in the attacker's own pin | Pins folded into the derived key → a swap **breaks** the app |
| Hook the delegate to always accept (jailbreak) | App-layer MAC / sealed config keyed by the bound key still fails |
| Trust a CA via a config profile | Key-binding ignores the OS trust decision for the pin |

Full write-up: **[docs/HARDENING_IOS.md](docs/HARDENING_IOS.md)**. Scope and
limits: **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**.

## Build & test the core

The C core builds and tests anywhere (the iOS layer builds in Xcode):

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure   # SHA/HMAC KATs + pinning behaviour
./build/aicp_demo                             # narrated walk-through
```

The demo shows the real public key unsealing a provisioned config while a MITM key
gets unrecoverable garbage — with no branch in between to flip.

## Layout

```
include/aicp.h      portable core API (called from the iOS layer)
src/aicp.c          core: pinset, constant-time verify, key-binding, integrity
src/pins.c          obfuscated (XOR-masked) compiled-in pin set
src/sha256.*        bundled SHA-256 (FIPS 180-4)
src/hmac_sha256.*   bundled HMAC-SHA256 (RFC 2104)
ios/                URLSession pinning delegate + SPKI extraction (Objective-C)
examples/demo.c     narrated core demo
tools/gen_pins.c    turn a DER SPKI into an obfuscated pin row
tests/              SHA/HMAC known-answer tests + pinning behaviour
docs/               iOS hardening notes + threat model
```

## Your own pins

```sh
openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der > spki.der
./build/gen_pins 0 spki.der    # paste the row into src/pins.c
```

Pin the **issuer/intermediate** key and keep a backup pin so certificate rotation
doesn't brick the app.

## Scope & ethics

A **defensive** security-engineering project: it helps iOS developers make their
own certificate pinning resilient to tampering (OWASP MASVS resilience). It is not
an evasion tool and it is honest about its ceiling — a determined runtime attacker
on a jailbroken device is out of scope (see the threat model). Pair it with
jailbreak/hook detection and App Attest.

## License

MIT © 2024 Sun Hengsokpanha
