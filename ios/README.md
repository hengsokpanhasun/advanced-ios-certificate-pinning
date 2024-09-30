# iOS integration

This folder is the iOS layer: an `NSURLSession` delegate that pins the server's
**public key (SPKI)** using the portable hard-to-patch core in `../src`. It is
Objective-C against Apple's `Security` framework, so it builds inside your Xcode
app — not with the repo's CMake (which builds and tests the C core only).

## Files

| File | Role |
|------|------|
| `AICPSPKI.{h,m}` | Extract a certificate's DER SubjectPublicKeyInfo from `SecTrust` (RSA-2048/4096, EC P-256/P-384) |
| `AICPPinningDelegate.{h,m}` | `NSURLSessionDelegate` that validates the chain, pins the SPKI via the core, and optionally hands up a bound key |

## Add to an app

1. Drag `ios/AICPSPKI.*`, `ios/AICPPinningDelegate.*` and the C core
   (`src/aicp.c`, `src/pins.c`, `src/sha256.c`, `src/hmac_sha256.c`, plus the
   `include/` and `src/` headers) into your target. Link `Security.framework`.
2. Put your real pins into `src/pins.c` with `tools/gen_pins` (see
   `../docs/HARDENING_IOS.md`).

### Objective-C

```objc
AICPPinningDelegate *pinner = [AICPPinningDelegate new];
pinner.pinnedHosts = [NSSet setWithObject:@"api.yourservice.com"];

NSURLSession *session =
    [NSURLSession sessionWithConfiguration:NSURLSessionConfiguration.defaultSessionConfiguration
                                  delegate:pinner
                             delegateQueue:nil];
```

### Swift (via a bridging header exposing `aicp.h`)

```swift
let pinner = AICPPinningDelegate()
pinner.pinnedHosts = ["api.yourservice.com"]
let session = URLSession(configuration: .default, delegate: pinner, delegateQueue: nil)
```

## The important part — don't stop at the boolean

The delegate must end in "use credential" or "cancel", so there is, unavoidably,
a boolean in *this* Objective-C code that an attacker can patch. That is why the
delegate also derives a key with `aicp_bind_key` and hands it to
`keyBoundHandler`. Use that key to protect something the app genuinely needs:

```objc
pinner.keyBoundHandler = ^(NSString *host, NSData *key) {
    // e.g. derive the HMAC key for your API request signing from `key`,
    // or unseal a config blob provisioned under the real server's key.
};
```

Now even if someone patches the delegate to always accept, a MITM session derives
the *wrong* key, so request signatures fail and sealed data stays sealed. The
patch-resistance lives at the app/data layer, not at the accept/reject branch.
See `../docs/HARDENING_IOS.md`.
