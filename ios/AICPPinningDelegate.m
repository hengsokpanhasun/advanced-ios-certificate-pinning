//
//  AICPPinningDelegate.m
//  Advanced iOS Certificate Pinning
//
#import "AICPPinningDelegate.h"
#import "AICPSPKI.h"
#import <Security/Security.h>
#import "aicp.h"

@implementation AICPPinningDelegate {
    aicp_ctx *_ctx;
}

- (instancetype)init {
    if ((self = [super init])) {
        _ctx = aicp_create();
        _pinnedHosts = [NSSet set];
        _bindingInfo = [@"aicp/session/v1" dataUsingEncoding:NSUTF8StringEncoding];
    }
    return self;
}

- (void)dealloc {
    if (_ctx) aicp_destroy(_ctx);
}

- (void)URLSession:(NSURLSession *)session
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
      completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition,
                                  NSURLCredential *_Nullable))completionHandler {

    NSURLProtectionSpace *space = challenge.protectionSpace;

    // Only handle server-trust challenges; let the system do the rest.
    if (![space.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }
    // Pin only configured hosts (empty set = pin everything).
    if (self.pinnedHosts.count > 0 && ![self.pinnedHosts containsObject:space.host]) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }

    SecTrustRef trust = space.serverTrust;
    if (!trust) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // 1) Standard chain validation FIRST — pinning is in addition to it, never
    //    a replacement. A pinned key on an otherwise-invalid chain is still bad.
    CFErrorRef err = NULL;
    if (!SecTrustEvaluateWithError(trust, &err)) {
        if (err) CFRelease(err);
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // 2) Public-key pinning against the obfuscated, bound pin set.
    BOOL matched = NO;
    NSData *matchedSPKI = nil;
    CFIndex count = SecTrustGetCertificateCount(trust);
    for (CFIndex i = 0; i < count; i++) {
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, i);
        NSData *spki = [AICPSPKI spkiDERForCertificate:cert];
        if (!spki) continue;
        if (aicp_evaluate_spki(_ctx, spki.bytes, spki.length) == 1) {
            matched = YES;
            matchedSPKI = spki;
            break;
        }
    }

    if (!matched) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // 3) HARD guarantee: derive a key bound to the matched public key and hand it
    //    up so app-layer protection (request MAC / sealed config) depends on it.
    //    The boolean above is a branch an attacker could patch in THIS code; the
    //    key binding below is what they cannot forge — see docs/HARDENING_IOS.md.
    if (self.keyBoundHandler && matchedSPKI) {
        uint8_t key[AICP_KEY_LEN];
        if (aicp_bind_key(_ctx, matchedSPKI.bytes, matchedSPKI.length,
                          self.bindingInfo.bytes, self.bindingInfo.length, key) == 0) {
            self.keyBoundHandler(space.host, [NSData dataWithBytes:key length:sizeof(key)]);
            memset(key, 0, sizeof(key));
        }
    }

    completionHandler(NSURLSessionAuthChallengeUseCredential,
                      [NSURLCredential credentialForTrust:trust]);
}

@end
