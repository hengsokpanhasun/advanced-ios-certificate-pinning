//
//  AICPPinningDelegate.h
//  Advanced iOS Certificate Pinning
//
//  A drop-in NSURLSession delegate that performs public-key (SPKI) pinning using
//  the portable hard-to-patch core. Assign it as your URLSession's delegate.
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AICPPinningDelegate : NSObject <NSURLSessionDelegate, NSURLSessionTaskDelegate>

/// Hosts to pin. If empty, every TLS host is pinned. Hosts not in the set fall
/// back to the system's default trust evaluation.
@property (nonatomic, copy) NSSet<NSString *> *pinnedHosts;

/// Optional: called with a key derived by aicp_bind_key for a matched connection.
/// Use it to key app-layer protection (a request MAC, a sealed config) so that
/// even a patched delegate cannot make a MITM session produce valid app data.
/// `info` is the binding context; pass the same value you provisioned with.
@property (nonatomic, copy, nullable) void (^keyBoundHandler)(NSString *host, NSData *derivedKey);

/// The binding context passed to key derivation (default: "aicp/session/v1").
@property (nonatomic, copy) NSData *bindingInfo;

@end

NS_ASSUME_NONNULL_END
