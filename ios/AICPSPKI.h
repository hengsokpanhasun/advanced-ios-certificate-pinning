//
//  AICPSPKI.h
//  Advanced iOS Certificate Pinning
//
//  Extract the full DER SubjectPublicKeyInfo of a certificate's public key, so it
//  can be SHA-256'd into a pin and compared / bound by the portable core.
//
#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

@interface AICPSPKI : NSObject

/// The DER SubjectPublicKeyInfo for a certificate's public key, or nil if the
/// key type/size is unsupported. Supports RSA-2048/4096 and EC P-256/P-384 —
/// the common server key types.
+ (nullable NSData *)spkiDERForCertificate:(SecCertificateRef)certificate;

@end

NS_ASSUME_NONNULL_END
