//
//  AICPSPKI.m
//  Advanced iOS Certificate Pinning
//
//  SecKeyCopyExternalRepresentation returns the *raw* public key (PKCS#1 for RSA,
//  04||X||Y for EC) — not a full SubjectPublicKeyInfo. To get an SPKI hash that
//  matches OpenSSL / other pinners, we prepend the fixed ASN.1 header for the key
//  type and size, then the result is the DER SPKI. (Same approach as TrustKit.)
//
#import "AICPSPKI.h"

// --- fixed ASN.1 SubjectPublicKeyInfo headers -------------------------------
static const uint8_t kRSA2048[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00};
static const uint8_t kRSA4096[] = {
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00};
static const uint8_t kECP256[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00};
static const uint8_t kECP384[] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00};

@implementation AICPSPKI

+ (nullable NSData *)headerForKeyType:(NSString *)type sizeBits:(NSInteger)bits {
    if ([type isEqualToString:(__bridge NSString *)kSecAttrKeyTypeRSA]) {
        if (bits == 2048) return [NSData dataWithBytes:kRSA2048 length:sizeof(kRSA2048)];
        if (bits == 4096) return [NSData dataWithBytes:kRSA4096 length:sizeof(kRSA4096)];
    } else if ([type isEqualToString:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom]) {
        if (bits == 256) return [NSData dataWithBytes:kECP256 length:sizeof(kECP256)];
        if (bits == 384) return [NSData dataWithBytes:kECP384 length:sizeof(kECP384)];
    }
    return nil; // unsupported key type/size — fail closed
}

+ (nullable NSData *)spkiDERForCertificate:(SecCertificateRef)certificate {
    if (!certificate) return nil;

    SecKeyRef key = SecCertificateCopyKey(certificate); // iOS 12+
    if (!key) return nil;

    NSData *result = nil;
    CFErrorRef err = NULL;
    CFDataRef raw = SecKeyCopyExternalRepresentation(key, &err);
    CFDictionaryRef attrs = SecKeyCopyAttributes(key);

    if (raw && attrs) {
        NSString *type = (__bridge NSString *)CFDictionaryGetValue(attrs, kSecAttrKeyType);
        NSNumber *bits = (__bridge NSNumber *)CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
        NSData *header = [self headerForKeyType:type sizeBits:bits.integerValue];
        if (header) {
            NSMutableData *spki = [NSMutableData dataWithData:header];
            [spki appendData:(__bridge NSData *)raw];
            result = spki;
        }
    }

    if (raw) CFRelease(raw);
    if (attrs) CFRelease(attrs);
    if (err) CFRelease(err);
    CFRelease(key);
    return result;
}

@end
