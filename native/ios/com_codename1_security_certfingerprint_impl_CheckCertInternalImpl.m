#import "com_codename1_security_certfingerprint_impl_CheckCertInternalImpl.h"

#include "com_codename1_security_certfingerprint_impl_Impl.h"

@implementation com_codename1_security_certfingerprint_impl_CheckCertInternalImpl

-(void)checkCert:(NSString*)param{
    dispatch_async(dispatch_get_main_queue(), ^{
        NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:param]];
        
        if(![NSURLConnection connectionWithRequest:request delegate:self]) {
            com_codename1_security_certfingerprint_impl_Impl_fail___java_lang_String(getThreadLocalData(), fromNSString(getThreadLocalData(), @"Connection error"));
        }
    });
}

-(BOOL)isSupported{
    return YES;
}

- (void) connection: (NSURLConnection*)connection willSendRequestForAuthenticationChallenge: (NSURLAuthenticationChallenge*)challenge {
    SecTrustRef trustRef = [[challenge protectionSpace] serverTrust];
    SecTrustEvaluate(trustRef, NULL);
    
    //    [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
    [connection cancel];
    
    CFIndex count = SecTrustGetCertificateCount(trustRef);
    
    SecCertificateRef certRef = SecTrustGetCertificateAtIndex(trustRef, 0);
    NSString* fingerprint = [self getFingerprint:certRef];
    com_codename1_security_certfingerprint_impl_Impl_success___java_lang_String(getThreadLocalData(), fromNSString(getThreadLocalData(), fingerprint));
}

// Delegate method, called from connectionWithRequest
- (void) connection: (NSURLConnection*)connection didFailWithError: (NSError*)error {
    connection = nil;
    
    com_codename1_security_certfingerprint_impl_Impl_fail___java_lang_String(getThreadLocalData(), fromNSString(getThreadLocalData(), [error localizedFailureReason]));
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    connection = nil;
}

- (NSString*) getFingerprint: (SecCertificateRef) cert {
    NSData* certData = (__bridge NSData*) SecCertificateCopyData(cert);
    unsigned char sha1Bytes[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(certData.bytes, (int)certData.length, sha1Bytes);
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 3];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; ++i) {
        [fingerprint appendFormat:@"%02x ", sha1Bytes[i]];
    }
    return [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

@end
