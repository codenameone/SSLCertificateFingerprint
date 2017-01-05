#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonDigest.h>

@interface com_codename1_security_certfingerprint_impl_CheckCertInternalImpl : NSObject <NSURLConnectionDelegate> {
}

-(void)checkCert:(NSString*)param;
-(BOOL)isSupported;
@end
