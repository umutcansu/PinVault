// RNPinVaultURLRequestHandler — React Native's https traffic (fetch,
// XMLHttpRequest, <Image>) through PinVault's pinned session on iOS.
//
// RCTNetworking asks every RCTURLRequestHandler whether it can handle a request
// and picks the one with the highest handlerPriority (RCTNetworking.mm,
// handlerForRequest:). RCTHTTPRequestHandler has none (0); this one answers
// YES for https with priority 10, so RN's own handler only sees plain http
// (which ATS refuses unless the app allows it). In the New Architecture the
// handler list comes from codegen: package.json → codegenConfig.ios.
// modulesConformingToProtocol.RCTURLRequestHandler names this module, and
// RCTAppSetupUtils adds it to RCTNetworking's handlers.
//
// The work is Swift (PinVaultReactNetworking.swift → Core/ReactNetworking.swift).
#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>
#import <React/RCTURLRequestDelegate.h>
#import <React/RCTURLRequestHandler.h>
#import <ReactCommon/RCTTurboModule.h>

#if __has_include(<RNPinVault/RNPinVault-Swift.h>)
#import <RNPinVault/RNPinVault-Swift.h>
#else
#import "RNPinVault-Swift.h"
#endif

@interface RNPinVaultURLRequestHandler : NSObject <RCTURLRequestHandler, RCTTurboModule>
@end

@implementation RNPinVaultURLRequestHandler

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

// Native only: JS never requires this module.
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return nullptr;
}

- (BOOL)canHandleRequest:(NSURLRequest *)request
{
  return [RNPinVaultReactNetworking canHandle:request];
}

- (float)handlerPriority
{
  return 10;
}

- (id)sendRequest:(NSURLRequest *)request withDelegate:(id<RCTURLRequestDelegate>)delegate
{
  // RN does not retain the delegate; its RCTNetworkTask keeps itself alive until done.
  __weak id<RCTURLRequestDelegate> weakDelegate = delegate;
  __block __weak RNPinVaultReactNetworkingTask *weakToken = nil;
  RNPinVaultReactNetworkingTask *token = [RNPinVaultReactNetworking prepare:request
      didSendData:^(int64_t bytes) {
        RNPinVaultReactNetworkingTask *t = weakToken;
        if (t) [weakDelegate URLRequest:t didSendDataWithProgress:bytes];
      }
      didReceiveResponse:^(NSURLResponse *response) {
        RNPinVaultReactNetworkingTask *t = weakToken;
        if (t) [weakDelegate URLRequest:t didReceiveResponse:response];
      }
      didReceiveData:^(NSData *data) {
        RNPinVaultReactNetworkingTask *t = weakToken;
        if (t) [weakDelegate URLRequest:t didReceiveData:data];
      }
      didComplete:^(NSError *error) {
        RNPinVaultReactNetworkingTask *t = weakToken;
        if (t) [weakDelegate URLRequest:t didCompleteWithError:error];
      }];
  weakToken = token;
  // The token is returned before any callback can run (RN's rule): resume starts the request.
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    [token resume];
  });
  return token;
}

- (void)cancelRequest:(id)requestToken
{
  if ([requestToken isKindOfClass:[RNPinVaultReactNetworkingTask class]]) {
    [(RNPinVaultReactNetworkingTask *)requestToken cancel];
  }
}

@end
