#import "RNPinVault.h"

#import <objc/message.h>
#import <React/RCTBridgeModule.h>

#import "RNPinVaultWebSocketPinning.h"

#if __has_include(<RNPinVault/RNPinVault-Swift.h>)
#import <RNPinVault/RNPinVault-Swift.h>
#else
#import "RNPinVault-Swift.h"
#endif

@implementation RNPinVault {
  RNPinVaultBridge *_bridge;
}

@synthesize moduleRegistry = _moduleRegistry;

+ (NSString *)moduleName
{
  return @"RNPinVault";
}

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

- (instancetype)init
{
  if (self = [super init]) {
    _bridge = [RNPinVaultBridge new];
    __weak RNPinVault *weakSelf = self;
    _bridge.emitConnectionEvent = ^(NSDictionary<NSString *, id> *event) {
      [weakSelf emitOnConnectionEvent:event];
    };
    _bridge.emitGuardRequest = ^(NSDictionary<NSString *, id> *request) {
      [weakSelf emitOnGuardRequest:request];
    };
    // Which RCTURLRequestHandler RCTNetworking picks for an https request
    // (its private handlerForRequest:, the method it sends every request through).
    _bridge.reactNetworkingIsPinned = ^NSNumber *_Nullable {
      RNPinVault *strongSelf = weakSelf;
      RCTModuleRegistry *registry = strongSelf ? strongSelf->_moduleRegistry : nil;
      id networking = [registry moduleForName:"Networking"];
      SEL selector = NSSelectorFromString(@"handlerForRequest:");
      Class ours = NSClassFromString(@"RNPinVaultURLRequestHandler");
      if (networking == nil || ours == nil || ![networking respondsToSelector:selector]) {
        return nil;
      }
      NSURLRequest *probe = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://pinvault.invalid/"]];
      id handler = ((id(*)(id, SEL, NSURLRequest *))objc_msgSend)(networking, selector, probe);
      return @([handler isKindOfClass:ours]);
    };
    // Whether SocketRocket's initializer still hands every wss socket to PinVault.
    _bridge.reactWebSocketIsPinned = ^BOOL {
      return [RNPinVaultWebSocketPinning isPinned];
    };
  }
  return self;
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativePinVaultSpecJSI>(params);
}

// Swift answers with plain blocks; the JS side reads code, message and userInfo.
static void (^Resolver(RCTPromiseResolveBlock resolve))(id)
{
  return ^(id value) { resolve(value); };
}

static void (^Rejecter(RCTPromiseRejectBlock reject))(NSString *, NSString *, NSDictionary<NSString *, id> *)
{
  return ^(NSString *code, NSString *message, NSDictionary<NSString *, id> *info) {
    NSError *error = info ? [NSError errorWithDomain:@"PinVault" code:0 userInfo:info] : nil;
    reject(code, message, error);
  };
}

#define R Resolver(resolve)
#define J Rejecter(reject)

- (void)start:(NSString *)configJson resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge start:configJson resolve:R reject:J];
}

- (void)updateNow:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge updateNowWithResolve:R reject:J];
}

- (void)currentVersion:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge currentVersionWithResolve:R reject:J];
}

- (void)hostPinVersions:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge hostPinVersionsWithResolve:R reject:J];
}

- (void)pinsForHost:(NSString *)hostname resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge pinsForHost:hostname resolve:R reject:J];
}

- (void)signingStatus:(NSString *)configApiId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge signingStatus:configApiId resolve:R reject:J];
}

- (void)isForceUpdate:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge isForceUpdateWithResolve:R reject:J];
}

- (void)reset:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge resetWithResolve:R reject:J];
}

- (void)schedulePeriodicUpdates:(NSNumber *)intervalHours
                        resolve:(RCTPromiseResolveBlock)resolve
                         reject:(RCTPromiseRejectBlock)reject
{
  [_bridge schedulePeriodicUpdates:intervalHours resolve:R reject:J];
}

- (void)cancelPeriodicUpdates:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge cancelPeriodicUpdatesWithResolve:R reject:J];
}

- (void)enableDebugLogging:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge enableDebugLoggingWithResolve:R reject:J];
}

- (void)fetch:(NSString *)requestJson resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge fetch:requestJson resolve:R reject:J];
}

- (void)deviceId:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge deviceIdWithResolve:R reject:J];
}

- (void)enrollForResult:(NSString *)token
                  label:(NSString *)label
                resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject
{
  [_bridge enrollForResult:token label:label resolve:R reject:J];
}

- (void)autoEnrollForResult:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge autoEnrollForResultWithResolve:R reject:J];
}

- (void)checkPendingEnrollment:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge checkPendingEnrollmentWithResolve:R reject:J];
}

- (void)isEnrolled:(NSString *)label resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge isEnrolled:label resolve:R reject:J];
}

- (void)isEnrollmentPending:(NSString *)label resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge isEnrollmentPending:label resolve:R reject:J];
}

- (void)enrollmentVerificationCode:(NSString *)label
                           resolve:(RCTPromiseResolveBlock)resolve
                            reject:(RCTPromiseRejectBlock)reject
{
  [_bridge enrollmentVerificationCode:label resolve:R reject:J];
}

- (void)enrolledClientCN:(NSString *)label resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge enrolledClientCN:label resolve:R reject:J];
}

- (void)enrolledClientNotAfter:(NSString *)label resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge enrolledClientNotAfter:label resolve:R reject:J];
}

- (void)unenroll:(NSString *)label
  wipeVaultFiles:(BOOL)wipeVaultFiles
         resolve:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject
{
  [_bridge unenroll:label wipeVaultFiles:wipeVaultFiles resolve:R reject:J];
}

- (void)identityKeySecurityLevel:(NSString *)label resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge identityKeySecurityLevel:label resolve:R reject:J];
}

- (void)setVaultToken:(NSString *)key
                token:(NSString *)token
              resolve:(RCTPromiseResolveBlock)resolve
               reject:(RCTPromiseRejectBlock)reject
{
  [_bridge setVaultToken:key token:token resolve:R reject:J];
}

- (void)clearVaultTokens:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge clearVaultTokensWithResolve:R reject:J];
}

- (void)fetchFile:(NSString *)key
            token:(NSString *)token
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  [_bridge fetchFile:key token:token resolve:R reject:J];
}

- (void)loadFile:(NSString *)key
        encoding:(NSString *)encoding
         resolve:(RCTPromiseResolveBlock)resolve
          reject:(RCTPromiseRejectBlock)reject
{
  [_bridge loadFile:key encoding:encoding resolve:R reject:J];
}

- (void)fileStatus:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge fileStatus:key resolve:R reject:J];
}

- (void)unlockFile:(NSString *)key
        promptJson:(NSString *)promptJson
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject
{
  [_bridge unlockFile:key prompt:promptJson resolve:R reject:J];
}

- (void)isFileLocked:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge isFileLocked:key resolve:R reject:J];
}

- (void)hasFile:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge hasFile:key resolve:R reject:J];
}

- (void)fileVersion:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge fileVersion:key resolve:R reject:J];
}

- (void)clearFile:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge clearFile:key resolve:R reject:J];
}

- (void)syncAllFiles:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge syncAllFilesWithResolve:R reject:J];
}

- (void)attestNow:(NSString *)configApiId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge attestNow:configApiId resolve:R reject:J];
}

- (void)fetchAttestationToken:(NSString *)host resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge fetchAttestationToken:host resolve:R reject:J];
}

- (void)attestationStatus:(NSString *)configApiId resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [_bridge attestationStatus:configApiId resolve:R reject:J];
}

- (void)answerGuard:(NSString *)requestId allowed:(BOOL)allowed
{
  [_bridge answerGuard:requestId allowed:allowed];
}

@end
