// RNPinVaultWebSocketPinning — React Native's WebSocket through PinVault's
// pins on iOS.
//
// RCTWebSocketModule opens every socket with SocketRocket (SRWebSocket on
// CFStream), outside URLSession, so the URLRequestHandler never sees it. Every
// SRWebSocket initializer ends in -initWithURLRequest:protocols:securityPolicy:
// (SocketRocket 0.7.x, SRWebSocket.m). This file replaces that method at load:
// a socket to a wss / https URL (SocketRocket's SRURLRequiresSSL) always gets a
// policy that asks PinVault, whatever policy its creator passed.
//
// RCTSetCustomSRWebSocketProvider is not used: its block gets only the
// request, so the subprotocols RN hands the initializer (graphql-ws, MQTT,
// STOMP) would be lost, and a provider set later by another library would
// replace ours without a trace.
//
// SocketRocket checks the server trust in -stream:handleEvent: before it
// writes the upgrade request: a refused chain sends no header and no cookie.
//
// The policy is a runtime subclass of SRSecurityPolicy, so the plugin needs
// neither SocketRocket's headers nor a link to it: no chain validation in the
// stream (pins replace CA trust, as in every PinVault session), the TLS 1.2
// floor of SocketRocket's default, and -evaluateServerTrust:forDomain: →
// PinVault for the host and port of the socket's own URL.
#import "RNPinVaultWebSocketPinning.h"

#import <Security/Security.h>
#import <objc/runtime.h>
#import <os/lock.h>

#if __has_include(<RNPinVault/RNPinVault-Swift.h>)
#import <RNPinVault/RNPinVault-Swift.h>
#else
#import "RNPinVault-Swift.h"
#endif

typedef id (*RNPVSocketInit)(id, SEL, NSURLRequest *, NSArray *, id);

static os_unfair_lock gLock = OS_UNFAIR_LOCK_INIT;
static RNPVSocketInit gOriginalInit = NULL;
static Class gPolicyClass = Nil;
static char kHostKey;
static char kPortKey;

static NSString *const kSocketClass = @"SRWebSocket";
static NSString *const kPolicyClass = @"SRSecurityPolicy";
static NSString *const kInitSelector = @"initWithURLRequest:protocols:securityPolicy:";
static NSString *const kUpdateSelector = @"updateSecurityOptionsInStream:";
static NSString *const kEvaluateSelector = @"evaluateServerTrust:forDomain:";

// SocketRocket's SRURLRequiresSSL.
static BOOL RequiresTLS(NSURL *url)
{
  NSString *scheme = url.scheme.lowercaseString;
  return [scheme isEqualToString:@"wss"] || [scheme isEqualToString:@"https"];
}

static void PinnedUpdateSecurityOptions(id self, SEL _cmd, NSStream *stream)
{
  [stream setProperty:(__bridge id)CFSTR("kCFStreamSocketSecurityLevelTLSv1_2")
               forKey:(__bridge NSString *)kCFStreamPropertySocketSecurityLevel];
  [stream setProperty:@{(__bridge NSString *)kCFStreamSSLValidatesCertificateChain : @NO}
               forKey:(__bridge NSString *)kCFStreamPropertySSLSettings];
}

static BOOL PinnedEvaluateServerTrust(id self, SEL _cmd, SecTrustRef trust, NSString *domain)
{
  NSString *host = objc_getAssociatedObject(self, &kHostKey);
  NSNumber *port = objc_getAssociatedObject(self, &kPortKey);
  if (trust == NULL || host.length == 0 || port == nil) {
    return NO;
  }
  return [RNPinVaultReactNetworking acceptsWebSocketTrust:trust host:host port:port.integerValue];
}

// The policy class, made once; Nil when SocketRocket's is missing or has another shape.
static Class PolicyClass(void)
{
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    Class base = NSClassFromString(kPolicyClass);
    SEL update = NSSelectorFromString(kUpdateSelector);
    SEL evaluate = NSSelectorFromString(kEvaluateSelector);
    Method baseUpdate = base ? class_getInstanceMethod(base, update) : NULL;
    Method baseEvaluate = base ? class_getInstanceMethod(base, evaluate) : NULL;
    if (baseUpdate == NULL || baseEvaluate == NULL) {
      return;
    }
    Class sub = objc_allocateClassPair(base, "RNPinVaultSRSecurityPolicy", 0);
    if (sub == Nil) {
      return;
    }
    class_addMethod(sub, update, (IMP)PinnedUpdateSecurityOptions, method_getTypeEncoding(baseUpdate));
    class_addMethod(sub, evaluate, (IMP)PinnedEvaluateServerTrust, method_getTypeEncoding(baseEvaluate));
    objc_registerClassPair(sub);
    gPolicyClass = sub;
  });
  return gPolicyClass;
}

// A policy for one socket: the host and port SocketRocket connects to (port 0 → 443, as SRProxyConnect).
static id PolicyFor(NSURL *url)
{
  Class cls = PolicyClass();
  if (cls == Nil) {
    return nil; // SocketRocket asks nil, which answers NO: refused.
  }
  id policy = [[cls alloc] init];
  NSUInteger port = url.port.unsignedIntValue;
  objc_setAssociatedObject(policy, &kHostKey, url.host, OBJC_ASSOCIATION_COPY_NONATOMIC);
  objc_setAssociatedObject(policy, &kPortKey, @(port == 0 ? 443 : port), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  return policy;
}

static id PinnedInit(id self, SEL _cmd, NSURLRequest *request, NSArray *protocols, id securityPolicy)
{
  if (RequiresTLS(request.URL)) {
    securityPolicy = PolicyFor(request.URL);
  }
  return gOriginalInit(self, _cmd, request, protocols, securityPolicy);
}

static Method SocketInit(void)
{
  Class socket = NSClassFromString(kSocketClass);
  return socket ? class_getInstanceMethod(socket, NSSelectorFromString(kInitSelector)) : NULL;
}

// Info.plist PinVaultPinReactNativeNetworking = NO: the native opt-out of the https handler covers this too.
static BOOL Enabled(void)
{
  id value = [NSBundle.mainBundle objectForInfoDictionaryKey:@"PinVaultPinReactNativeNetworking"];
  return ![value respondsToSelector:@selector(boolValue)] || [value boolValue];
}

@implementation RNPinVaultWebSocketPinning

+ (void)load
{
  [self install];
}

+ (BOOL)install
{
  if (!Enabled()) {
    return NO;
  }
  os_unfair_lock_lock(&gLock);
  BOOL installed = NO;
  Method method = SocketInit();
  if (method != NULL && gOriginalInit != NULL) {
    installed = method_getImplementation(method) == (IMP)PinnedInit;
  } else if (method != NULL && PolicyClass() != Nil &&
             strcmp(method_getTypeEncoding(method) ?: "", "@40@0:8@16@24@32") == 0) {
    gOriginalInit = (RNPVSocketInit)method_getImplementation(method);
    method_setImplementation(method, (IMP)PinnedInit);
    installed = YES;
  }
  os_unfair_lock_unlock(&gLock);
  return installed;
}

+ (BOOL)isPinned
{
  if (NSClassFromString(kSocketClass) == Nil) {
    return YES; // No SocketRocket: React Native has no WebSocket to pin.
  }
  return [self install];
}

@end
