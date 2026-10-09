// RNPinVaultWebSocketPinning — React Native's WebSocket (SocketRocket) through
// PinVault's pins on iOS. See RNPinVaultWebSocketPinning.mm.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface RNPinVaultWebSocketPinning : NSObject

/// Installs the hook when it is not in place yet (it is installed at load;
/// this covers a SocketRocket image loaded later). NO when it cannot be:
/// Info.plist opt-out, no SocketRocket initializer of the known shape.
+ (BOOL)install;

/// Whether every SocketRocket socket to a `wss` / `https` URL is judged by
/// PinVault right now: the hook is installed and still the initializer's
/// implementation (nothing replaced it since). YES without SocketRocket in the app.
+ (BOOL)isPinned;

@end

NS_ASSUME_NONNULL_END
