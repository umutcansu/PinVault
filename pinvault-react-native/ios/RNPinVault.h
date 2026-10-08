// RNPinVault — the ObjC++ shell of the TurboModule. It conforms to the
// codegen protocol and forwards every call to the Swift bridge
// (PinVaultBridge.swift), which calls PinVault.shared.
#import <RNPinVaultSpec/RNPinVaultSpec.h>

@interface RNPinVault : NativePinVaultSpecBase <NativePinVaultSpec>
@end
