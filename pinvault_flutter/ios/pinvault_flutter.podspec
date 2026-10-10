Pod::Spec.new do |s|
  s.name             = 'pinvault_flutter'
  s.version          = '2.4.0'
  s.summary          = 'PinVault Flutter Plugin.'
  s.description      = 'Dynamic certificate pinning, mTLS identity, and vault files for Flutter.'
  s.homepage         = 'https://github.com/umutcansu/PinVault'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Umut Cansu' => 'email@example.com' }
  s.source           = { :path => '.' }
  s.source_files = 'pinvault_flutter/Sources/pinvault_flutter/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '16.0'

  # PinVault for iOS is a Swift package (Package.swift at the repository root,
  # product "PinVault"), not a CocoaPod. The app must link it one of two ways:
  #   - Flutter's Swift Package Manager support (Flutter 3.24+): enable SPM in
  #     the Runner project and add the PinVault package (git URL at the tag of
  #     this plugin's version, or the local checkout at ../..).
  #   - `cocoapods-spm`: `plugin 'cocoapods-spm'` in the Podfile, then
  #       spm_dependency(self, url: 'https://github.com/umutcansu/PinVault.git',
  #                      requirement: { kind: 'exactVersion', version: version },
  #                      products: ['PinVault'])
  # The Swift side imports `PinVault` (see Classes/SwiftPinVaultFlutterPlugin.swift).
  s.dependency 'PinVault'
  
  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
