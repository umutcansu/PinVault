# PinVault for iOS as a CocoaPod, so a Flutter/RN plugin can `s.dependency 'PinVault'`.
#
# The canonical distribution is the Swift package (Package.swift at this root,
# product "PinVault"); this podspec compiles the same sources for the CocoaPods
# toolchain. It is not on CocoaPods trunk; an app's Podfile names it:
#   pod 'PinVault', :git => 'https://github.com/umutcansu/PinVault.git', :tag => 'v<this version>'
# or, for a local checkout,
#   pod 'PinVault', :path => '<checkout>'   # this directory
# (`:git` / `:path` in the Podfile take the place of `s.source`).
Pod::Spec.new do |s|
  s.name             = 'PinVault'
  s.version          = '2.5.1'
  s.summary          = 'Dynamic certificate pinning, mTLS identity, and vault files for iOS.'
  s.description      = 'PinVault for iOS: remote signed pin configs, mTLS enrollment, signed vault files, device attestation.'
  s.homepage         = 'https://github.com/umutcansu/PinVault'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Umut Cansu' => 'umutcansu@gmail.com' }
  s.source           = { :git => 'https://github.com/umutcansu/PinVault.git', :tag => "v#{s.version}" }

  s.platform         = :ios, '16.0'
  s.source_files     = 'pinvault-ios/Sources/PinVault/**/*.swift'
  s.swift_version    = '6.0'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
