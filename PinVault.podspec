# PinVault for iOS as a CocoaPod, so a Flutter/RN plugin can `s.dependency 'PinVault'`.
#
# The canonical distribution is the Swift package (Package.swift at this root,
# product "PinVault"); this podspec compiles the same sources for the CocoaPods
# toolchain. For a local checkout, the app's Podfile adds
#   pod 'PinVault', :path => '<checkout>'   # this directory
# A published flow would point `s.source` at the git tag instead.
Pod::Spec.new do |s|
  s.name             = 'PinVault'
  s.version          = '2.4.2'
  s.summary          = 'Dynamic certificate pinning, mTLS identity, and vault files for iOS.'
  s.description      = 'PinVault for iOS: remote signed pin configs, mTLS enrollment, signed vault files, device attestation.'
  s.homepage         = 'https://github.com/umutcansu/PinVault'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Umut Cansu' => 'umutcansu@gmail.com' }
  s.source           = { :path => '.' }

  s.platform         = :ios, '16.0'
  s.source_files     = 'pinvault-ios/Sources/PinVault/**/*.swift'
  s.swift_version    = '6.0'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
