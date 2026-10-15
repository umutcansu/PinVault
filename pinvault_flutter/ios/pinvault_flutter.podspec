Pod::Spec.new do |s|
  s.name             = 'pinvault_flutter'
  s.version          = '2.8.1'
  s.summary          = 'PinVault Flutter Plugin.'
  s.description      = 'Dynamic certificate pinning, mTLS identity, and vault files for Flutter.'
  s.homepage         = 'https://github.com/umutcansu/PinVault'
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = { 'Umut Cansu' => 'umutcansu@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files = 'pinvault_flutter/Sources/pinvault_flutter/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '16.0'

  # The native PinVault library. With Flutter's Swift Package Manager support
  # (the default) the plugin's Package.swift (pinvault_flutter/Package.swift)
  # brings it from the PinVault git tag. With CocoaPods, PinVault is the pod of
  # the repository root's PinVault.podspec; it is not on CocoaPods trunk, so
  # the app's Podfile names it:
  #   pod 'PinVault', :git => 'https://github.com/umutcansu/PinVault.git', :tag => 'v2.8.1'
  # (or `:path => '<checkout>'` for a local checkout, as the example does).
  # 2.6.0: PinnedSession.makeWebSocketTask(for:), which the pinned WebSocket calls.
  # 2.6.1: without tokenHosts only the Config API carries the token.
  s.dependency 'PinVault', '>= 2.6.1'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
