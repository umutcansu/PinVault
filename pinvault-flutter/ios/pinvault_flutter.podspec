Pod::Spec.new do |s|
  s.name             = 'pinvault_flutter'
  s.version          = '2.4.0'
  s.summary          = 'PinVault Flutter Plugin.'
  s.description      = 'Dynamic certificate pinning, mTLS identity, and vault files for Flutter.'
  s.homepage         = 'https://github.com/umutcansu/PinVault'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Umut Cansu' => 'email@example.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '16.0'

  # Add dependency to the Swift Package
  s.dependency 'PinVault'
  
  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
