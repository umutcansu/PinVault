require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

# PinVault for iOS is a Swift package (Package.swift at the repository root,
# product "PinVault"). React Native's spm_dependency adds it to the Pods project:
#   - consumers: the git URL at the tag of this package's version (v2.3.2);
#   - development: PINVAULT_IOS_PACKAGE_PATH = a PinVault checkout (the sample's
#     Podfile sets it to this repository), the counterpart of pinvault.localPath.
pinvault_url = "https://github.com/umutcansu/PinVault.git"
local_package = ENV["PINVAULT_IOS_PACKAGE_PATH"].to_s.strip

Pod::Spec.new do |s|
  s.name         = "RNPinVault"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "16.0" }
  s.source       = { :git => pinvault_url, :tag => "v#{s.version}" }
  s.source_files = "ios/*.{h,mm,swift}", "ios/Core/*.swift"
  s.private_header_files = "ios/*.h"
  s.swift_version = "5.9"

  if local_package.empty?
    spm_dependency(s,
      url: pinvault_url,
      requirement: { kind: "exactVersion", version: s.version.to_s },
      products: ["PinVault"]
    )
  else
    path = File.expand_path(local_package)
    unless File.exist?(File.join(path, "Package.swift"))
      raise "PINVAULT_IOS_PACKAGE_PATH=#{local_package}: no Package.swift there (a PinVault checkout is expected)"
    end
    Pod::UI.puts "[RNPinVault] PinVault Swift package from #{path}"
    spm_dependency(s, url: path, requirement: {}, products: ["PinVault"])
  end

  install_modules_dependencies(s)
end
