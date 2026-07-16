require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "hathor-ct-crypto-mobile"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = "https://github.com/HathorNetwork/hathor-ct-crypto"
  s.license      = package["license"]
  s.authors      = "Hathor Labs"
  s.platforms    = { :ios => "13.0" }
  s.source       = { :git => "https://github.com/HathorNetwork/hathor-ct-crypto.git", :tag => "v#{s.version}" }

  # The RN bridge module + the UniFFI-generated Swift API. The compiled Rust
  # core arrives as a vendored XCFramework (built by CI, shipped in the npm
  # tarball — not present in a plain git checkout).
  s.source_files = "ios/**/*.{swift,m}"
  s.vendored_frameworks = "ios/HathorCtCrypto.xcframework"
  s.swift_version = "5.0"

  s.dependency "React-Core"
end
