import UIKit
import React
import React_RCTAppDelegate
import ReactAppDependencyProvider
import RNPinVault

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?

  var reactNativeDelegate: ReactNativeDelegate?
  var reactNativeFactory: RCTReactNativeFactory?

  /// Uygulama arka plana geçerken ekranın üstüne konan bulanık katman: iOS'un
  /// uygulama değiştiricide gösterdiği anlık görüntüde kimlik ve vault içeriği
  /// görünmez (Android'deki FLAG_SECURE'un karşılığı).
  private var privacyCover: UIView?

  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    // PinVault'un periyodik config güncellemesi (BGTaskScheduler): açılışta, tek satır.
    _ = PinVaultBridge.registerBackgroundTask()

    let delegate = ReactNativeDelegate()
    let factory = RCTReactNativeFactory(delegate: delegate)
    delegate.dependencyProvider = RCTAppDependencyProvider()

    reactNativeDelegate = delegate
    reactNativeFactory = factory

    window = UIWindow(frame: UIScreen.main.bounds)

    factory.startReactNative(
      withModuleName: "SampleClientRN",
      in: window,
      launchOptions: launchOptions
    )

    return true
  }

  func applicationWillResignActive(_ application: UIApplication) {
    guard privacyCover == nil, let window else { return }
    let cover = UIVisualEffectView(effect: UIBlurEffect(style: .systemMaterial))
    cover.frame = window.bounds
    cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    window.addSubview(cover)
    privacyCover = cover
  }

  func applicationDidBecomeActive(_ application: UIApplication) {
    privacyCover?.removeFromSuperview()
    privacyCover = nil
  }
}

class ReactNativeDelegate: RCTDefaultReactNativeFactoryDelegate {
  override func sourceURL(for bridge: RCTBridge) -> URL? {
    self.bundleURL()
  }

  override func bundleURL() -> URL? {
#if DEBUG
    RCTBundleURLProvider.sharedSettings().jsBundleURL(forBundleRoot: "index")
#else
    Bundle.main.url(forResource: "main", withExtension: "jsbundle")
#endif
  }
}
