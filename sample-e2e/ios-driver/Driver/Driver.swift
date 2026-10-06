// sample-e2e iOS UI sürücüsü: XCUITest'in tek test yöntemi 127.0.0.1 üzerinde
// küçük bir HTTP sunucusu açar ve simctl ile başlatılmış uygulamaya (ya da
// SpringBoard'a) XCUIApplication(bundleIdentifier:) ile bağlanır. Uçlar JSON
// alır ve JSON döndürür; istemci sample-e2e/lib/iosDriver.js.
//
//   GET  /health                         → { ok, port, bundle, pid }
//   GET  /tree?bundle=                   → { screen, nodes: [{ id, label, value, placeholder, type, enabled, selected, focused, frame:[x1,y1,x2,y2], depth }] }
//   POST /tap {x, y, bundle?, duration?} → koordinata dokunur (nokta; uygulama penceresine göre)
//   POST /tapElement {id, bundle?, timeout?}      → erişilebilirlik kimliğiyle bulur, görünür olana kadar kaydırır, dokunur
//   POST /type {text, bundle?}                    → odaktaki alana yazar
//   POST /clearAndType {id, text, bundle?}        → alana dokunur, içeriği siler (hepsini seç + sil), yazar
//   POST /swipe {x1, y1, x2, y2, duration, bundle?}
//   POST /scrollTo {id, bundle?, timeout?}        → öğeyi dokunulabilir hale getirir (dokunmaz)
//   GET  /alerts                                  → SpringBoard'daki uyarı/sistem penceresi düğmeleri ve metinleri
//   POST /tapAlertButton {id | label, timeout?}   → SpringBoard'da (yoksa uygulamada) düğmeye dokunur
//   POST /pressHome, POST /activate {bundle?}
//   GET  /keyboard?bundle=  → { shown, frame }   POST /dismissKeyboard {bundle?} → { shown }
//   POST /stop                                    → sunucuyu kapatır (test yöntemi biter)
//
// Ortam (xcodebuild'e TEST_RUNNER_<AD> olarak verilir, burada <AD> görünür):
//   DRIVER_PORT (6870), DRIVER_BUNDLE (com.example.sampleclient),
//   DRIVER_WAIT_IDLE=1 → XCTest'in "uygulama boşta mı" beklemesi açık kalır
//   (varsayılan kapalı: harness ekranı kendisi yokluyor; uygulamada dönen bir
//   gösterge ya da harness'ın kendi süreçindeki vekile giden bir istek her
//   dokunuşu saniyelerce bekletiyordu).
//
// İstekler tek tek, ana iş parçacığında işlenir (XCUITest bunu ister). Bir
// XCTest hatası (öğe yok, kaydırılamadı…) testi bitirmez: record(_:) onu
// yakalar ve yanıta "error" olarak yazılır.
import Network
import XCTest

final class Driver: XCTestCase {
    /// Bir istek sırasında XCTest'in kaydettiği hatalar (yalnızca ana iş parçacığı).
    static var issues: [String] = []

    override func setUp() {
        super.setUp()
        continueAfterFailure = true
    }

    override func record(_ issue: XCTIssue) {
        // super çağrılmaz: sürücünün testi hiçbir zaman "başarısız" olmaz,
        // hata isteğin yanıtına girer.
        Driver.issues.append(issue.compactDescription)
    }

    func testServe() throws {
        let env = ProcessInfo.processInfo.environment
        let port = UInt16(env["DRIVER_PORT"] ?? "") ?? 6870
        Routes.defaultBundle = env["DRIVER_BUNDLE"].flatMap { $0.isEmpty ? nil : $0 } ?? "com.example.sampleclient"
        Routes.port = Int(port)
        if env["DRIVER_WAIT_IDLE"] != "1" { Quiescence.disable() }

        let done = expectation(description: "sürücü kapandı")
        let server = try Server(port: port) { done.fulfill() }
        server.start()
        NSLog("PinVaultDriver: 127.0.0.1:%d dinleniyor (uygulama %@)", Int(port), Routes.defaultBundle)
        wait(for: [done], timeout: 7 * 24 * 3600)
        server.cancel()
    }
}

// MARK: - XCTest'in boşta bekleme adımı

/// XCUIApplicationProcess'in "quiescence" beklemelerini boş bırakır
/// (WebDriverAgent'ın waitForQuiescence=false ayarıyla aynı yöntem). Seçici bu
/// Xcode'da yoksa hiçbir şey yapmaz.
enum Quiescence {
    static func disable() {
        guard let cls = NSClassFromString("XCUIApplicationProcess") else { return }
        let names = [
            "waitForQuiescenceIncludingAnimationsIdle:",
            "waitForQuiescenceIncludingAnimationsIdle:isPreEvent:",
            "waitForQuiescenceIncludingAnimationsIdle:usingActivity:isPreEvent:",
        ]
        // Bütün argümanları tamsayı/işaretçi olan, değer döndürmeyen yöntemler: boş blok.
        let noop: @convention(block) (UnsafeRawPointer?, Int, Int, Int) -> Void = { _, _, _, _ in }
        for name in names {
            guard let method = class_getInstanceMethod(cls, NSSelectorFromString(name)),
                  let encoding = method_getTypeEncoding(method) else { continue }
            let types = String(cString: encoding).filter { !$0.isNumber }
            // "v@:B", "v@:BB", "v@:B@B" — dönüş void, argümanlar BOOL/char/nesne.
            guard types.first == "v", types.dropFirst(3).allSatisfy({ "Bc@".contains($0) }) else { continue }
            method_setImplementation(method, imp_implementationWithBlock(noop))
        }
    }
}

// MARK: - HTTP

struct Request {
    let method: String
    let path: String
    let params: [String: Any]
}

final class Server {
    private let listener: NWListener
    private let netQueue = DispatchQueue(label: "pinvault.driver.net")
    /// Sıralı: aynı anda tek istek ana iş parçacığında.
    private let workQueue = DispatchQueue(label: "pinvault.driver.work")
    private let onStop: () -> Void

    init(port: UInt16, onStop: @escaping () -> Void) throws {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port)!)
        listener = try NWListener(using: params)
        self.onStop = onStop
    }

    func start() {
        listener.stateUpdateHandler = { [weak self] state in
            if case .failed(let error) = state {
                NSLog("PinVaultDriver: dinleyici düştü: %@", "\(error)")
                DispatchQueue.main.async { self?.onStop() }
            }
        }
        listener.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
        listener.start(queue: netQueue)
    }

    func cancel() { listener.cancel() }

    private final class Buffer { var data = Data() }

    private func accept(_ conn: NWConnection) {
        conn.start(queue: netQueue)
        let buffer = Buffer()
        func receive() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { [weak self] data, _, complete, error in
                guard let self = self else { conn.cancel(); return }
                if let data = data { buffer.data.append(data) }
                if let request = HTTP.parse(buffer.data) {
                    self.dispatch(request, conn)
                } else if complete || error != nil {
                    conn.cancel()
                } else {
                    receive()
                }
            }
        }
        receive()
    }

    private func dispatch(_ request: Request, _ conn: NWConnection) {
        workQueue.async {
            var status = 200
            var body: [String: Any] = [:]
            var stop = false
            DispatchQueue.main.sync {
                (status, body) = Routes.handle(request)
                stop = request.path == "/stop"
            }
            let response = HTTP.response(status: status, body: body)
            conn.send(content: response, completion: .contentProcessed { _ in
                conn.cancel()
                if stop { DispatchQueue.main.async { self.onStop() } }
            })
        }
    }
}

enum HTTP {
    /// Tam bir istek (başlıklar + Content-Length kadar gövde) geldiyse ayrıştırır.
    static func parse(_ data: Data) -> Request? {
        guard let headerEnd = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: data[data.startIndex..<headerEnd.lowerBound], as: UTF8.self)
        var lines = head.components(separatedBy: "\r\n")
        let first = lines.removeFirst().split(separator: " ")
        guard first.count >= 2 else { return Request(method: "GET", path: "/", params: [:]) }
        var length = 0
        for line in lines {
            let parts = line.split(separator: ":", maxSplits: 1)
            if parts.count == 2, parts[0].lowercased() == "content-length" {
                length = Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0
            }
        }
        let bodyStart = headerEnd.upperBound
        guard data.count - (bodyStart - data.startIndex) >= length else { return nil }
        let body = data[bodyStart..<(bodyStart + length)]

        var params: [String: Any] = [:]
        let target = String(first[1])
        let components = URLComponents(string: target)
        for item in components?.queryItems ?? [] { params[item.name] = item.value ?? "" }
        if !body.isEmpty, let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any] {
            for (key, value) in json { params[key] = value }
        }
        return Request(method: String(first[0]).uppercased(), path: components?.path ?? target, params: params)
    }

    static func response(status: Int, body: [String: Any]) -> Data {
        let json = (try? JSONSerialization.data(withJSONObject: body)) ?? Data("{}".utf8)
        let reason = status == 200 ? "OK" : status == 404 ? "Not Found" : status == 400 ? "Bad Request" : "Error"
        var out = Data("HTTP/1.1 \(status) \(reason)\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: \(json.count)\r\nConnection: close\r\n\r\n".utf8)
        out.append(json)
        return out
    }
}

// MARK: - Uçlar

struct DriverError: Error {
    let status: Int
    let message: String
    init(_ message: String, status: Int = 500) {
        self.message = message
        self.status = status
    }
}

enum Routes {
    static var defaultBundle = "com.example.sampleclient"
    static var port = 0
    static let springboard = "com.apple.springboard"

    static func handle(_ req: Request) -> (Int, [String: Any]) {
        Driver.issues.removeAll()
        do {
            var out = try route(req)
            if !Driver.issues.isEmpty {
                out["ok"] = false
                out["error"] = Driver.issues.joined(separator: "\n")
                return (500, out)
            }
            if out["ok"] == nil { out["ok"] = true }
            return (200, out)
        } catch let e as DriverError {
            return (e.status, ["ok": false, "error": e.message, "issues": Driver.issues])
        } catch {
            return (500, ["ok": false, "error": "\(error)", "issues": Driver.issues])
        }
    }

    static func route(_ req: Request) throws -> [String: Any] {
        let p = req.params
        let app = XCUIApplication(bundleIdentifier: string(p["bundle"]) ?? defaultBundle)
        switch req.path {
        case "/health":
            return ["port": port, "bundle": defaultBundle, "pid": Int(getpid())]
        case "/tree":
            return try tree(app)
        case "/tap":
            guard let x = number(p["x"]), let y = number(p["y"]) else { throw DriverError("x ve y gerekli", status: 400) }
            let point = app.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: x, dy: y))
            if let duration = number(p["duration"]), duration > 0 {
                point.press(forDuration: duration)
            } else {
                point.tap()
            }
            return [:]
        case "/tapElement":
            let element = try find(app, p)
            let scrolled = try scrollIntoView(element, app)
            let frame = tapCenter(element, app)
            return ["frame": rect(frame), "scrolled": scrolled]
        case "/scrollTo":
            let element = try find(app, p)
            let scrolled = try scrollIntoView(element, app)
            return ["frame": rect(element.frame), "scrolled": scrolled, "hittable": element.isHittable]
        case "/type":
            guard let text = string(p["text"]) else { throw DriverError("text gerekli", status: 400) }
            waitForKeyboardFocus(app, nil)
            app.typeText(text)
            return [:]
        case "/clearAndType":
            let element = try find(app, p)
            return try clearAndType(element, app, string(p["text"]) ?? "")
        case "/swipe":
            guard let x1 = number(p["x1"]), let y1 = number(p["y1"]), let x2 = number(p["x2"]), let y2 = number(p["y2"]) else {
                throw DriverError("x1, y1, x2, y2 gerekli", status: 400)
            }
            drag(app, from: CGPoint(x: x1, y: y1), to: CGPoint(x: x2, y: y2), seconds: (number(p["duration"]) ?? 300) / 1000)
            return [:]
        case "/alerts":
            return try alerts()
        case "/tapAlertButton":
            return try tapAlertButton(p, app)
        case "/pressHome":
            XCUIDevice.shared.press(.home)
            return [:]
        case "/activate":
            app.activate()
            return [:]
        case "/keyboard":
            let keyboard = app.keyboards.firstMatch
            let shown = keyboard.exists
            return ["shown": shown, "frame": shown ? rect(keyboard.frame) : NSNull()]
        case "/dismissKeyboard":
            return ["shown": dismissKeyboard(app)]
        case "/stop":
            return ["stopping": true]
        default:
            throw DriverError("bilinmeyen uç: \(req.method) \(req.path)", status: 404)
        }
    }

    // MARK: Ağaç

    static func tree(_ app: XCUIApplication) throws -> [String: Any] {
        let started = Date()
        let root = try app.snapshot()
        var nodes: [[String: Any]] = []
        func walk(_ s: XCUIElementSnapshot, _ depth: Int) {
            nodes.append([
                "id": s.identifier,
                "label": s.label,
                "value": text(s.value),
                "placeholder": s.placeholderValue ?? "",
                "title": s.title,
                "type": typeName(s.elementType),
                "enabled": s.isEnabled,
                "selected": s.isSelected,
                "focused": keyboardFocus(s),
                "frame": rect(s.frame),
                "depth": depth,
            ])
            if depth < 80 { s.children.forEach { walk($0, depth + 1) } }
        }
        walk(root, 0)
        return [
            "ms": Int(Date().timeIntervalSince(started) * 1000),
            "screen": ["width": Double(root.frame.width), "height": Double(root.frame.height)],
            "nodes": nodes,
        ]
    }

    /// Klavye odağı: XCElementSnapshot'ın hasKeyboardFocus özelliği (açık API'de yok;
    /// yoksa false).
    static func keyboardFocus(_ s: XCUIElementSnapshot) -> Bool {
        let object = s as AnyObject
        guard object.responds(to: NSSelectorFromString("hasKeyboardFocus")) else { return false }
        return (object.value(forKey: "hasKeyboardFocus") as? Bool) ?? false
    }

    // MARK: Öğe bulma ve kaydırma

    static func find(_ app: XCUIApplication, _ p: [String: Any]) throws -> XCUIElement {
        guard let id = string(p["id"]), !id.isEmpty else { throw DriverError("id gerekli", status: 400) }
        let timeout = (number(p["timeout"]) ?? 5000) / 1000
        let element = app.descendants(matching: .any).matching(NSPredicate(format: "identifier == %@", id)).firstMatch
        if !element.waitForExistence(timeout: timeout) {
            throw DriverError("öğe yok: \(id)", status: 404)
        }
        return element
    }

    /// Öğe dokunulabilir olana kadar ekranı yavaşça kaydırır. Ekran dışındaki
    /// SwiftUI öğeleri ağaçta durur ama dokunulamaz. Kaydırma yapıldıysa true.
    static func scrollIntoView(_ element: XCUIElement, _ app: XCUIApplication) throws -> Bool {
        var scrolled = false
        for _ in 0..<14 {
            if element.isHittable { return scrolled }
            let frame = element.frame
            let screen = app.frame
            if frame.isEmpty || screen.isEmpty { break }
            let keyboard = app.keyboards.firstMatch
            let keyboardTop = keyboard.exists ? keyboard.frame.minY : screen.maxY
            if keyboard.exists && frame.maxY > keyboardTop {
                // Klavyenin altında: önce klavye kapanır, sonra yeniden bakılır.
                if !dismissKeyboard(app) { return scrolled }
                continue
            }
            let visibleTop = screen.minY + screen.height * 0.12
            let visibleBottom = min(keyboardTop, screen.maxY - screen.height * 0.08)
            let x = screen.midX
            if frame.midY > visibleBottom {
                let distance = min(frame.midY - (visibleTop + visibleBottom) / 2, (visibleBottom - visibleTop) * 0.8)
                let start = visibleBottom - 10
                drag(app, from: CGPoint(x: x, y: start), to: CGPoint(x: x, y: start - max(distance, 60)), seconds: 0.5)
            } else if frame.midY < visibleTop {
                let distance = min((visibleTop + visibleBottom) / 2 - frame.midY, (visibleBottom - visibleTop) * 0.8)
                let start = visibleTop + 10
                drag(app, from: CGPoint(x: x, y: start), to: CGPoint(x: x, y: start + max(distance, 60)), seconds: 0.5)
            } else {
                // Görünür alanda ama dokunulamıyor (üstünde başka bir pencere ya da
                // devre dışı): kaydırma işe yaramaz.
                break
            }
            scrolled = true
        }
        if !element.isHittable {
            throw DriverError("öğe görünür hale getirilemedi: \(element.identifier) \(rect(element.frame))", status: 409)
        }
        return scrolled
    }

    /// Öğenin ortasına, o anki çerçevesinden hesaplanan koordinatla dokunur.
    /// element.tap() dokunuştan sonra öğeyi yeniden arıyor; dokunuşla kapanan
    /// bir sistem penceresinde (Face ID → Vazgeç) bu "öğe yok" hatası veriyordu.
    @discardableResult
    static func tapCenter(_ element: XCUIElement, _ app: XCUIApplication) -> CGRect {
        let frame = element.frame
        app.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: frame.midX, dy: frame.midY)).tap()
        return frame
    }

    /// Yavaş sürükleme: parmak sonda kısa süre bekler, içerik savrulmaz.
    static func drag(_ app: XCUIApplication, from: CGPoint, to: CGPoint, seconds: Double) {
        let origin = app.coordinate(withNormalizedOffset: .zero)
        let start = origin.withOffset(CGVector(dx: from.x, dy: from.y))
        let end = origin.withOffset(CGVector(dx: to.x, dy: to.y))
        let distance = hypot(to.x - from.x, to.y - from.y)
        let velocity = max(distance / CGFloat(max(seconds, 0.05)), 50)
        start.press(forDuration: 0.05, thenDragTo: end, withVelocity: XCUIGestureVelocity(rawValue: velocity), thenHoldForDuration: 0.15)
    }

    // MARK: Yazma

    static func waitForKeyboardFocus(_ app: XCUIApplication, _ element: XCUIElement?, timeout: Double = 3) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let element = element, let snapshot = try? element.snapshot(), keyboardFocus(snapshot) { return }
            if app.keyboards.firstMatch.exists { return }
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
    }

    /// Alanın metni; boş alanın yer tutucusu metin sayılmaz.
    static func fieldText(_ element: XCUIElement) -> String {
        let value = text(element.value)
        if let placeholder = element.placeholderValue, !placeholder.isEmpty, value == placeholder { return "" }
        return value
    }

    static func clearAndType(_ element: XCUIElement, _ app: XCUIApplication, _ newText: String) throws -> [String: Any] {
        _ = try scrollIntoView(element, app)
        tapCenter(element, app)
        waitForKeyboardFocus(app, element)
        var current = fieldText(element)
        if !current.isEmpty {
            // Hepsini seç + sil. Olmazsa imleç alanın sonuna alınıp tek tek silinir.
            app.typeKey("a", modifierFlags: .command)
            app.typeText(XCUIKeyboardKey.delete.rawValue)
            current = fieldText(element)
            var attempts = 0
            while !current.isEmpty && attempts < 3 {
                element.coordinate(withNormalizedOffset: CGVector(dx: 0.97, dy: 0.5)).tap()
                waitForKeyboardFocus(app, element, timeout: 1)
                app.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: current.count + 2))
                current = fieldText(element)
                attempts += 1
            }
            if !current.isEmpty { throw DriverError("alan boşaltılamadı: \(element.identifier) (kalan \(current.count) karakter)") }
        }
        if !newText.isEmpty { app.typeText(newText) }
        return ["value": fieldText(element)]
    }

    /// Klavyeyi kapatır; sonunda klavye hâlâ açıksa true.
    @discardableResult
    static func dismissKeyboard(_ app: XCUIApplication) -> Bool {
        let keyboard = app.keyboards.firstMatch
        if !keyboard.exists { return false }
        // 1. Uygulamanın klavye çubuğundaki "Bitti" düğmesi.
        let done = NSPredicate(format: "identifier == 'keyboardDoneButton' OR label IN {'Bitti', 'Done', 'Tamam'}")
        let toolbarButton = app.toolbars.buttons.matching(done).firstMatch
        if toolbarButton.exists && toolbarButton.isHittable {
            tapCenter(toolbarButton, app)
            if waitGone(keyboard) { return false }
        }
        // 2. Tek satırlık alanda Return düzenlemeyi bitirir (çok satırlıda satır ekler).
        let focused = focusedType(app)
        if focused == nil || ["textField", "secureTextField", "searchField"].contains(focused!) {
            app.typeText("\n")
            if waitGone(keyboard) { return false }
        }
        // 3. İçeriği yavaşça aşağı çekmek (scrollDismissesKeyboard).
        let screen = app.frame
        drag(app, from: CGPoint(x: screen.midX, y: screen.height * 0.3), to: CGPoint(x: screen.midX, y: screen.height * 0.55), seconds: 0.4)
        return !waitGone(keyboard)
    }

    static func waitGone(_ element: XCUIElement, timeout: Double = 1.5) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if !element.exists { return true }
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
        return !element.exists
    }

    /// Klavye odağındaki öğenin türü (biliniyorsa).
    static func focusedType(_ app: XCUIApplication) -> String? {
        guard let root = try? app.snapshot() else { return nil }
        var found: String?
        func walk(_ s: XCUIElementSnapshot) {
            if found != nil { return }
            if keyboardFocus(s) { found = typeName(s.elementType); return }
            s.children.forEach(walk)
        }
        walk(root)
        return found
    }

    // MARK: Sistem pencereleri (SpringBoard)

    static func alerts() throws -> [String: Any] {
        let root = try XCUIApplication(bundleIdentifier: springboard).snapshot()
        var buttons: [[String: Any]] = []
        var texts: [String] = []
        var alerts: [String] = []
        func walk(_ s: XCUIElementSnapshot) {
            switch s.elementType {
            case .button:
                buttons.append(["id": s.identifier, "label": s.label, "enabled": s.isEnabled, "frame": rect(s.frame)])
            case .staticText:
                if !s.label.isEmpty { texts.append(s.label) }
            case .alert, .sheet:
                alerts.append(s.label)
            default:
                break
            }
            s.children.forEach(walk)
        }
        walk(root)
        return ["buttons": buttons, "texts": texts, "alerts": alerts]
    }

    static func tapAlertButton(_ p: [String: Any], _ app: XCUIApplication) throws -> [String: Any] {
        let id = string(p["id"]) ?? ""
        let label = string(p["label"]) ?? ""
        if id.isEmpty && label.isEmpty { throw DriverError("id ya da label gerekli", status: 400) }
        let predicate = NSPredicate(format: "(identifier != '' AND identifier == %@) OR (label != '' AND label == %@)", id, label)
        let timeout = (number(p["timeout"]) ?? 5000) / 1000
        let deadline = Date().addingTimeInterval(timeout)
        let places: [(String, XCUIApplication)] = [(springboard, XCUIApplication(bundleIdentifier: springboard)), ("app", app)]
        repeat {
            for (name, target) in places {
                let button = target.buttons.matching(predicate).firstMatch
                if button.exists {
                    let label = button.label
                    tapCenter(button, target)
                    return ["where": name, "label": label]
                }
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
        } while Date() < deadline
        throw DriverError("sistem penceresinde düğme yok: \(id.isEmpty ? label : id)", status: 404)
    }

    // MARK: Yardımcılar

    static func string(_ v: Any?) -> String? {
        switch v {
        case let s as String: return s
        case let n as NSNumber: return n.stringValue
        default: return nil
        }
    }

    static func number(_ v: Any?) -> Double? {
        switch v {
        case let n as NSNumber: return n.doubleValue
        case let s as String: return Double(s)
        default: return nil
        }
    }

    static func text(_ v: Any?) -> String {
        switch v {
        case nil: return ""
        case let s as String: return s
        case let n as NSNumber: return n.stringValue
        case let other?: return "\(other)"
        }
    }

    static func rect(_ r: CGRect) -> [Double] {
        [Double(r.minX), Double(r.minY), Double(r.maxX), Double(r.maxY)]
    }

    static func typeName(_ t: XCUIElement.ElementType) -> String {
        switch t {
        case .any: return "any"
        case .other: return "other"
        case .application: return "application"
        case .group: return "group"
        case .window: return "window"
        case .sheet: return "sheet"
        case .alert: return "alert"
        case .dialog: return "dialog"
        case .button: return "button"
        case .radioButton: return "radioButton"
        case .radioGroup: return "radioGroup"
        case .checkBox: return "checkBox"
        case .popover: return "popover"
        case .keyboard: return "keyboard"
        case .key: return "key"
        case .navigationBar: return "navigationBar"
        case .tabBar: return "tabBar"
        case .toolbar: return "toolbar"
        case .statusBar: return "statusBar"
        case .table: return "table"
        case .cell: return "cell"
        case .collectionView: return "collectionView"
        case .slider: return "slider"
        case .pageIndicator: return "pageIndicator"
        case .progressIndicator: return "progressIndicator"
        case .activityIndicator: return "activityIndicator"
        case .segmentedControl: return "segmentedControl"
        case .picker: return "picker"
        case .pickerWheel: return "pickerWheel"
        case .switch: return "switch"
        case .toggle: return "toggle"
        case .link: return "link"
        case .image: return "image"
        case .icon: return "icon"
        case .searchField: return "searchField"
        case .scrollView: return "scrollView"
        case .scrollBar: return "scrollBar"
        case .staticText: return "staticText"
        case .textField: return "textField"
        case .secureTextField: return "secureTextField"
        case .datePicker: return "datePicker"
        case .textView: return "textView"
        case .menu: return "menu"
        case .menuItem: return "menuItem"
        case .webView: return "webView"
        case .stepper: return "stepper"
        case .tab: return "tab"
        default: return "type\(t.rawValue)"
        }
    }
}
