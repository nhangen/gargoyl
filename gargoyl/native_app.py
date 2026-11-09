"""Build source for an unprivileged native macOS operator shell; no action at import."""

SWIFT = r"""
import AppKit
import WebKit
import LocalAuthentication
import SystemConfiguration
import Security

// Traditional local login keychain. Never uses a shared Python trust identity,
// access groups, synchronization, data-protection entitlements or widened ACLs.
struct SavedFleetCredential: CustomStringConvertible {
    let token:String
    let recordID:String
    init(token:String,created:Double,expires:Double,recordID:String=UUID().uuidString.lowercased()) { self.token=token; self.created=created; self.expires=expires; self.recordID=recordID }
    let created:Double
    let expires:Double
    var description:String { return "<private read-only account session>" }
    static func tokenValid(_ token:String) -> Bool { token.range(of:"^darkbloom-at-[A-Za-z0-9._~-]{8,2048}$",options:.regularExpression) != nil }
    func encoded() -> Data? {
        return try? JSONSerialization.data(withJSONObject:["schema":1,"purpose":"desktop_account","token":token,"created":created,"expires":expires,"record_id":recordID])
    }
    static func decode(_ data:Data, now:Double) -> SavedFleetCredential? {
        guard data.count <= 4096, let value=(try? JSONSerialization.jsonObject(with:data)) as? [String:Any],
              Set(value.keys) == Set(["schema","purpose","token","created","expires","record_id"]),
              let schema=value["schema"] as? NSNumber, CFGetTypeID(schema) != CFBooleanGetTypeID(), schema.doubleValue == 1,
              value["purpose"] as? String == "desktop_account", let token=value["token"] as? String, tokenValid(token),
              let recordID=value["record_id"] as? String, let uuid=UUID(uuidString:recordID), uuid.uuidString.lowercased() == recordID,
              let c=value["created"] as? NSNumber, CFGetTypeID(c) != CFBooleanGetTypeID(),
              let x=value["expires"] as? NSNumber, CFGetTypeID(x) != CFBooleanGetTypeID() else { return nil }
        guard let encoded=String(data:data,encoding:.utf8) else { return nil }
        for key in ["schema","purpose","token","created","expires","record_id"] {
            let pattern="\"" + key + "\"\\s*:"
            guard let regex=try? NSRegularExpression(pattern:pattern), regex.numberOfMatches(in:encoded,range:NSRange(encoded.startIndex...,in:encoded)) == 1 else { return nil }
        }
        let created=c.doubleValue, expires=x.doubleValue
        guard now.isFinite, created.isFinite, expires.isFinite, created > 0, created <= now,
              expires > created, expires - created <= 30 * 86400 else { return nil }
        return SavedFleetCredential(token:token,created:created,expires:expires,recordID:recordID)
    }
}
struct FleetCredentialGate {
    var consumed=false
    mutating func take(_ value:[String:Any], mode:String, remember:Bool, owner:Bool, generation:Int, current:Int) -> String? {
        guard !consumed, mode == "fleet-session-remember", remember, owner, generation == current,
              Set(value.keys) == Set(["kind","purpose","token"]), value["kind"] as? String == "fleet-credential",
              value["purpose"] as? String == "desktop_account", let token=value["token"] as? String, SavedFleetCredential.tokenValid(token) else { return nil }
        consumed=true; return token
    }
}
final class FleetSavedSessionState {
    var credential:SavedFleetCredential?
    var revoked=false
    var stored=false
}
enum FleetRemovalRequest { case all; case matching(SavedFleetCredential) }
final class LoginFleetCredentialStore {
    static let service="dev.gargoyl.read-only-fleet"
    static let account="desktop_account"
    let open:()->(OSStatus,AnyObject?)
    let copy:(CFDictionary)->(OSStatus,CFTypeRef?)
    let add:(CFDictionary)->OSStatus
    let update:(CFDictionary,CFDictionary)->OSStatus
    let delete:(CFDictionary)->OSStatus
    #if GARGOYL_NATIVE_TESTS
    // Test builds must never reach the real Keychain, whatever HOME, preferences or callbacks say.
    init(open:@escaping ()->(OSStatus,AnyObject?) = LoginFleetCredentialStore.openLogin,
         copy:@escaping (CFDictionary)->(OSStatus,CFTypeRef?) = { _ in (errSecNotAvailable,nil) },
         add:@escaping (CFDictionary)->OSStatus = { _ in errSecNotAvailable },
         update:@escaping (CFDictionary,CFDictionary)->OSStatus = { _,_ in errSecNotAvailable },
         delete:@escaping (CFDictionary)->OSStatus = { _ in errSecNotAvailable }) {
        self.open=open; self.copy=copy; self.add=add; self.update=update; self.delete=delete
    }
    #else
    init(open:@escaping ()->(OSStatus,AnyObject?) = LoginFleetCredentialStore.openLogin,
         copy:@escaping (CFDictionary)->(OSStatus,CFTypeRef?) = { query in var out:CFTypeRef?; let status=SecItemCopyMatching(query,&out); return (status,out) },
         add:@escaping (CFDictionary)->OSStatus = { SecItemAdd($0,nil) },
         update:@escaping (CFDictionary,CFDictionary)->OSStatus = { SecItemUpdate($0,$1) },
         delete:@escaping (CFDictionary)->OSStatus = { SecItemDelete($0) }) {
        self.open=open; self.copy=copy; self.add=add; self.update=update; self.delete=delete
    }
    #endif
    static func trustedLoginMetadata(fileOwner:Int, mode:Int, regular:Bool, parentOwner:Int, parentMode:Int, uid:Int)->Bool {
        // The OS-managed file is encrypted; read bits are not a plaintext-secret
        // boundary. Never chmod it. Refuse untrusted ownership or writable paths.
        return regular && fileOwner == uid && parentOwner == uid && mode & 0o022 == 0 && parentMode & 0o022 == 0
    }
    static func openLogin()->(OSStatus,AnyObject?) {
        #if GARGOYL_NATIVE_TESTS
        return (errSecNotAvailable,nil)
        #else
        let path=NSHomeDirectory()+"/Library/Keychains/login.keychain-db"
        let url=URL(fileURLWithPath:path)
        guard url.resolvingSymlinksInPath().path == path,
              let attrs=try? FileManager.default.attributesOfItem(atPath:path),
              let parent=try? FileManager.default.attributesOfItem(atPath:url.deletingLastPathComponent().path),
              let owner=attrs[.ownerAccountID] as? NSNumber, let mode=attrs[.posixPermissions] as? NSNumber,
              let parentOwner=parent[.ownerAccountID] as? NSNumber, let parentMode=parent[.posixPermissions] as? NSNumber,
              Self.trustedLoginMetadata(fileOwner:owner.intValue,mode:mode.intValue,regular:attrs[.type] as? FileAttributeType == .typeRegular,parentOwner:parentOwner.intValue,parentMode:parentMode.intValue,uid:Int(getuid()))
        else { return (errSecNotAvailable,nil) }
        var keychain:SecKeychain?
        let status=SecKeychainOpen(path,&keychain)
        return (status,keychain)
        #endif
    }
    static func query(_ keychain:AnyObject)->[String:Any] {
        return [kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:service,kSecAttrAccount as String:account,kSecMatchSearchList as String:[keychain],kSecMatchLimit as String:kSecMatchLimitOne]
    }
    func read()->(OSStatus,Data?) {
        let (opened,keychain)=open(); guard opened == errSecSuccess, let keychain=keychain else { return (opened,nil) }
        var query=Self.query(keychain); query[kSecReturnData as String]=true
        let (status,value)=copy(query as CFDictionary)
        guard status == errSecSuccess, let data=value as? Data, data.count <= 4096 else { return (status == errSecSuccess ? errSecDecode : status,nil) }
        return (status,data)
    }
    func save(_ data:Data)->OSStatus {
        guard data.count <= 4096, let credential=SavedFleetCredential.decode(data,now:Date().timeIntervalSince1970) else { return errSecParam }
        let (opened,keychain)=open(); guard opened == errSecSuccess, let keychain=keychain else { return opened }
        var query:[String:Any]=[kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:Self.service,kSecAttrAccount as String:Self.account,kSecUseKeychain as String:keychain,kSecValueData as String:data,kSecAttrGeneric as String:Data(credential.recordID.utf8)]
        let added=add(query as CFDictionary)
        guard added == errSecDuplicateItem else { return added }
        query=Self.query(keychain); query[kSecReturnRef as String]=true
        let (found,item)=copy(query as CFDictionary); guard found == errSecSuccess, let item=item else { return found }
        return update([kSecClass as String:kSecClassGenericPassword,kSecMatchItemList as String:[item]] as CFDictionary,[kSecValueData as String:data,kSecAttrGeneric as String:Data(credential.recordID.utf8)] as CFDictionary)
    }
    func forget(matching credential:SavedFleetCredential?=nil, authorize:()->Bool = { ownerActive() })->OSStatus {
        let (opened,keychain)=open(); guard opened == errSecSuccess, let keychain=keychain else { return opened }
        var query=Self.query(keychain); query[kSecReturnRef as String]=true
        if let credential=credential { query[kSecAttrGeneric as String]=Data(credential.recordID.utf8) }
        let (found,item)=copy(query as CFDictionary)
        if found == errSecItemNotFound { return credential == nil ? errSecSuccess : errSecItemNotFound }
        guard found == errSecSuccess, let item=item else { return found }
        var removal:[String:Any]=[kSecClass as String:kSecClassGenericPassword,kSecMatchItemList as String:[item]]
        if let credential=credential { removal[kSecAttrGeneric as String]=Data(credential.recordID.utf8) }
        guard authorize() else { return errSecUserCanceled }
        return delete(removal as CFDictionary)
    }
}


func makeApplicationMenu(_ application: NSApplication) -> NSMenu {
    let menu = NSMenu(title:"Gargoyl")
    let hide = menu.addItem(withTitle:"Hide Gargoyl",action:#selector(NSApplication.hide(_:)),keyEquivalent:"h")
    hide.target = application; hide.keyEquivalentModifierMask = [.command]
    let others = menu.addItem(withTitle:"Hide Others",action:#selector(NSApplication.hideOtherApplications(_:)),keyEquivalent:"h")
    others.target = application; others.keyEquivalentModifierMask = [.command,.option]
    let show = menu.addItem(withTitle:"Show All",action:#selector(NSApplication.unhideAllApplications(_:)),keyEquivalent:"")
    show.target = application
    menu.addItem(.separator())
    let quit = menu.addItem(withTitle:"Quit Gargoyl",action:#selector(NSApplication.terminate(_:)),keyEquivalent:"q")
    quit.target = application
    return menu
}

let resourceRules = #"[{"trigger":{"url-filter":".*"},"action":{"type":"block"}}]"#
let fleetSignInURL = URL(string:"https://console.darkbloom.dev/link?purpose=desktop_account")!
let nativeViews = ["fleet", "management", "tools", "evidence", "history", "operation", "details"]
func accountView(_ value: String) -> Bool { value == "management" || value.hasPrefix("fleet") }
func readOnlyView(_ value: String) -> Bool {
    return nativeViews.contains(value) || ["fleet-recent","fleet-older","fleet-unknown"].contains(value) || value.range(of:"^fleet-node-[a-f0-9]{64}$",options:.regularExpression) != nil
}
func validFleetAuthorization(_ value: [String:Any]) -> Bool {
    guard Set(value.keys) == Set(["kind","purpose","user_code","expires_in"]),
          value["kind"] as? String == "fleet-authorization", value["purpose"] as? String == "desktop_account",
          let code = value["user_code"] as? String, code.range(of:"^[A-Za-z0-9-]{4,32}$",options:.regularExpression) != nil,
          let number = value["expires_in"] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
          let expires = value["expires_in"] as? Int, expires > 0 && expires <= 900 else { return false }
    return true
}
func safeAliasText(_ value:String, maximum:Int=64) -> Bool {
    return value.count <= maximum && value.utf8.count <= maximum * 2 && value.unicodeScalars.allSatisfy { ![.control,.format,.surrogate].contains($0.properties.generalCategory) }
}
func aliasRows(_ value:[String:Any]) -> [[String:String]]? {
    guard Set(value.keys) == Set(["kind","providers"]), value["kind"] as? String == "fleet-alias-list",
          let rows = value["providers"] as? [[String:String]], !rows.isEmpty, rows.count <= 256,
          Set(rows.compactMap { $0["id"] }).count == rows.count else { return nil }
    for row in rows {
        guard Set(row.keys) == Set(["id","name","alias"]), let id=row["id"], !id.isEmpty, safeAliasText(id,maximum:128),
              let name=row["name"], !name.isEmpty, safeAliasText(name,maximum:128), let alias=row["alias"], safeAliasText(alias) else { return nil }
    }
    return rows
}
func endedFleetStatus(_ previous:String, disconnected:Bool, preview:Bool=false) -> String {
    if preview {
        return "Read-only preview: account connection, saved-session recovery and provider controls are disabled; cached reports are retained."
    }
    return disconnected ? "Account memory collection disconnected. Saved sign-in is separate; use Forget to remove it." : previous + " Account session ended; cached reports are not live. Reconnect to resume."
}
func observedExitText(_ observation: (status: Int32, signal: Bool)?) -> String? {
    guard let observation = observation else { return nil }
    return observation.signal
        ? " The account reader was terminated by signal \(observation.status)."
        : " The account reader exited with status \(observation.status)."
}
func viewDestination(_ url: URL?, mainFrame: Bool) -> String? {
    guard mainFrame, let url = url else { return nil }
    let prefix = "gargoyl-view://"
    let value = url.absoluteString
    guard value.hasPrefix(prefix), value.hasSuffix("/") else { return nil }
    let view = String(value.dropFirst(prefix.count).dropLast())
    return readOnlyView(view) && value == prefix + view + "/" ? view : nil
}

let fragmentScripts = [
    "main":"document.getElementById('main')?.scrollIntoView()",
    "fleet-overview":"document.getElementById('fleet-overview')?.scrollIntoView()",
    "needs-attention":"document.getElementById('needs-attention')?.scrollIntoView()"
]
func canonicalLocalHost(_ value: String) -> String? {
    guard let id = UUID(uuidString:value), id.uuidString.lowercased() == value else { return nil }
    return id.uuidString.lowercased()
}
func fragmentScript(_ url: URL?, mainFrame: Bool, localHostID: String = "00000000-0000-4000-8000-000000000001") -> String? {
    guard mainFrame, let value = url?.absoluteString else { return nil }
    if let fixed = fragmentScripts.first(where:{ value == "about:blank#" + $0.key || value == "about:blank%23" + $0.key }) { return fixed.value }
    // Reconstruct from the trusted view's canonical identity, never URL text.
    guard let id = canonicalLocalHost(localHostID),
          value == "about:blank#host-" + id || value == "about:blank%23host-" + id else { return nil }
    return "document.getElementById('host-\(id)')?.scrollIntoView()"
}
func scrollNativeFragment(_ action: WKNavigationAction, in web: WKWebView, localHostID: String = "00000000-0000-4000-8000-000000000001", cancel: () -> Void) -> Bool {
    guard action.navigationType == .linkActivated,
          let script = fragmentScript(action.request.url,mainFrame:action.targetFrame?.isMainFrame == true,localHostID:localHostID) else { return false }
    cancel()
    web.evaluateJavaScript(script,completionHandler:nil)
    return true
}

func ownerActive() -> Bool {
    #if GARGOYL_NATIVE_TESTS
    if let value = ProcessInfo.processInfo.environment["GARGOYL_TEST_OWNER"], value == "1" { return true }
    #endif
    var uid: uid_t = 0; var gid: gid_t = 0
    return SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) != nil && uid == geteuid() && geteuid() != 0
}

func allowedNavigation(_ url: URL?, mainFrame: Bool) -> Bool {
    guard mainFrame, let url = url else { return false }
    return url.absoluteString == "about:blank"
}
struct ViewSelection {
    private(set) var selected = "fleet"
    private(set) var generation = 0
    mutating func select(_ view: String) -> Bool {
        guard readOnlyView(view) else { return false }
        selected = view; generation += 1; return true
    }
    func accepts(_ generation: Int) -> Bool { return generation == self.generation }
}
func manualCompletionMessage(status: Int32, verified: Bool, failure: String?) -> String? {
    if let failure = failure { return failure }
    if status != 0 || !verified { return "Manual operation completion is unverified or was not authorized. No automatic retry. Refresh Operation status before another attempt." }
    return nil
}
func reconciliationEnabled(state: String, preview: Bool, busy: Bool) -> Bool {
    !preview && !busy && ["intent","unknown"].contains(state)
}

struct ApprovalGate {
    let request: String
    let digest: String
    let expires: Double
    var consumed = false
    mutating func consume(request: String, digest: String, owner: Bool, authenticated: Bool, now: Double) -> Bool {
        guard !consumed, request == self.request, digest == self.digest else { return false }
        consumed = true
        return owner && authenticated && now <= expires && now >= expires-90
    }
}
struct CompletionGate {
    var ended = false
    var eof = false
    var finalized = false
    mutating func finish() -> Bool {
        guard ended && eof && !finalized else { return false }
        finalized = true; return true
    }
}
struct WindowHistory {
    private(set) var events: [String] = []
    mutating func record(_ event: String, miniaturized: Bool, visible: Bool, reopeningVisibleWindows: Bool? = nil, applicationHidden: Bool? = nil) {
        let sequence = (events.last.flatMap { Int($0.split(separator:" ")[0]) } ?? 0) + 1
        let reopened = reopeningVisibleWindows.map { " hasVisibleWindows=\($0)" } ?? ""
        let hidden = applicationHidden.map { " applicationHidden=\($0)" } ?? ""
        events.append("\(sequence) \(event) miniaturized=\(miniaturized) visible=\(visible)\(reopened)\(hidden)")
        events = Array(events.suffix(16))
    }
}
final class Worker {
    let mode: String
    let process = Process()
    let input = Pipe()
    let output = Pipe()
    var buffer = Data()
    var replied = false
    var exitObservation: (status: Int32, signal: Bool)?
    var completion = CompletionGate()
    let event: ([String: Any]) -> Void
    let finished: (Worker) -> Void
    init(mode: String, preview: Bool = false, event: @escaping ([String: Any]) -> Void, finished: @escaping (Worker) -> Void = { _ in }) throws {
        self.mode = mode; self.event = event; self.finished = finished
        if preview && ["fleet-session", "fleet-session-remember", "fleet-restore"].contains(mode) { throw NSError(domain:"Gargoyl", code:1) }
        var pythonPath = Bundle.main.object(forInfoDictionaryKey: "GargoylPython") as? String
        #if GARGOYL_NATIVE_TESTS
        pythonPath = ProcessInfo.processInfo.environment["GARGOYL_FIXTURE_PYTHON"] ?? pythonPath
        let pathAllowed = (pythonPath != nil) && (pythonPath!.hasPrefix(NSHomeDirectory() + "/") || ProcessInfo.processInfo.environment["GARGOYL_FIXTURE_PYTHON"] != nil)
        #else
        let pathAllowed = (pythonPath != nil) && pythonPath!.hasPrefix(NSHomeDirectory() + "/")
        #endif
        guard ownerActive(), (["restart", "reconcile", "status", "export", "start-monitor", "stop-monitor", "fleet-session", "fleet-alias-list", "fleet-alias-set", "fleet-session-remember", "fleet-restore"].contains(mode) || (mode.hasPrefix("view-") && readOnlyView(String(mode.dropFirst(5))))),
              let path = pythonPath,
              pathAllowed, path.hasSuffix("/.venv/bin/python") || path.hasSuffix("/bin/python")
        else { throw NSError(domain: "Gargoyl", code: 1) }
        let executable = URL(fileURLWithPath: path)
        let attributes = try FileManager.default.attributesOfItem(atPath: executable.resolvingSymlinksInPath().path)
        guard let owner = attributes[.ownerAccountID] as? NSNumber, [0,Int(geteuid())].contains(owner.intValue),
              let permissions = attributes[.posixPermissions] as? NSNumber, permissions.intValue & 0o022 == 0
        else { throw NSError(domain: "Gargoyl", code: 2) }
        process.executableURL = executable
        process.arguments = ["-I", "-B", "-m", "gargoyl.gui_runtime", mode]
        var env = ["HOME":NSHomeDirectory(), "PATH":"/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE":"1"]
        if preview { env["GARGOYL_PREVIEW"] = "1" }
        process.environment = env
        process.currentDirectoryURL = URL(fileURLWithPath: NSHomeDirectory())
        process.standardInput = input; process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            DispatchQueue.main.async {
                guard let self = self else { return }
                if data.isEmpty { handle.readabilityHandler = nil; self.completion.eof = true; self.finishIfReady(); return }
                self.buffer.append(data)
                if self.buffer.count > 600000 { self.buffer.removeAll(); return }
                while let newline = self.buffer.firstIndex(of: 10) {
                    let line = self.buffer.prefix(upTo: newline)
                    self.buffer.removeSubrange(...newline)
                    if let value = try? JSONSerialization.jsonObject(with: line) as? [String: Any] { self.event(value) }
                }
            }
        }
        process.terminationHandler = { [weak self] terminated in DispatchQueue.main.async {
            guard let self = self else { return }
            self.exitObservation = (terminated.terminationStatus, terminated.terminationReason == .uncaughtSignal)
            self.completion.ended = true; self.finishIfReady()
        } }
        try process.run()
    }
    func finishIfReady() {
        if completion.finish() { finished(self) }
    }
    func reply(_ request: [String: Any], approved: Bool) {
        guard !replied, let id = request["request_id"] as? String, let digest = request["preview_digest"] as? String else { return }
        replied = true
        if let data = try? JSONSerialization.data(withJSONObject: ["request_id":id,"preview_digest":digest,"approved":approved]) {
            try? input.fileHandleForWriting.write(contentsOf: data + Data([10]))
        }
        try? input.fileHandleForWriting.close()
    }
    func restoreCredential(_ credential:SavedFleetCredential, retryCount:Int=0) {
        guard mode == "fleet-restore", !replied, SavedFleetCredential.tokenValid(credential.token) else { return }
        replied = true
        var payload: [String: Any] = ["purpose":"desktop_account","token":credential.token,"valid_until":credential.expires]
        if retryCount > 0 { payload["retry_count"] = retryCount }
        if let data=try? JSONSerialization.data(withJSONObject:payload) {
            try? input.fileHandleForWriting.write(contentsOf:data+Data([10]))
        }
    }
    func setAlias(provider:String, alias:String) {
        guard mode == "fleet-alias-set", !replied else { return }
        replied = true
        if let data = try? JSONSerialization.data(withJSONObject:["provider_id":provider,"alias":alias]) {
            try? input.fileHandleForWriting.write(contentsOf:data + Data([10]))
        }
        try? input.fileHandleForWriting.close()
    }
    func disconnectFleet() {
        guard ["fleet-session", "fleet-session-remember", "fleet-restore"].contains(mode) else { return }
        if let data = "disconnect\n".data(using: .utf8) {
            try? input.fileHandleForWriting.write(contentsOf: data)
        }
        try? input.fileHandleForWriting.close()
    }
    func quitFleet() {
        guard ["fleet-session", "fleet-session-remember", "fleet-restore"].contains(mode) else { return }
        if let data = "quit\n".data(using: .utf8) {
            try? input.fileHandleForWriting.write(contentsOf: data)
        }
        try? input.fileHandleForWriting.close()
    }
    // No terminate/interrupt method: closing the app never cancels accepted work.
}

enum FleetRecoveryDecision: Equatable {
    case retry(delay: Double, attempt: Int)
    case terminal
    case none
}

func decideFleetRecovery(
    reason: String,
    retryCount: Int,
    preview: Bool,
    generationMatch: Bool,
    savedExpires: Double?,
    now: Double,
    ownerActive: Bool
) -> FleetRecoveryDecision {
    guard generationMatch, !preview, ownerActive else { return .none }
    if ["auth_required", "scope_refused", "expired"].contains(reason) {
        return .none
    }
    guard let expires = savedExpires, expires > now else {
        return .none
    }
    if retryCount < 5 {
        let attempt = retryCount + 1
        let delay: Double = reason == "session_busy" ? 3.0 : min(60.0, 3.0 * pow(2.0, Double(retryCount)))
        return .retry(delay: delay, attempt: attempt)
    } else {
        return .terminal
    }
}

final class App: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate, NSMenuItemValidation, NSToolbarDelegate, NSToolbarItemValidation {
    var window: NSWindow!
    var windowHistory = WindowHistory()
    var web: WKWebView!
    let status = NSTextField(wrappingLabelWithString: "Loading read-only operator console… Automatic repair is off.")
    var restartButton: NSButton!
    var reconcileButton: NSButton!
    var operationState = "unavailable"
    var workers: [Worker] = []
    var restartWorker: Worker?
    var manualVerified = false
    var acceptedOperationID: String?
    var manualFailure: String?
    var webReady = false
    var viewSelection = ViewSelection()
    var viewWorker: Worker?
    var renderedLocalHostID = ""
    var pending: [String: Any]?
    var approvalGate: ApprovalGate?
    var context: LAContext?
    var consentSheet: NSWindow?
    var approvalTimer: Timer?
    var exportData: Data?
    let fleetStatus = NSTextField(wrappingLabelWithString:"Account fleet not connected. This Mac’s local collection is separate.")
    #if GARGOYL_NATIVE_TESTS
    var readRemember:()->Bool = { false }
    var writeRemember:(Bool)->Void = { _ in }
    #else
    var readRemember:()->Bool = { UserDefaults.standard.bool(forKey:"rememberReadOnlyFleet") }
    var writeRemember:(Bool)->Void = { UserDefaults.standard.set($0,forKey:"rememberReadOnlyFleet") }
    #endif
    var fleetOwner:()->Bool = { ownerActive() }
    var credentialStore=LoginFleetCredentialStore()
    let credentialQueue=DispatchQueue(label:"dev.gargoyl.readonly-keychain")
    var credentialEpoch=0
    var keychainBusy=false
    var pendingCredentialRemoval:FleetRemovalRequest?
    var savedFleetState=FleetSavedSessionState()
    var rememberCurrentFleet=false
    var fleetCredentialGate=FleetCredentialGate()
    var fleetGrantStartedAt=0.0
    var startupRestoreAttempted=false
    var fleetRetryCount=0
    var lastFleetReason=""
    var forgetFleetButton=NSButton()
    var fleetWorker: Worker?
    var aliasWorker: Worker?
    var aliasOptions = [[String:String]]()
    var aliasPicker: NSPopUpButton?
    var aliasField: NSTextField?
    var aliasIdentityLabel: NSTextField?
    var fleetGeneration = 0
    var fleetAuthSheet: NSWindow?
    var fleetUserCode: String?
    var fleetAuthPresented = false
    var fleetAuthTimer: Timer?
    var fleetRecoveryTimer: Timer?
    var fleetRefreshTimer: Timer?
    var connectFleetButton: NSButton!
    var accountMenu: NSMenu?
    var accountToolbarItem: NSMenuToolbarItem?
    var accountTitleTimer: Timer?
    var disconnectFleetButton: NSButton!
    var viewPhase = "not started"
    #if GARGOYL_NATIVE_TESTS
    var previewOverride:Bool?
    #endif
    var previewOnly: Bool {
        #if GARGOYL_NATIVE_TESTS
        if let value=previewOverride { return value }
        #endif
        return Bundle.main.object(forInfoDictionaryKey:"GargoylReadOnlyPreview") as? Bool ?? true
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        let menu = NSMenu(); let appItem = NSMenuItem(); menu.addItem(appItem)
        let appMenu = makeApplicationMenu(NSApp)
        appItem.submenu = appMenu; NSApp.mainMenu = menu
        let viewItem = NSMenuItem(); menu.addItem(viewItem); let viewMenu = NSMenu(title:"View"); viewItem.submenu = viewMenu
        let fullScreen = viewMenu.addItem(withTitle:"Enter Full Screen",action:#selector(NSWindow.toggleFullScreen(_:)),keyEquivalent:"f"); fullScreen.keyEquivalentModifierMask = [.command,.control]
        let windowItem = NSMenuItem(); menu.addItem(windowItem); let windowMenu = NSMenu(title:"Window"); windowItem.submenu = windowMenu
        let minimizeItem = windowMenu.addItem(withTitle:"Minimize",action:#selector(NSWindow.performMiniaturize(_:)),keyEquivalent:"m")
        windowMenu.addItem(withTitle:"Zoom",action:#selector(NSWindow.performZoom(_:)),keyEquivalent:"")
        NSApp.windowsMenu = windowMenu
        let helpItem = NSMenuItem(); menu.addItem(helpItem); let helpMenu = NSMenu(title:"Help"); helpItem.submenu = helpMenu
        let diagnostics = helpMenu.addItem(withTitle:"Window diagnostics…",action:#selector(windowDiagnostics),keyEquivalent:""); diagnostics.target = self
        window = NSWindow(contentRect: NSRect(x:0,y:0,width:1180,height:820), styleMask:[.titled,.closable,.miniaturizable,.resizable], backing:.buffered, defer:false)
        window.isReleasedWhenClosed = false
        minimizeItem.target = window
        window.title = previewOnly ? "Gargoyl — Read-only preview" : "Gargoyl"
        window.collectionBehavior.insert(.fullScreenPrimary)
        window.minSize = NSSize(width:390,height:600); window.delegate = self
        let content = NSView(); window.contentView = content
        // Native title-bar toolbar. Account actions live in one menu whose items mirror the enabled
        // state of hidden state-holder buttons (validateMenuItem); toolbar items mirror the restart and
        // reconciliation holders (validateToolbarItem), so the existing control logic is unchanged.
        connectFleetButton = NSButton(title:"Connect fleet…",target:self,action:#selector(connectFleet))
        disconnectFleetButton = NSButton(title:"Disconnect fleet",target:self,action:#selector(disconnectFleet)); disconnectFleetButton.isEnabled = false
        forgetFleetButton = NSButton(title:"Forget saved sign-in…",target:self,action:#selector(forgetSavedFleet)); forgetFleetButton.isEnabled = !previewOnly && self.readRemember()
        if previewOnly {
            connectFleetButton.isEnabled = false
            fleetStatus.stringValue = "Read-only preview: account connection, saved sign-in, and provider control are disabled."
        }
        let account = NSMenu(title:"Account")
        let header = NSMenuItem(title:"Darkbloom account · read-only",action:nil,keyEquivalent:""); header.isEnabled = false
        account.addItem(header)
        let accountItems: [(String, Selector)?] = [("Connect fleet…",#selector(connectFleet)),("Resume saved sign-in",#selector(resumeSavedFleet)),("Disconnect fleet",#selector(disconnectFleet)),nil,("Forget saved sign-in…",#selector(forgetSavedFleet))]
        for entry in accountItems {
            guard let entry = entry else { account.addItem(NSMenuItem.separator()); continue }
            let (title, selector) = entry
            let item = NSMenuItem(title:title,action:selector,keyEquivalent:""); item.target = self; account.addItem(item)
        }
        account.autoenablesItems = true; accountMenu = account
        reconcileButton = NSButton(title:"Record reconciliation…",target:self,action:#selector(reconcileOperation))
        reconcileButton.isEnabled = false; reconcileButton.isHidden = true
        restartButton = NSButton(title:"Restart local provider…",target:self,action:#selector(restartProvider))
        if previewOnly { restartButton.isEnabled = false }
        let toolbar = NSToolbar(identifier:"GargoylMainToolbar")
        toolbar.delegate = self; toolbar.displayMode = .iconAndLabel; toolbar.allowsUserCustomization = false
        window.toolbar = toolbar; window.toolbarStyle = .unified
        let config = WKWebViewConfiguration(); config.defaultWebpagePreferences.allowsContentJavaScript = false
        config.websiteDataStore = .nonPersistent()
        web = WKWebView(frame:.zero,configuration:config); web.navigationDelegate = self; web.uiDelegate = self
        // Native messages sit in a quiet status area under the page instead of above it.
        for field in [fleetStatus,status] {
            field.font = NSFont.systemFont(ofSize:NSFont.smallSystemFontSize); field.textColor = .secondaryLabelColor
            field.translatesAutoresizingMaskIntoConstraints = false
        }
        let statusArea = NSStackView(views:[fleetStatus,status]); statusArea.orientation = .vertical; statusArea.alignment = .leading; statusArea.spacing = 2
        statusArea.translatesAutoresizingMaskIntoConstraints = false; web.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(web); content.addSubview(statusArea)
        NSLayoutConstraint.activate([
            web.leadingAnchor.constraint(equalTo:content.leadingAnchor),web.trailingAnchor.constraint(equalTo:content.trailingAnchor),web.topAnchor.constraint(equalTo:content.topAnchor),
            web.heightAnchor.constraint(greaterThanOrEqualToConstant:300),
            statusArea.topAnchor.constraint(equalTo:web.bottomAnchor,constant:6),statusArea.leadingAnchor.constraint(equalTo:content.leadingAnchor,constant:12),
            statusArea.trailingAnchor.constraint(equalTo:content.trailingAnchor,constant:-12),statusArea.bottomAnchor.constraint(equalTo:content.bottomAnchor,constant:-8),
            fleetStatus.widthAnchor.constraint(equalTo:statusArea.widthAnchor),status.widthAnchor.constraint(equalTo:statusArea.widthAnchor)
        ])
        window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps:true)
        accountTitleTimer = Timer.scheduledTimer(withTimeInterval:1,repeats:true) { [weak self] _ in self?.syncAccountTitle(); self?.window.toolbar?.validateVisibleItems() }
        fleetRefreshTimer = Timer.scheduledTimer(withTimeInterval:30,repeats:true) { [weak self] _ in
            guard let self = self, accountView(self.viewSelection.selected), self.window.isVisible, !NSApp.isHidden else { return }
            self.refresh()
        }
        viewPhase = "compiling isolation rules"
        WKContentRuleListStore.default().compileContentRuleList(forIdentifier:"GargoylLoopbackOnly",encodedContentRuleList:resourceRules) { [weak self] list, _ in
            DispatchQueue.main.async {
                guard let self = self, let list = list else { self?.show("Dashboard network isolation unavailable. Display remains blocked."); return }
                self.web.configuration.userContentController.add(list); self.webReady = true; self.viewPhase = "rules ready"; self.refresh(); self.restoreSavedFleetIfEnabled()
            }
        }
    }
    // Account menu items mirror the hidden state-holder buttons the connection logic maintains.
    func validateMenuItem(_ item: NSMenuItem) -> Bool {
        switch item.action {
        case #selector(connectFleet): return connectFleetButton?.isEnabled ?? false
        case #selector(disconnectFleet): return disconnectFleetButton?.isEnabled ?? false
        case #selector(forgetSavedFleet): return forgetFleetButton.isEnabled
        case #selector(resumeSavedFleet): return !previewOnly && !keychainBusy && readRemember() && (connectFleetButton?.isEnabled ?? false)
        default: return toolbarActionEnabled(item.action)
        }
    }
    // The Account title says whether an account session is open, so the state never hides in the menu.
    func syncAccountTitle() {
        let open = disconnectFleetButton?.isEnabled ?? false
        let tip = open ? "Account · connecting or connected (read-only)" : "Account · not connected"
        guard let item = accountToolbarItem, item.toolTip != tip else { return }
        item.toolTip = tip
        item.image = NSImage(systemSymbolName:open ? "person.crop.circle.fill" : "person.crop.circle",accessibilityDescription:tip)
    }
    // Toolbar: read-only actions first, then a flexible gap, then manual operation set apart.
    let toolbarSpecs: [(NSToolbarItem.Identifier, String, String, String, Selector)] = [
        (NSToolbarItem.Identifier("gargoyl.aliases"),"Aliases…","Edit friendly names kept only on this Mac","tag",#selector(editFleetAliases)),
        (NSToolbarItem.Identifier("gargoyl.refresh"),"Refresh","Reload the current view","arrow.clockwise",#selector(refresh)),
        (NSToolbarItem.Identifier("gargoyl.start"),"Start monitor","Start this Mac's Gargoyl monitoring job (never Darkbloom)","play.circle",#selector(startMonitor)),
        (NSToolbarItem.Identifier("gargoyl.stop"),"Stop monitor","Stop this Mac's Gargoyl monitoring job (never Darkbloom)","stop.circle",#selector(stopMonitor)),
        (NSToolbarItem.Identifier("gargoyl.export"),"Export local…","Save bounded normalized evidence from this Mac","square.and.arrow.up",#selector(exportReport)),
        (NSToolbarItem.Identifier("gargoyl.operation"),"Operation status","Show the last manual operation on this Mac","list.bullet.rectangle",#selector(operationStatus)),
        (NSToolbarItem.Identifier("gargoyl.reconcile"),"Reconcile…","Available on Operation status for an unresolved operation","checkmark.seal",#selector(reconcileOperation)),
        (NSToolbarItem.Identifier("gargoyl.restart"),"Restart local…","Review and confirm one graceful Darkbloom restart on this Mac","arrow.counterclockwise.circle",#selector(restartProvider))
    ]
    let accountIdentifier = NSToolbarItem.Identifier("gargoyl.account")
    func toolbarOrder() -> [NSToolbarItem.Identifier] {
        let ids = toolbarSpecs.map { $0.0 }
        return [accountIdentifier] + Array(ids[0..<5]) + [.flexibleSpace] + Array(ids[5..<7]) + [.space, ids[7]]
    }
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] { toolbarOrder() }
    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] { toolbarOrder() }
    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        if itemIdentifier == accountIdentifier {
            let item = NSMenuToolbarItem(itemIdentifier:itemIdentifier)
            item.label = "Account"; item.paletteLabel = "Account"; item.showsIndicator = true
            if let menu = accountMenu { item.menu = menu }
            item.image = NSImage(systemSymbolName:"person.crop.circle",accessibilityDescription:"Account · not connected")
            item.toolTip = "Account · not connected"
            accountToolbarItem = item
            return item
        }
        guard let spec = toolbarSpecs.first(where:{ $0.0 == itemIdentifier }) else { return nil }
        let item = NSToolbarItem(itemIdentifier:itemIdentifier)
        item.label = spec.1; item.paletteLabel = spec.1; item.toolTip = spec.2
        item.image = NSImage(systemSymbolName:spec.3,accessibilityDescription:spec.1)
        item.target = self; item.action = spec.4; item.isBordered = true
        return item
    }
    // Toolbar items mirror the same enablement the old buttons had.
    // One rule for toolbar items and their overflow-menu copies (which validate as menu items).
    func toolbarActionEnabled(_ action: Selector?) -> Bool {
        switch action {
        case #selector(startMonitor), #selector(stopMonitor), #selector(editFleetAliases): return !previewOnly
        case #selector(restartProvider): return restartButton?.isEnabled ?? false
        case #selector(reconcileOperation): return (reconcileButton?.isEnabled ?? false) && !(reconcileButton?.isHidden ?? true)
        default: return true
        }
    }
    func validateToolbarItem(_ item: NSToolbarItem) -> Bool {
        if item.action == #selector(reconcileOperation) {
            // Pass through the specific reason Operation status computes (none recorded, preview, busy).
            item.toolTip = (reconcileButton?.isHidden ?? true) ? "Open Operation status to review an unresolved operation" : reconcileButton?.toolTip
        }
        return toolbarActionEnabled(item.action)
    }
    @objc func refresh() { displayView(viewSelection.selected) }
    func displayView(_ view: String) {
        guard webReady, viewSelection.select(view) else { return }
        if view == "operation" { operationState = "unavailable" }
        updateReconciliationControl()
        // One read-only worker at a time. A changed selection is loaded after it exits.
        guard viewWorker == nil else { return }
        viewPhase = "loading private view"
        renderedLocalHostID = ""
        let generation = viewSelection.generation
        var delivered = false
        do {
            viewWorker = try Worker(mode:"view-" + view,preview:previewOnly,event:{ [weak self] value in
                guard let self = self, self.viewSelection.accepts(generation),
                      value["kind"] as? String == "view", value["view"] as? String == view,
                      let html = value["html"] as? String, html.utf8.count <= 500000,
                      let localHostID = value["local_host_id"] as? String, canonicalLocalHost(localHostID) != nil else { return }
                if view == "operation" {
                    let state = value["operation_state"] as? String ?? "unavailable"
                    self.operationState = ["none","intent","unknown","completed","reconciled","unavailable"].contains(state) ? state : "unavailable"
                    self.updateReconciliationControl()
                }
                self.renderedLocalHostID = localHostID
                delivered = true; self.viewPhase = "received private HTML"
                self.finishViewLoading()
                self.web.loadHTMLString(html,baseURL:URL(string:"about:blank"))
            },finished:{ [weak self] completed in
                guard let self = self, self.viewWorker === completed else { return }
                self.viewWorker = nil; self.viewPhase = delivered ? "worker completed" : "worker completed without HTML"
                if !self.viewSelection.accepts(generation) { self.displayView(self.viewSelection.selected); return }
                if !delivered || completed.process.terminationStatus != 0 {
                    self.web.loadHTMLString("<html><body><h1>View unavailable</h1><p>Current evidence could not be validated. Health and operation outcome are unknown. Use Refresh to check again. No provider action was performed.</p></body></html>",baseURL:URL(string:"about:blank"))
                }
            })
        } catch {
            viewPhase = "worker launch unavailable"
            web.loadHTMLString("<html><body><h1>View unavailable</h1><p>Active Mac owner or installed worker unavailable. No provider action was performed.</p></body></html>",baseURL:URL(string:"about:blank"))
        }
    }
    func finishViewLoading() {
        if status.stringValue == "Loading read-only operator console… Automatic repair is off." {
            show("Read-only views. Provider restart requires Mac confirmation; automatic repair is off.")
        }
    }
    func show(_ text: String) { status.stringValue = String(text.prefix(4000)) }
    func launch(_ mode: String, handler: (([String: Any]) -> Void)? = nil) {
        do {
            let worker = try Worker(mode:mode,event:{ [weak self] value in
                if let handler = handler { handler(value) }
                else if let text = value["text"] as? String { self?.show(text) }
            },finished:{ [weak self] completed in
                self?.workers.removeAll { $0 === completed }
                if completed.process.terminationStatus != 0 { self?.show("Action unavailable or unverified. No automatic retry. Inspect operation status.") }
            })
            workers.append(worker)
        } catch { show("Action unavailable. Check that this app and the installed monitor belong to the active Mac owner.") }
    }
    func dismissFleetAuthorization() {
        fleetAuthTimer?.invalidate(); fleetAuthTimer = nil
        let sheet = fleetAuthSheet; fleetAuthSheet = nil; fleetUserCode = nil
        if let sheet = sheet { window.endSheet(sheet); sheet.orderOut(nil) }
    }
    @objc func openFleetSignIn() {
        #if !GARGOYL_NATIVE_TESTS
        guard fleetAuthSheet != nil, fleetWorker != nil, ownerActive() else { return }
        NSWorkspace.shared.open(fleetSignInURL)
        fleetStatus.stringValue = "Awaiting your official read-only approval. The one-time code remains in the native sheet."
        #endif
    }
    @objc func copyFleetCode() {
        guard fleetAuthSheet != nil, ownerActive(), let code = fleetUserCode else { return }
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(code,forType:.string)
    }
    @objc func disconnectFleet() {
        fleetGeneration += 1
        fleetRecoveryTimer?.invalidate(); fleetRecoveryTimer = nil
        dismissFleetAuthorization()
        fleetWorker?.disconnectFleet()
        fleetStatus.stringValue = "Disconnecting account collection. Local monitoring and Darkbloom remain unchanged."
        disconnectFleetButton.isEnabled = false
        if fleetWorker == nil { connectFleetButton.isEnabled = !previewOnly }
    }
    @objc func aliasProviderChanged() {
        guard let picker=aliasPicker, aliasOptions.indices.contains(picker.indexOfSelectedItem) else { return }
        let row=aliasOptions[picker.indexOfSelectedItem]
        aliasField?.stringValue = row["alias"] ?? ""
        aliasIdentityLabel?.stringValue = "Actual provider ID: " + (row["id"] ?? "") + "\nSource label: " + (row["name"] ?? "")
    }
    @objc func editFleetAliases() {
        guard !previewOnly, ownerActive(), aliasWorker == nil, window.attachedSheet == nil else { return }
        do {
            aliasWorker = try Worker(mode:"fleet-alias-list",event:{ [weak self] value in
                guard let self=self else { return }
                guard let rows=aliasRows(value), self.ownerForAlias() else { self.show("Local alias inventory unavailable. Connect the account and refresh; actual IDs remain unchanged."); return }
                self.presentAliasEditor(rows)
            },finished:{ [weak self] completed in
                guard let self=self, self.aliasWorker === completed else { return }; self.aliasWorker=nil
            })
        } catch { show("Local aliases unavailable. No provider setting was changed.") }
    }
    func ownerForAlias() -> Bool { return ownerActive() && window.attachedSheet == nil }
    func presentAliasEditor(_ rows:[[String:String]]) {
        guard ownerForAlias() else { return }
        aliasOptions=rows
        let picker=NSPopUpButton(frame:NSRect(x:0,y:0,width:540,height:30))
        picker.addItems(withTitles:rows.map { ($0["name"] ?? "") + " · " + ($0["id"] ?? "") })
        picker.target=self; picker.action = #selector(aliasProviderChanged); aliasPicker=picker
        let name=NSTextField(string:""); name.placeholderString="Your local friendly name"; aliasField=name
        let identity=NSTextField(wrappingLabelWithString:""); identity.font=NSFont.monospacedSystemFont(ofSize:11,weight:.regular); aliasIdentityLabel=identity
        let controls=NSStackView(views:[picker,identity,name]); controls.orientation = .vertical; controls.alignment = .leading; controls.spacing=10
        controls.frame=NSRect(x:0,y:0,width:540,height:115)
        name.widthAnchor.constraint(equalToConstant:540).isActive=true
        identity.widthAnchor.constraint(equalToConstant:540).isActive=true
        aliasProviderChanged()
        let alert=NSAlert(); alert.messageText="Edit local friendly name"
        alert.informativeText="Choose the actual provider ID, then enter a name you recognize. This alias stays on this Mac; it does not rename Darkbloom records or change identity matching, restart targets or provider settings. Leave the name blank to remove its alias."
        alert.accessoryView=controls; alert.addButton(withTitle:"Save local alias"); alert.addButton(withTitle:"Cancel")
        alert.beginSheetModal(for:window) { [weak self] response in
            guard let self=self else { return }
            defer { self.aliasOptions=[]; self.aliasPicker=nil; self.aliasField=nil; self.aliasIdentityLabel=nil }
            guard response == .alertFirstButtonReturn, ownerActive(), rows.indices.contains(picker.indexOfSelectedItem), safeAliasText(name.stringValue) else { return }
            let selected=rows[picker.indexOfSelectedItem]
            do {
                let writer = try Worker(mode:"fleet-alias-set",event:{ [weak self] value in
                    guard let self=self else { return }
                    if value["kind"] as? String == "status" { self.show("Local alias saved. Actual provider ID and source name are unchanged."); self.refresh() }
                    else { self.show("Local alias unavailable. No provider setting was changed.") }
                },finished:{ [weak self] completed in
                    guard let self=self, self.aliasWorker === completed else { return }; self.aliasWorker=nil
                })
                self.aliasWorker=writer; writer.setAlias(provider:selected["id"]!,alias:name.stringValue)
            } catch { self.show("Local alias unavailable. No provider setting was changed.") }
        }
    }
    @objc func connectFleet() {
        guard !previewOnly, fleetWorker == nil, ownerActive(), window.attachedSheet == nil else { return }
        let alert=NSAlert(); alert.messageText="Connect your read-only fleet account"
        alert.informativeText="Darkbloom’s account grant can view Macs, summary and earnings; Gargoyl reads only owned-provider metadata. It cannot control providers. You approve the account grant on the official site. Optionally remember this read-only session in this Mac’s encrypted login Keychain, with standard macOS application access controls. No password, provider credential or synchronization is configured. You may see a macOS Keychain access prompt, including after app updates."
        let remember=NSButton(checkboxWithTitle:"Remember this read-only account in login Keychain",target:nil,action:nil)
        remember.state = .off; remember.isEnabled = !keychainBusy; alert.accessoryView=remember
        alert.addButton(withTitle:"Continue"); alert.addButton(withTitle:"Cancel")
        alert.beginSheetModal(for:window) { [weak self] response in
            guard let self=self, response == .alertFirstButtonReturn, ownerActive() else { return }
            self.beginFleet(remember:remember.state == .on, restored:nil)
        }
    }
    func beginFleet(remember:Bool, restored:SavedFleetCredential?, retryCount:Int=0) {
        guard !previewOnly, fleetWorker == nil, ownerActive() else { return }
        if remember && keychainBusy { show("Remember is unavailable while another Keychain operation is pending. Try again when it finishes."); return }
        fleetRecoveryTimer?.invalidate(); fleetRecoveryTimer = nil
        fleetRetryCount=retryCount; lastFleetReason=""
        savedFleetState=FleetSavedSessionState(); savedFleetState.credential=restored; savedFleetState.stored = (restored != nil) ? self.readRemember() : false
        fleetGeneration += 1; let generation = fleetGeneration; fleetAuthPresented = false
        rememberCurrentFleet=remember; fleetCredentialGate=FleetCredentialGate()
        fleetGrantStartedAt=Date().timeIntervalSince1970
        connectFleetButton.isEnabled = false; disconnectFleetButton.isEnabled = true
        fleetStatus.stringValue = restored == nil ? "Requesting Darkbloom’s read-only account scope… No provider grant fallback." : "Checking saved read-only account access… Cached reports do not prove a live session."
        displayView("fleet")
        do {
            let mode=restored != nil ? "fleet-restore" : (remember ? "fleet-session-remember" : "fleet-session")
            fleetWorker = try Worker(mode:mode,preview:previewOnly,event:{ [weak self] value in
                guard let self = self, generation == self.fleetGeneration else { return }
                // Credentials are consumed here; never enter generic rendering/status paths.
                if value["kind"] as? String == "fleet-credential" { self.rememberFreshFleetCredential(value,generation:generation); return }
                self.fleetEvent(value,generation:generation)
            },finished:{ [weak self] completed in
                guard let self = self, self.fleetWorker === completed else { return }
                self.dismissFleetAuthorization(); self.fleetWorker = nil
                self.connectFleetButton.isEnabled = !self.previewOnly; self.disconnectFleetButton.isEnabled = false
                self.fleetStatus.stringValue = endedFleetStatus(self.fleetStatus.stringValue,disconnected:generation != self.fleetGeneration,preview:self.previewOnly)
                self.refresh()
                let decision = decideFleetRecovery(
                    reason: self.lastFleetReason,
                    retryCount: self.fleetRetryCount,
                    preview: self.previewOnly,
                    generationMatch: generation == self.fleetGeneration,
                    savedExpires: self.savedFleetState.credential?.expires,
                    now: Date().timeIntervalSince1970,
                    ownerActive: self.fleetOwner()
                )
                switch decision {
                case .retry(let delay, let attempt):
                    self.connectFleetButton.isEnabled = false; self.disconnectFleetButton.isEnabled = true
                    let reasonDesc = self.lastFleetReason == "session_busy" ? "Waiting for the previous account reader to close…" : "Recovering account reader with saved sign-in…"
                    self.fleetStatus.stringValue = "\(reasonDesc) Retrying in \(Int(delay))s (attempt \(attempt)/5). No new grant or provider action."
                    self.fleetRecoveryTimer?.invalidate()
                    self.fleetRecoveryTimer = Timer.scheduledTimer(withTimeInterval:delay,repeats:false) { [weak self] _ in
                        guard let self=self else { return }
                        self.runRecovery(generation:generation,attempt:attempt)
                    }
                case .terminal:
                    self.fleetStatus.stringValue = "Account reader recovery stopped after reaching retry budget. Saved sign-in is preserved; resume manually when available."
                case .none:
                    break
                }
                if let exitText = observedExitText(completed.exitObservation) {
                    self.fleetStatus.stringValue = self.fleetStatus.stringValue + exitText
                }
            })
            if let restored=restored { fleetWorker?.restoreCredential(restored, retryCount: retryCount) }
        } catch {
            fleetStatus.stringValue = "Account connection unavailable. No provider action or credential fallback was attempted."
            connectFleetButton.isEnabled = !previewOnly; disconnectFleetButton.isEnabled = false
        }
    }
    func runRecovery(generation:Int,attempt:Int) {
        guard generation == self.fleetGeneration, self.fleetWorker == nil else { return }
        self.resetRestoreControls(generation:generation)
        guard self.fleetOwner(), let saved=self.savedFleetState.credential, saved.expires > Date().timeIntervalSince1970 else { return }
        self.beginFleet(remember:false,restored:saved,retryCount:attempt)
    }
    func rememberFreshFleetCredential(_ value:[String:Any],generation:Int) {
        guard let token=fleetCredentialGate.take(value,mode:fleetWorker?.mode ?? "",remember:rememberCurrentFleet,owner:self.fleetOwner(),generation:generation,current:fleetGeneration) else { disconnectFleet(); return }
        let credential=SavedFleetCredential(token:token,created:fleetGrantStartedAt,expires:fleetGrantStartedAt+30*86400)
        guard let data=credential.encoded(), SavedFleetCredential.decode(data,now:Date().timeIntervalSince1970) != nil else { show("Read-only session could not be saved. Current connection remains memory-only."); return }
        guard !keychainBusy else { show("Keychain busy; current connection remains memory-only."); return }
        keychainBusy=true
        let session=savedFleetState; session.credential=credential
        let previousRemember=self.readRemember()
        self.writeRemember(true); forgetFleetButton.isEnabled=true
        let epoch=credentialEpoch
        credentialQueue.async { [weak self] in
            guard let self=self else { return }
            let allowed=DispatchQueue.main.sync { self.fleetOwner() && epoch == self.credentialEpoch && generation == self.fleetGeneration }
            guard allowed else { DispatchQueue.main.async { self.finishKeychainOperation() }; return }
            let status=self.credentialStore.save(data)
            DispatchQueue.main.async {
                defer { self.finishKeychainOperation() }
                guard epoch == self.credentialEpoch else { return }
                session.stored = status == errSecSuccess
                if status == errSecSuccess {
                    self.writeRemember(true); self.forgetFleetButton.isEnabled=true
                    if session.revoked { self.queueCredentialRemoval(.matching(credential)); return }
                    self.show("Read-only sign-in saved in this Mac’s login Keychain. Quit/reopen can resume within the original grant lifetime. No provider credential was saved.")
                } else { self.writeRemember(previousRemember); self.forgetFleetButton.isEnabled=previousRemember; self.show("Keychain save unavailable or declined. The current connection remains memory-only; no plaintext fallback.") }
            }
        }
    }
    @objc func resumeSavedFleet() {
        guard !previewOnly, ownerActive(), fleetWorker == nil, !keychainBusy else { return }
        guard self.readRemember() else { show("No saved sign-in is enabled. Use Connect fleet and choose Remember if desired."); return }
        startupRestoreAttempted=false; restoreSavedFleetIfEnabled()
    }
    func restoreSavedFleetIfEnabled() {
        guard !startupRestoreAttempted else { return }; startupRestoreAttempted=true
        guard !previewOnly, self.readRemember(), self.fleetOwner(), fleetWorker == nil else { return }
        guard !keychainBusy else { return }; keychainBusy=true
        fleetGeneration += 1; let generation=fleetGeneration; let epoch=credentialEpoch
        connectFleetButton.isEnabled=false; disconnectFleetButton.isEnabled=true
        fleetStatus.stringValue="Reading the saved read-only sign-in from login Keychain…"
        credentialQueue.async { [weak self] in
            guard let self=self else { return }
            let allowed=DispatchQueue.main.sync { self.fleetOwner() && generation == self.fleetGeneration && epoch == self.credentialEpoch }
            guard allowed else { DispatchQueue.main.async { self.finishKeychainOperation(); self.resetRestoreControls(generation:generation) }; return }
            let (status,data)=self.credentialStore.read()
            let now=Date().timeIntervalSince1970
            let credential=data.flatMap { SavedFleetCredential.decode($0,now:now) }
            var expired=false
            var removed=false
            if status == errSecSuccess, let credential=credential, credential.expires <= now {
                expired=true
                let stillAllowed=DispatchQueue.main.sync { self.fleetOwner() && generation == self.fleetGeneration && epoch == self.credentialEpoch }
                if stillAllowed { removed=self.credentialStore.forget(matching:credential,authorize:{ DispatchQueue.main.sync { self.fleetOwner() && generation == self.fleetGeneration && epoch == self.credentialEpoch } }) == errSecSuccess }
            }
            DispatchQueue.main.async {
                defer { self.finishKeychainOperation() }
                self.resetRestoreControls(generation:generation)
                guard generation == self.fleetGeneration, epoch == self.credentialEpoch, self.fleetOwner() else { return }
                if expired || status == errSecItemNotFound {
                    if removed || status == errSecItemNotFound { self.writeRemember(false); self.forgetFleetButton.isEnabled=false }
                    self.fleetStatus.stringValue="Saved sign-in expired or is missing. Connect fleet to approve a new read-only session."
                } else if status == errSecSuccess, let credential=credential {
                    self.beginFleet(remember:false,restored:credential)
                } else { self.fleetStatus.stringValue="Saved sign-in unavailable, invalid, locked or access declined. Nothing was deleted. Connect fleet or try reopening after unlocking login Keychain." }
            }
        }
    }
    @objc func forgetSavedFleet() {
        guard !previewOnly, self.fleetOwner(), window.attachedSheet == nil else { return }
        let alert=NSAlert(); alert.messageText="Forget saved read-only sign-in?"
        alert.informativeText="Remove only Gargoyl’s saved account session from this Mac’s login Keychain. The current memory connection continues until you Disconnect or Quit. No account/provider credential, remote grant, provider setting or machine is changed."
        alert.addButton(withTitle:"Forget saved sign-in"); alert.addButton(withTitle:"Cancel")
        alert.beginSheetModal(for:window) { [weak self] response in
            guard let self=self, response == .alertFirstButtonReturn, self.fleetOwner() else { return }
            self.removeSavedFleetCredential()
        }
    }
    func resetRestoreControls(generation:Int) {
        guard generation == fleetGeneration, fleetWorker == nil else { return }
        connectFleetButton.isEnabled = !previewOnly; disconnectFleetButton.isEnabled=false
        if !self.fleetOwner() { fleetStatus.stringValue="Saved account restore cancelled because the active Mac owner changed. Connect fleet when the owner returns." }
    }
    func finishKeychainOperation() {
        keychainBusy=false
        if let pending=pendingCredentialRemoval, self.fleetOwner() { pendingCredentialRemoval=nil; queueCredentialRemoval(pending) }
    }
    func removeSavedFleetCredential() {
        credentialEpoch += 1
        queueCredentialRemoval(.all)
    }
    func queueCredentialRemoval(_ request:FleetRemovalRequest) {
        if keychainBusy {
            if case .all=request { pendingCredentialRemoval=request }
            else if pendingCredentialRemoval == nil { pendingCredentialRemoval=request }
            return
        }
        guard self.fleetOwner() else { pendingCredentialRemoval=request; return }
        keychainBusy=true
        let epoch=credentialEpoch
        credentialQueue.async { [weak self] in
            guard let self=self else { return }
            let allowed=DispatchQueue.main.sync { self.fleetOwner() && epoch == self.credentialEpoch }
            guard allowed else { DispatchQueue.main.async { self.finishKeychainOperation() }; return }
            let status:OSStatus
            switch request {
            case .all: status=self.credentialStore.forget(authorize:{ DispatchQueue.main.sync { self.fleetOwner() && epoch == self.credentialEpoch } })
            case .matching(let credential): status=self.credentialStore.forget(matching:credential,authorize:{ DispatchQueue.main.sync { self.fleetOwner() && epoch == self.credentialEpoch } })
            }
            DispatchQueue.main.async {
                defer { self.finishKeychainOperation() }
                guard epoch == self.credentialEpoch else { return }
                if status == errSecSuccess { self.writeRemember(false); self.forgetFleetButton.isEnabled=false; self.show("Saved sign-in forgotten. Existing memory collection is unchanged.") }
                else if status != errSecItemNotFound { self.show("Keychain removal unavailable or declined. Saved state was not assumed removed.") }
            }
        }
    }
    func fleetEvent(_ value:[String:Any], generation:Int) {
        guard let kind = value["kind"] as? String else { return }
        if kind == "fleet-authorization" {
            guard validFleetAuthorization(value), !fleetAuthPresented, fleetAuthSheet == nil, ownerActive(),
                  let code = value["user_code"] as? String, let expires = value["expires_in"] as? Int else { disconnectFleet(); return }
            fleetAuthPresented = true; fleetUserCode = code
            let alert = NSAlert(); alert.messageText = "Connect your Darkbloom fleet · read-only"
            alert.informativeText = "Use the account that owns your fleet. Copy this one-time code, open the official page and approve its read-only request.\n\nDarkbloom’s desktop_account scope permits fleet, summary and earnings reads, plus revoking this session; it does not grant provider control. Gargoyl requests only owned-provider metadata. Legacy provider grants are refused.\n\nIf you selected Remember, the read-only token is saved in login Keychain after the first validated fleet read; otherwise it stays in memory. Closing the window keeps collection running. No provider credential is stored. No provider restart, enrollment or remote commands."
            let field = NSTextField(labelWithString:code); field.isSelectable = true; field.font = NSFont.monospacedSystemFont(ofSize:22,weight:.semibold)
            let copy = NSButton(title:"Copy code",target:self,action:#selector(copyFleetCode))
            let open = NSButton(title:"Open official Darkbloom sign-in",target:self,action:#selector(openFleetSignIn))
            let controls = NSStackView(views:[field,copy,open]); controls.orientation = .vertical; controls.alignment = .leading; controls.spacing = 8
            controls.frame = NSRect(x:0,y:0,width:360,height:100); alert.accessoryView = controls
            alert.addButton(withTitle:"Cancel connection")
            fleetAuthSheet = alert.window
            fleetAuthTimer = Timer.scheduledTimer(withTimeInterval:Double(expires),repeats:false) { [weak self] _ in self?.disconnectFleet() }
            alert.beginSheetModal(for:window) { [weak self] _ in
                guard let self = self, generation == self.fleetGeneration, self.fleetAuthSheet != nil else { return }
                self.disconnectFleet()
            }
        } else if kind == "fleet-connected" {
            dismissFleetAuthorization()
            fleetStatus.stringValue = "Read-only account scope confirmed. Loading owned-provider metadata…"
        } else if kind == "fleet-updated", let count = value["count"] as? Int, count >= 0 && count <= 256 {
            fleetStatus.stringValue = "Account API returned \(count) provider records. Reports are not independent remote process checks."
            if accountView(viewSelection.selected) { refresh() }
        } else if kind == "fleet-unavailable" {
            dismissFleetAuthorization()
            let reason = value["reason"] as? String ?? "unavailable"
            lastFleetReason=reason
            if reason == "auth_required" {
                savedFleetState.revoked=true
                if savedFleetState.stored, let credential=savedFleetState.credential { queueCredentialRemoval(.matching(credential)) }
            }
            let reasons = ["session_busy":"Another local account reader is still closing. A saved read-only session may resume after it exits.","scope_refused":"Darkbloom did not confirm the read-only scope. Provider-control fallback was refused.","auth_required":"Account authorization is unavailable. Connect again to resume read-only collection.","invalid_data":"Account inventory could not be validated. No substitute fleet or health verdict is shown.","expired":"Account connection expired. Connect again; no credential was saved."]
            fleetStatus.stringValue = reasons[reason] ?? "Account collection unavailable. Cached reports are not current health evidence."
            if accountView(viewSelection.selected) { refresh() }
        }
    }
    @objc func startMonitor() { if !previewOnly { launch("start-monitor"); refresh() } }
    @objc func stopMonitor() { if !previewOnly { launch("stop-monitor") } }
    @objc func operationStatus() { displayView("operation") }
    @objc func exportReport() {
        launch("export",handler:{ [weak self] value in
            guard let self = self else { return }
            guard value["kind"] as? String == "export", let payload = value["payload"],
                  let data = try? JSONSerialization.data(withJSONObject:payload,options:[.prettyPrinted,.sortedKeys]), data.count <= 600000 else {
                if let text = value["text"] as? String { self.show(text) }; return
            }
            let panel = NSSavePanel(); panel.nameFieldStringValue = "gargoyl-diagnostics.json"
            panel.beginSheetModal(for:self.window) { response in
                guard response == .OK, let url = panel.url else { return }
                do { try data.write(to:url,options:.atomic); self.show("Normalized diagnostics exported. No raw logs, model names or credentials included.") }
                catch { self.show("Export could not be saved. No provider action was performed.") }
            }
        })
    }
    func updateReconciliationControl() {
        reconcileButton.isHidden = viewSelection.selected != "operation"
        reconcileButton.isEnabled = reconciliationEnabled(state:operationState,preview:previewOnly,busy:restartWorker != nil)
        reconcileButton.toolTip = operationState == "none" ? "No unresolved operation is recorded." : (reconcileButton.isEnabled ? "Review read-only observations; recording requires Mac confirmation. No provider command runs." : "No eligible unresolved record, preview-only mode, or another operation is active. Refresh Operation status.")
    }
    @objc func restartProvider() { startManualOperation("restart") }
    @objc func reconcileOperation() {
        guard reconciliationEnabled(state:operationState,preview:previewOnly,busy:restartWorker != nil) else { show("Reconciliation unavailable: no eligible unresolved operation. Refresh Operation status."); return }
        startManualOperation("reconcile")
    }
    func startManualOperation(_ mode: String) {
        guard ["restart","reconcile"].contains(mode), !previewOnly, restartWorker == nil, ownerActive() else { show("Manual operation unavailable: active owner or an existing operation could not be verified."); return }
        displayView("operation")
        restartButton.isEnabled = false; reconcileButton.isEnabled = false
        manualVerified = false; acceptedOperationID = nil; manualFailure = nil
        do {
            restartWorker = try Worker(mode:mode,event:{ [weak self] value in self?.restartEvent(value) },finished:{ [weak self] completed in
                guard let self = self, self.restartWorker === completed else { return }
                if let message = manualCompletionMessage(status:completed.process.terminationStatus,verified:self.manualVerified,failure:self.manualFailure) { self.show(message) }
                self.context?.invalidate(); self.context = nil; self.approvalTimer?.invalidate(); self.pending = nil; self.approvalGate = nil; self.acceptedOperationID = nil
                self.restartWorker = nil; self.restartButton.isEnabled = !self.previewOnly; self.updateReconciliationControl(); self.refresh()
            })
        } catch { restartButton.isEnabled = !previewOnly; updateReconciliationControl(); show("Manual operation unavailable. No provider action was invoked.") }
    }
    func restartEvent(_ value: [String: Any]) {
        guard let kind = value["kind"] as? String else { return }
        if kind == "preview" { review(value) }
        else if kind == "result" {
            if value["state"] as? String == "completed" && value["reason"] as? String == "cli_success_and_replacement_observed" {
                manualVerified = true
                show("Manual restart reported complete; replacement process verified. Protocol health remains unknown."); refresh()
            } else { show("Restart completion is unverified. No retry is permitted. Inspect Operation status.") }
        }
        else if kind == "reconcile-result" {
            if restartWorker?.mode == "reconcile", value["state"] as? String == "reconciled", value["reason"] as? String == "reconciled_read_only", let accepted = acceptedOperationID, value["operation_id"] as? String == accepted {
                manualVerified = true
                show("Read-only reconciliation recorded. Prior outcome remains unproven. No provider command ran. A later restart needs fresh preflight and Mac confirmation."); refresh()
            } else { show("Reconciliation completion is unverified. Refresh Operation status; no automatic retry.") }
        }
        else if let text = value["text"] as? String { if kind == "unavailable" { manualFailure = text }; show(text) }
    }
    func review(_ request: [String: Any]) {
        guard ownerActive(), pending == nil, let worker = restartWorker,
              ["restart","reconcile"].contains(worker.mode),
              request["policy"] as? String == (worker.mode == "reconcile" ? "native-readonly-reconciliation-v1" : "native-manual-installation-v1"),
              let id = request["request_id"] as? String, id.range(of:"^[a-f0-9]{32}$",options:.regularExpression) != nil,
              let expiry = request["expires_at"] as? Double, expiry >= Date().timeIntervalSince1970, expiry <= Date().timeIntervalSince1970+90,
              let digest = request["preview_digest"] as? String, digest.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil,
              let target = request["target"] as? [String:Any], let process = target["process"] as? [String:Any],
              let pid = process["pid"] as? Int, pid > 0, let birth = process["born_us"] as? Int64,
              process["owner_uid"] as? Int == Int(geteuid()), let version = target["version"] as? String, ["0.10.5","0.10.6"].contains(version)
        else { restartWorker?.reply(request,approved:false); show("Restart preview is unavailable or invalid."); return }
        let reconciling = worker.mode == "reconcile"
        var reconciliationText = ""
        if reconciling {
            guard let operation = request["operation_id"] as? String, operation.range(of:"^[a-f0-9]{32}$",options:.regularExpression) != nil,
                  let observation = request["observation"] as? String,
                  let description = ["original_process_observed":"The original process is observed now.","different_process_observed":"A different process is observed now.","provider_unobservable":"The provider could not be verified now."][observation]
            else { worker.reply(request,approved:false); show("Reconciliation preview is invalid."); return }
            var currentText = "Current provider identity: unverified."
            if observation != "provider_unobservable" {
                guard let current = request["current"] as? [String:Any], let process = current["process"] as? [String:Any],
                      let currentPID = process["pid"] as? Int, currentPID > 0, let currentBirth = process["born_us"] as? Int64, currentBirth > 0,
                      process["owner_uid"] as? Int == Int(geteuid()), let currentVersion = current["version"] as? String, ["0.10.5","0.10.6"].contains(currentVersion)
                else { worker.reply(request,approved:false); show("Current reconciliation observation is invalid."); return }
                currentText = "Current observed provider: PID \(currentPID), birth \(currentBirth), version \(currentVersion)."
            } else if !(request["current"] is NSNull) { worker.reply(request,approved:false); return }
            reconciliationText = "Operation \(operation). Prior target: PID \(pid), birth \(birth), version \(version).\n\n\(description) \(currentText)\n\nThis records only read-only observations in Gargoyl’s journal. No provider command, restart, retry or backend-guard clearing runs. The prior command must be absent, or the conservative unidentified-command bound must have elapsed. These observations do not prove what the interrupted request did or that no upstream work remains.\n\nRecording permits a later separately confirmed manual restart after fresh preflight. It does not establish exactly-once execution or a successful prior restart. Changed observations cancel this request.\n\nContinue to your Mac’s confirmation?"
        }
        pending = request
        approvalGate = ApprovalGate(request:id,digest:digest,expires:expiry)
        approvalTimer = Timer.scheduledTimer(withTimeInterval:90,repeats:false) { [weak self] _ in self?.cancelApproval("Confirmation expired. No manual operation was authorized.") }
        let alert = NSAlert(); alert.messageText = reconciling ? "Record read-only reconciliation?" : "Restart Darkbloom on this Mac?"
        alert.informativeText = "Current provider: PID \(pid), birth \(birth), version \(version), owner \(geteuid()).\nExecutable: ~/.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom\nCommand: restart --timeout 600 --startup-timeout 180 (no force).\n\nThe current provider in this installation will refuse new work, drain accepted work, then restart with existing settings. It may be unavailable while restarting. Darkbloom temporarily disables startup/watchdog, removes recovery history, changes termination allowance and restores configured recovery. Replacement can resume configured coordinator traffic/authorization and existing startup/update behavior. Existing model/settings are reused; no credentials or configuration are supplied. A timeout can leave it draining or disabled. No force or automatic retry is permitted.\n\nThis is installation-scoped consent, not an atomic lock to the displayed process. The target is checked again before execution. One operation may take up to 840 seconds plus cleanup. An uncertain result remains blocked.\n\nThe next step is your Mac’s authentication prompt."
        if reconciling { alert.informativeText = reconciliationText }
        alert.addButton(withTitle:"Continue to Mac confirmation"); alert.addButton(withTitle:"Cancel")
        consentSheet = alert.window
        alert.beginSheetModal(for:window) { [weak self, weak worker] response in
            guard let self = self, let worker = worker, self.restartWorker === worker, self.pending?["request_id"] as? String == id else { return }
            self.consentSheet = nil
            guard response == .alertFirstButtonReturn, ownerActive() else { self.cancelApproval("Cancelled. No manual operation was authorized."); return }
            #if GARGOYL_NATIVE_TESTS
            self.cancelApproval("Mac owner authentication is unavailable. The manual operation remains blocked.")
            #else
            let context = LAContext(); context.touchIDAuthenticationAllowableReuseDuration = 0; context.localizedCancelTitle = reconciling ? "Cancel reconciliation" : "Cancel restart"
            var error: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthentication,error:&error) else { self.cancelApproval("Mac owner authentication is unavailable. The manual operation remains blocked."); return }
            self.context = context
            context.evaluatePolicy(.deviceOwnerAuthentication,localizedReason:reconciling ? "record one read-only Gargoyl reconciliation" : "authorize one manual Darkbloom restart on this Mac") { success, _ in
                DispatchQueue.main.async {
                    guard self.restartWorker === worker, self.pending?["request_id"] as? String == id else { return }
                    guard var gate = self.approvalGate else { return }
                    let approved = gate.consume(request:id,digest:digest,owner:ownerActive(),authenticated:success,now:Date().timeIntervalSince1970)
                    self.approvalGate = gate
                    guard approved else { self.cancelApproval("Mac confirmation failed or was cancelled. No manual operation was authorized."); return }
                    self.approvalTimer?.invalidate(); self.context?.invalidate(); self.context = nil
                    self.acceptedOperationID = reconciling ? request["operation_id"] as? String : nil
                    self.pending = nil
                    worker.reply(request,approved:true)
                    self.show(reconciling ? "Mac owner confirmed. Rechecking current observations before recording reconciliation. No provider command runs." : "Mac owner confirmed. Rechecking the target before one graceful restart. Closing the app will not cancel or retry accepted work.")
                }
            }
            #endif
        }
    }
    func cancelApproval(_ message: String) {
        context?.invalidate(); context = nil; approvalTimer?.invalidate()
        if let sheet = consentSheet { consentSheet = nil; window.endSheet(sheet,returnCode:.abort) }
        if let request = pending { restartWorker?.reply(request,approved:false) }
        pending = nil; approvalGate = nil; show(message)
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if pending != nil { cancelApproval("Cancelled before authorization.") }
        if restartWorker != nil {
            let alert = NSAlert(); alert.messageText = "Close Gargoyl?"; alert.informativeText = "An accepted manual operation can continue independently. Closing this app never cancels, retries or clears its outcome. Reopen and use Operation status to inspect recorded evidence."
            alert.addButton(withTitle:"Keep open");alert.addButton(withTitle:"Close app")
            if alert.runModal() == .alertSecondButtonReturn {
                fleetRecoveryTimer?.invalidate(); fleetRecoveryTimer = nil
                fleetWorker?.quitFleet()
                return .terminateNow
            }
            return .terminateCancel
        }
        fleetRecoveryTimer?.invalidate(); fleetRecoveryTimer = nil
        fleetWorker?.quitFleet()
        return .terminateNow
    }
    func recordWindow(_ event: String, reopeningVisibleWindows: Bool? = nil) {
        guard window != nil else { return }
        windowHistory.record(event,miniaturized:window.isMiniaturized,visible:window.isVisible,reopeningVisibleWindows:reopeningVisibleWindows,applicationHidden:NSApp.isHidden)
    }
    func applicationDidHide(_ notification: Notification) { recordWindow("didHide") }
    func applicationDidUnhide(_ notification: Notification) { recordWindow("didUnhide") }
    func windowWillMiniaturize(_ notification: Notification) { recordWindow("willMiniaturize") }
    func windowDidMiniaturize(_ notification: Notification) { recordWindow("didMiniaturize") }
    func windowDidDeminiaturize(_ notification: Notification) { recordWindow("didDeminiaturize") }
    func windowWillClose(_ notification: Notification) { recordWindow("willClose") }
    @objc func windowDiagnostics() {
        let alert = NSAlert(); alert.messageText = "Native window diagnostics"
        alert.informativeText = "Window: Gargoyl. Minimize enabled: \(window.styleMask.contains(.miniaturizable)). Current miniaturized: \(window.isMiniaturized).\n\n" + windowHistory.events.joined(separator:"\n") + "\n\nRead-only view: \(viewPhase). Rules ready: \(webReady). View: \(viewSelection.selected). Generation: \(viewSelection.generation). Worker active: \(viewWorker != nil). Web size: \(Int(web.frame.width)) × \(Int(web.frame.height)). Document loaded: \(web.title != nil).\n\nEvents are bounded in-memory UI diagnostics only. Closing or minimizing this window does not stop monitoring or Darkbloom."
        alert.addButton(withTitle:"Done"); alert.beginSheetModal(for:window)
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        recordWindow("reopen",reopeningVisibleWindows:flag)
        if window.isMiniaturized { window.deminiaturize(nil) }
        window.makeKeyAndOrderFront(nil)
        if !keychainBusy, pendingCredentialRemoval != nil { finishKeychainOperation() }
        if accountView(viewSelection.selected) { refresh() }
        return false
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { return false }
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if action.navigationType == .linkActivated, let view = viewDestination(action.request.url,mainFrame:action.targetFrame?.isMainFrame == true) {
            decisionHandler(.cancel); displayView(view); return
        }
        if scrollNativeFragment(action,in:webView,localHostID:renderedLocalHostID,cancel:{ decisionHandler(.cancel) }) { return }
        guard allowedNavigation(action.request.url,mainFrame:action.targetFrame?.isMainFrame == true) else { decisionHandler(.cancel); return }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? { return nil }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { show("Monitoring is unavailable. Use Start monitoring; this never starts or restarts Darkbloom. Existing operation outcomes remain separate.") }
}

// Intent tokens can reach a reader that already exited; the write must fail with EPIPE, not kill the app.
signal(SIGPIPE, SIG_IGN)

#if GARGOYL_NATIVE_TESTS
final class ResourceFixture: NSObject, WKNavigationDelegate {
    let localHostID = "00000000-0000-4000-8000-000000000002"
    var finished = false
    var fragmentRequested = false
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if action.request.url?.absoluteString != "about:blank" { fragmentRequested = true }
        print("fixture navigation: \(action.request.url?.absoluteString ?? "nil") main=\(action.targetFrame?.isMainFrame == true) type=\(action.navigationType.rawValue) matched=\(fragmentScript(action.request.url,mainFrame:true) != nil)")
        if scrollNativeFragment(action,in:webView,localHostID:localHostID,cancel:{ decisionHandler(.cancel) }) { return }
        decisionHandler(allowedNavigation(action.request.url,mainFrame:action.targetFrame?.isMainFrame == true) ? .allow : .cancel)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { finished = true }
}
if CommandLine.arguments.contains("--self-test") {
    let fixtureApplication = NSApplication.shared
    let statusFixture = App()
    statusFixture.finishViewLoading(); precondition(statusFixture.status.stringValue.hasPrefix("Read-only views."))
    let uncertain = "Restart completion is unverified. No automatic retry. Inspect Operation status."
    statusFixture.show(uncertain); statusFixture.finishViewLoading()
    precondition(statusFixture.status.stringValue == uncertain)
    let appMenu = makeApplicationMenu(fixtureApplication)
    precondition(appMenu.items[0].action == #selector(NSApplication.hide(_:)))
    precondition(appMenu.items[0].keyEquivalent == "h" && appMenu.items[0].keyEquivalentModifierMask == [.command])
    precondition(appMenu.items[1].action == #selector(NSApplication.hideOtherApplications(_:)))
    precondition(appMenu.items[1].keyEquivalent == "h" && appMenu.items[1].keyEquivalentModifierMask == [.command,.option])
    precondition(appMenu.items[2].action == #selector(NSApplication.unhideAllApplications(_:)) && appMenu.items[2].keyEquivalent.isEmpty)
    for item in appMenu.items where !item.isSeparatorItem { precondition(item.target === fixtureApplication) }
    var ruleFinished = false; var ruleAccepted = false
    var compiledRules: WKContentRuleList?
    WKContentRuleListStore.default().compileContentRuleList(forIdentifier:"GargoylFixtureRules",encodedContentRuleList:resourceRules) { list, error in
        ruleAccepted = list != nil && error == nil; compiledRules = list; ruleFinished = true
        if let error = error { print("Rule compilation failed: \(error)") }
    }
    let limit = Date().addingTimeInterval(5)
    while !ruleFinished && Date() < limit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
    precondition(ruleAccepted)
    if let endpoint = ProcessInfo.processInfo.environment["GARGOYL_TEST_BLOCKED_RESOURCE"] {
        let configuration = WKWebViewConfiguration(); configuration.websiteDataStore = .nonPersistent()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = false
        configuration.userContentController.add(compiledRules!)
        let fixture = ResourceFixture(); let page = WKWebView(frame:NSRect(x:0,y:0,width:390,height:600),configuration:configuration); page.navigationDelegate = fixture
        page.loadHTMLString("<html><head><title>Native admin fixture</title></head><body><a href='about:blank#host-\(fixture.localHostID)'>Jump</a><h1 id='host-\(fixture.localHostID)' style='margin-top:1000px'>Rendered admin</h1><img src='\(endpoint)/image'><iframe src='\(endpoint)/frame'></iframe><link rel='stylesheet' href='\(endpoint)/style'></body></html>",baseURL:URL(string:"about:blank")!)
        let end = Date().addingTimeInterval(5)
        // WebKit can publish didFinish before its title property updates.
        // Wait for the actual main document, not only the callback.
        while (!fixture.finished || page.title != "Native admin fixture") && Date() < end { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        print("fixture finished=\(fixture.finished) title=\(page.title ?? "nil")")
        fflush(stdout)
        precondition(fixture.finished && page.title == "Native admin fixture")
        var anchor: String?; var inspected = false
        page.evaluateJavaScript("document.querySelector('a').href") { value, _ in anchor = value as? String; inspected = true }
        let inspectionLimit = Date().addingTimeInterval(3)
        while !inspected && Date() < inspectionLimit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        precondition(anchor == "about:blank#host-" + fixture.localHostID)
        precondition(fragmentScript(URL(string:anchor!),mainFrame:true,localHostID:fixture.localHostID) != nil)
        page.evaluateJavaScript("document.querySelector('a').click()",completionHandler:nil)
        let clickedLimit = Date().addingTimeInterval(1)
        while !fixture.fragmentRequested && Date() < clickedLimit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        var scrollPosition = 0.0
        let measureLimit = Date().addingTimeInterval(2)
        while scrollPosition <= 0 && Date() < measureLimit {
            var measured = false
            page.evaluateJavaScript("document.scrollingElement.scrollTop") { value, _ in scrollPosition = (value as? NSNumber)?.doubleValue ?? 0; measured = true }
            while !measured && Date() < measureLimit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
            if scrollPosition <= 0 { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        }
        print("actual anchor scroll=\(scrollPosition)"); fflush(stdout)
        precondition(scrollPosition > 0)
        if let file=ProcessInfo.processInfo.environment["GARGOYL_TEST_FLEET_HTML"], let html=try? String(contentsOfFile:file,encoding:.utf8) {
            fixture.finished=false; page.loadHTMLString(html,baseURL:URL(string:"about:blank")!)
            let fleetLimit=Date().addingTimeInterval(3)
            while !fixture.finished && Date() < fleetLimit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
            precondition(fixture.finished)
            for width in [390,760,1180] {
                page.setFrameSize(NSSize(width:width,height:600))
                var metrics:[NSNumber]?; var done=false
                page.evaluateJavaScript("[window.innerWidth,document.documentElement.scrollWidth,document.querySelector('.fleet-inventory').closest('.scroll').clientWidth,document.querySelector('.fleet-inventory').closest('.scroll').scrollWidth]") { value,_ in metrics=value as? [NSNumber]; done=true }
                let measureEnd=Date().addingTimeInterval(2)
                while !done && Date() < measureEnd { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
                precondition(metrics?.count == 4)
                precondition(metrics![0].intValue == width && metrics![1].intValue <= width)
                if width == 390 { precondition(metrics![3].intValue >= 800 && metrics![2].intValue < 390) }
            }
        }


    }
    if ProcessInfo.processInfo.environment["GARGOYL_FIXTURE_PYTHON"] != nil {
        var received = false; var ended = false
        let worker = try! Worker(mode:"view-tools",event:{ value in received = value["kind"] as? String == "view" },finished:{ _ in ended = true })
        let limit = Date().addingTimeInterval(5)
        while (!received || !ended) && Date() < limit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        print("worker received=\(received) finished=\(ended)"); fflush(stdout)
        precondition(received && ended)
        withExtendedLifetime(worker) {}
        let observed = worker.exitObservation
        precondition(observed != nil)
        precondition(observed?.status == 0 && observed?.signal == false)
        precondition(observedExitText(observed) == " The account reader exited with status 0.")

        let fixtureLogs = URL(fileURLWithPath:ProcessInfo.processInfo.environment["GARGOYL_FIXTURE_PYTHON"]!).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("logs")
        let stdinLog = fixtureLogs.appendingPathComponent("child_stdin.log").path
        let envLog = fixtureLogs.appendingPathComponent("child_env.log").path

        // Child process test: disconnectFleet() sends "disconnect\n"
        try? FileManager.default.removeItem(atPath: stdinLog)
        let discWorker = try! Worker(mode:"fleet-session",event:{ _ in })
        discWorker.disconnectFleet()
        let discLimit = Date().addingTimeInterval(0.5)
        while Date() < discLimit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        try? discWorker.input.fileHandleForWriting.close()
        let discData = (try? String(contentsOfFile:stdinLog,encoding:.utf8)) ?? ""
        precondition(discData.contains("disconnect\n"))
        withExtendedLifetime(discWorker) {}

        // Child process test: quitFleet() sends "quit\n"
        try? FileManager.default.removeItem(atPath: stdinLog)
        let quitWorker = try! Worker(mode:"fleet-session",event:{ _ in })
        quitWorker.quitFleet()
        let quitLimit = Date().addingTimeInterval(0.5)
        while Date() < quitLimit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        let quitData = (try? String(contentsOfFile:stdinLog,encoding:.utf8)) ?? ""
        precondition(quitData.contains("quit\n"))
        withExtendedLifetime(quitWorker) {}

        for send in [{ (w:Worker) in w.disconnectFleet() }, { (w:Worker) in w.quitFleet() }] {
            let exitedWorker = try! Worker(mode:"fleet-session",event:{ _ in })
            try? exitedWorker.input.fileHandleForWriting.write(contentsOf:Data("exit-now\n".utf8))
            let exitLimit = Date().addingTimeInterval(5)
            while exitedWorker.process.isRunning && Date() < exitLimit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
            precondition(!exitedWorker.process.isRunning)
            send(exitedWorker)
            withExtendedLifetime(exitedWorker) {}
        }

        // Child process test: preview sets GARGOYL_PREVIEW=1 without a fleet mode
        try? FileManager.default.removeItem(atPath: envLog)
        let prevWorker = try! Worker(mode:"status",preview:true,event:{ _ in })
        let prevLimit = Date().addingTimeInterval(0.5)
        while Date() < prevLimit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        try? prevWorker.input.fileHandleForWriting.close()
        let envData = (try? String(contentsOfFile:envLog,encoding:.utf8)) ?? ""
        precondition(envData == "1")
        withExtendedLifetime(prevWorker) {}

        // Preview combined with any fleet mode is refused by Worker construction.
        var previewFleetRefused = false
        do { _ = try Worker(mode:"fleet-session",preview:true,event:{ _ in }) } catch { previewFleetRefused = true }
        precondition(previewFleetRefused)
        for refusedMode in ["fleet-session-remember","fleet-restore"] {
            var refused = false
            do { _ = try Worker(mode:refusedMode,preview:true,event:{ _ in }) } catch { refused = true }
            precondition(refused)
        }

        // Worker.restoreCredential passes retry_count
        try? FileManager.default.removeItem(atPath: stdinLog)
        let restWorker = try! Worker(mode:"fleet-restore",event:{ _ in })
        let savedRest = SavedFleetCredential(token:"darkbloom-at-private-test-restore-token",created:100,expires:100+86400)
        restWorker.restoreCredential(savedRest,retryCount:3)
        let restLimit = Date().addingTimeInterval(0.5)
        while Date() < restLimit { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        try? restWorker.input.fileHandleForWriting.close()
        let restData = (try? String(contentsOfFile:stdinLog,encoding:.utf8)) ?? ""
        precondition(restData.contains("\"retry_count\":3"))
        precondition(restData.contains("darkbloom-at-private-test-restore-token"))
        withExtendedLifetime(restWorker) {}

        // beginFleet with restored credential produces fleet-restore mode and passes retryCount
        let restoreApp = App(); restoreApp.previewOverride = false
        restoreApp.connectFleetButton = NSButton(); restoreApp.disconnectFleetButton = NSButton()
        restoreApp.readRemember = { true }; restoreApp.fleetOwner = { true }
        restoreApp.beginFleet(remember:false,restored:savedRest,retryCount:4)
        precondition(restoreApp.fleetWorker?.mode == "fleet-restore")
        precondition(restoreApp.fleetRetryCount == 4)
        precondition(restoreApp.savedFleetState.credential?.token == savedRest.token)
        restoreApp.disconnectFleet()

        // Disconnect-then-finish: call disconnectFleet(), then invoke finished(worker) -> assert fleetRecoveryTimer == nil.
        // The credential is unexpired so the generation guard, not credential expiry, drives this outcome.
        let discFinishApp = App(); discFinishApp.previewOverride = false
        discFinishApp.connectFleetButton = NSButton(); discFinishApp.disconnectFleetButton = NSButton()
        discFinishApp.readRemember = { true }; discFinishApp.fleetOwner = { true }
        discFinishApp.lastFleetReason = "unavailable"
        discFinishApp.savedFleetState.credential = SavedFleetCredential(token:"valid-tok",created:100,expires:Date().timeIntervalSince1970+3600)
        discFinishApp.beginFleet(remember:false,restored:discFinishApp.savedFleetState.credential,retryCount:1)
        let preDiscGen = discFinishApp.fleetGeneration
        let activeWorker = discFinishApp.fleetWorker!
        discFinishApp.disconnectFleet()
        precondition(discFinishApp.fleetGeneration == preDiscGen + 1)
        precondition(discFinishApp.fleetRecoveryTimer == nil)
        activeWorker.finished(activeWorker)
        precondition(discFinishApp.fleetRecoveryTimer == nil)

        // Finish without disconnect: bounded recovery is scheduled from the in-memory grant.
        let retryApp = App(); retryApp.previewOverride = false
        retryApp.connectFleetButton = NSButton(); retryApp.disconnectFleetButton = NSButton()
        retryApp.readRemember = { true }; retryApp.fleetOwner = { true }
        retryApp.lastFleetReason = "unavailable"
        retryApp.savedFleetState.credential = SavedFleetCredential(token:"valid-tok",created:100,expires:Date().timeIntervalSince1970+3600)
        retryApp.beginFleet(remember:false,restored:retryApp.savedFleetState.credential,retryCount:1)
        let retryWorker = retryApp.fleetWorker!
        precondition(retryApp.fleetRecoveryTimer == nil)
        retryWorker.finished(retryWorker)
        precondition(retryApp.fleetWorker == nil)
        precondition(retryApp.fleetRecoveryTimer != nil)
        retryApp.disconnectFleet()
        precondition(retryApp.fleetRecoveryTimer == nil)

        // runRecovery restores the saved credential through beginFleet with the recorded attempt.
        let recoveryApp = App(); recoveryApp.previewOverride = false
        recoveryApp.connectFleetButton = NSButton(); recoveryApp.disconnectFleetButton = NSButton()
        recoveryApp.readRemember = { true }; recoveryApp.fleetOwner = { true }
        recoveryApp.savedFleetState.credential = SavedFleetCredential(token:"darkbloom-at-private-test-recovery-token",created:100,expires:Date().timeIntervalSince1970+3600)
        recoveryApp.runRecovery(generation:recoveryApp.fleetGeneration,attempt:3)
        precondition(recoveryApp.fleetWorker?.mode == "fleet-restore")
        precondition(recoveryApp.fleetRetryCount == 3)
        precondition(recoveryApp.savedFleetState.credential?.token == "darkbloom-at-private-test-recovery-token")
        recoveryApp.disconnectFleet()

        // Stale generation never schedules recovery.
        let staleGenApp = App(); staleGenApp.previewOverride = false
        staleGenApp.connectFleetButton = NSButton(); staleGenApp.disconnectFleetButton = NSButton()
        staleGenApp.fleetOwner = { true }
        staleGenApp.savedFleetState.credential = SavedFleetCredential(token:"valid-tok",created:100,expires:Date().timeIntervalSince1970+3600)
        staleGenApp.runRecovery(generation:staleGenApp.fleetGeneration+1,attempt:1)
        precondition(staleGenApp.fleetWorker == nil && staleGenApp.fleetRecoveryTimer == nil)

        // Owner change cancels recovery after the restore-controls reset.
        let ownerFlag = false
        let ownerSwitchApp = App(); ownerSwitchApp.previewOverride = false
        ownerSwitchApp.connectFleetButton = NSButton(); ownerSwitchApp.disconnectFleetButton = NSButton()
        ownerSwitchApp.fleetOwner = { ownerFlag }; ownerSwitchApp.readRemember = { true }
        ownerSwitchApp.savedFleetState.credential = SavedFleetCredential(token:"valid-tok",created:100,expires:Date().timeIntervalSince1970+3600)
        ownerSwitchApp.runRecovery(generation:ownerSwitchApp.fleetGeneration,attempt:1)
        precondition(ownerSwitchApp.fleetWorker == nil && ownerSwitchApp.fleetRecoveryTimer == nil)
        precondition(!ownerSwitchApp.disconnectFleetButton.isEnabled)

        // An expired saved credential never schedules recovery.
        let expiredCredApp = App(); expiredCredApp.previewOverride = false
        expiredCredApp.connectFleetButton = NSButton(); expiredCredApp.disconnectFleetButton = NSButton()
        expiredCredApp.fleetOwner = { true }
        expiredCredApp.savedFleetState.credential = SavedFleetCredential(token:"valid-tok",created:100,expires:Date().timeIntervalSince1970-10)
        expiredCredApp.runRecovery(generation:expiredCredApp.fleetGeneration,attempt:1)
        precondition(expiredCredApp.fleetWorker == nil && expiredCredApp.fleetRecoveryTimer == nil)

        try? FileManager.default.removeItem(atPath: stdinLog)
        try? FileManager.default.removeItem(atPath: envLog)
    }
    precondition(allowedNavigation(URL(string:"about:blank"),mainFrame:true))
    precondition(!allowedNavigation(URL(string:"about:blank#main"),mainFrame:true))
    for key in fragmentScripts.keys {
        for prefix in ["about:blank#", "about:blank%23"] { precondition(fragmentScript(URL(string:prefix + key),mainFrame:true) == fragmentScripts[key]) }
        precondition(fragmentScript(URL(string:"about:blank#" + key),mainFrame:false) == nil)
    }
    let configuredHost = "00000000-0000-4000-8000-000000000002"
    let hostURL = URL(string:"about:blank#host-" + configuredHost)
    precondition(fragmentScript(hostURL,mainFrame:true) == nil)
    precondition(fragmentScript(hostURL,mainFrame:true,localHostID:configuredHost) == "document.getElementById('host-\(configuredHost)')?.scrollIntoView()")
    precondition(fragmentScript(hostURL,mainFrame:false,localHostID:configuredHost) == nil)
    precondition(fragmentScript(hostURL,mainFrame:true,localHostID:"bad'payload") == nil)
    precondition(fragmentScript(URL(string:"https://example.invalid/#host-" + configuredHost),mainFrame:true,localHostID:configuredHost) == nil)
    for invalid in ["about:blank#restart", "about:blank%2523main", "about:blank%23main?command=restart", "about:blank#main/extra", "about:blank#main'", "http://127.0.0.1:8766/#main", "file:///tmp/#main", "gargoyl-view://tools/#main"] {
        precondition(fragmentScript(URL(string:invalid),mainFrame:true) == nil)
        precondition(!allowedNavigation(URL(string:invalid),mainFrame:true))
    }
    for reason in ["Reconciliation unavailable: the prior command is still running. Nothing was recorded.","Reconciliation unavailable: an unidentified prior command may still be running.","Reconciliation cancelled or confirmation expired. Nothing was recorded."] {
        let event:[String:Any] = ["kind":"unavailable","text":reason]
        let fixture=App(); fixture.restartEvent(event)
        precondition(manualCompletionMessage(status:1,verified:fixture.manualVerified,failure:fixture.manualFailure) == reason)
    }
    precondition(manualCompletionMessage(status:1,verified:false,failure:nil) != nil)
    precondition(manualCompletionMessage(status:0,verified:false,failure:nil) != nil)
    precondition(manualCompletionMessage(status:0,verified:true,failure:nil) == nil)
    precondition(reconciliationEnabled(state:"unknown",preview:false,busy:false))
    precondition(reconciliationEnabled(state:"intent",preview:false,busy:false))
    for state in ["none","completed","reconciled","unavailable","forged"] { precondition(!reconciliationEnabled(state:state,preview:false,busy:false)) }
    precondition(!reconciliationEnabled(state:"unknown",preview:true,busy:false))
    precondition(!reconciliationEnabled(state:"unknown",preview:false,busy:true))
    precondition(viewDestination(URL(string:"gargoyl-view://reconcile/"),mainFrame:true) == nil)
    for view in nativeViews { precondition(viewDestination(URL(string:"gargoyl-view://\(view)/"),mainFrame:true) == view) }
    for value in ["gargoyl-view://restart/", "gargoyl-view://tools/?action=restart", "gargoyl-view://user@tools/", "gargoyl-view://tools:80/", "gargoyl-view://tools/extra", "gargoyl-view://%74ools/", "gargoyl-view://tools/#restart", "https://example.com", "file:///tmp/test", "http://127.0.0.1:8766/", "data:text/html,test"] {
        precondition(viewDestination(URL(string:value),mainFrame:true) == nil)
        precondition(!allowedNavigation(URL(string:value),mainFrame:true))
    }
    precondition(viewDestination(URL(string:"gargoyl-view://tools/"),mainFrame:false) == nil)
    precondition(!allowedNavigation(URL(string:"about:blank"),mainFrame:false))

    let fixtureToken="darkbloom-at-fixture-token-123"
    let saved=SavedFleetCredential(token:fixtureToken,created:100,expires:100+30*86400)
    let savedData=saved.encoded()!
    precondition(SavedFleetCredential.decode(savedData,now:101)?.token == fixtureToken)
    precondition(SavedFleetCredential.decode(savedData,now:99) == nil)
    precondition(SavedFleetCredential.decode(savedData+Data(repeating:32,count:4096),now:101) == nil)
    precondition(SavedFleetCredential.decode(Data("{\"schema\":1,\"purpose\":\"provider\",\"token\":\"eigeninference-pt-fixture\",\"created\":100,\"expires\":200}".utf8),now:101) == nil)
    var credentialGate=FleetCredentialGate()
    let credentialEvent:[String:Any] = ["kind":"fleet-credential","purpose":"desktop_account","token":fixtureToken]
    precondition(credentialGate.take(credentialEvent,mode:"fleet-session",remember:false,owner:true,generation:1,current:1) == nil)
    precondition(credentialGate.take(credentialEvent,mode:"fleet-session-remember",remember:true,owner:true,generation:1,current:2) == nil)
    precondition(credentialGate.take(credentialEvent,mode:"fleet-session-remember",remember:true,owner:false,generation:1,current:1) == nil)
    precondition(credentialGate.take(credentialEvent,mode:"fleet-session-remember",remember:true,owner:true,generation:1,current:1) == fixtureToken)
    precondition(credentialGate.take(credentialEvent,mode:"fleet-session-remember",remember:true,owner:true,generation:1,current:1) == nil)
    precondition(LoginFleetCredentialStore.trustedLoginMetadata(fileOwner:501,mode:0o644,regular:true,parentOwner:501,parentMode:0o700,uid:501))
    precondition(!LoginFleetCredentialStore.trustedLoginMetadata(fileOwner:501,mode:0o664,regular:true,parentOwner:501,parentMode:0o700,uid:501))
    precondition(!LoginFleetCredentialStore.trustedLoginMetadata(fileOwner:502,mode:0o600,regular:true,parentOwner:501,parentMode:0o700,uid:501))
    precondition(!LoginFleetCredentialStore.trustedLoginMetadata(fileOwner:501,mode:0o600,regular:true,parentOwner:501,parentMode:0o777,uid:501))
    let loginFixture=NSObject(); let itemFixture=NSObject()
    var adds=0, updates=0, deletes=0, queries=0
    let fakeKeychain=LoginFleetCredentialStore(open:{ (errSecSuccess,loginFixture) },copy:{ query in
        let q=query as NSDictionary; precondition(q[kSecClass as String] as? String == kSecClassGenericPassword as String)
        precondition(q[kSecAttrService as String] as? String == LoginFleetCredentialStore.service)
        precondition(q[kSecAttrAccount as String] as? String == LoginFleetCredentialStore.account)
        precondition(q[kSecMatchSearchList as String] != nil); precondition(q[kSecUseDataProtectionKeychain as String] == nil)
        queries += 1
        return (errSecSuccess, q[kSecReturnData as String] as? Bool == true ? savedData as CFData : itemFixture)
    },add:{ query in
        let q=query as NSDictionary; precondition(q[kSecUseKeychain as String] != nil); precondition(q[kSecAttrAccess as String] == nil)
        precondition(q[kSecAttrSynchronizable as String] == nil); adds += 1; return errSecDuplicateItem
    },update:{ query,data in
        precondition((query as NSDictionary)[kSecMatchItemList as String] != nil); updates += 1; return errSecSuccess
    },delete:{ query in precondition((query as NSDictionary)[kSecMatchItemList as String] != nil); deletes += 1; return errSecSuccess })
    precondition(fakeKeychain.save(savedData) == errSecSuccess)
    precondition(fakeKeychain.read().1 == savedData)
    precondition(fakeKeychain.forget(authorize:{true}) == errSecSuccess)
    precondition(adds == 1 && updates == 1 && deletes == 1 && queries == 3)
    var deniedReads=0
    let deniedKeychain=LoginFleetCredentialStore(open:{ (errSecUserCanceled,nil) },copy:{ _ in deniedReads += 1; return (errSecSuccess,savedData as CFData) })
    precondition(deniedKeychain.read().0 == errSecUserCanceled); precondition(deniedReads == 0)

    func waitFakeKeychain(_ fixture:App) {
        let until=Date().addingTimeInterval(2)
        while fixture.keychainBusy && Date() < until { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        precondition(!fixture.keychainBusy)
    }
    let ownerChangedFixture=App(); ownerChangedFixture.previewOverride=false; ownerChangedFixture.connectFleetButton=NSButton(); ownerChangedFixture.disconnectFleetButton=NSButton(); var ownerPresent=true; var rememberFlag=true; var expiredDeletes=0
    ownerChangedFixture.fleetOwner={ownerPresent}; ownerChangedFixture.readRemember={rememberFlag}; ownerChangedFixture.writeRemember={rememberFlag=$0}
    let expiredRecord=SavedFleetCredential(token:fixtureToken,created:100,expires:200)
    ownerChangedFixture.credentialStore=LoginFleetCredentialStore(open:{ (errSecSuccess,loginFixture) },copy:{ _ in ownerPresent=false; return (errSecSuccess,expiredRecord.encoded()! as CFData) },delete:{ _ in expiredDeletes += 1; return errSecSuccess })
    ownerChangedFixture.restoreSavedFleetIfEnabled(); waitFakeKeychain(ownerChangedFixture)
    precondition(expiredDeletes == 0 && rememberFlag && ownerChangedFixture.connectFleetButton.isEnabled && !ownerChangedFixture.disconnectFleetButton.isEnabled)
    let cancelledRestore=App(); cancelledRestore.previewOverride=false; cancelledRestore.connectFleetButton=NSButton(); cancelledRestore.disconnectFleetButton=NSButton(); cancelledRestore.fleetGeneration=1; cancelledRestore.connectFleetButton.isEnabled=false; cancelledRestore.disconnectFleetButton.isEnabled=true
    cancelledRestore.disconnectFleet(); cancelledRestore.resetRestoreControls(generation:1)
    precondition(cancelledRestore.connectFleetButton.isEnabled && !cancelledRestore.disconnectFleetButton.isEnabled)
    let deniedRestore=App(); deniedRestore.previewOverride=false; deniedRestore.connectFleetButton=NSButton(); deniedRestore.disconnectFleetButton=NSButton(); var deniedFlag=true
    deniedRestore.fleetOwner={true}; deniedRestore.readRemember={deniedFlag}; deniedRestore.writeRemember={deniedFlag=$0}
    deniedRestore.credentialStore=LoginFleetCredentialStore(open:{ (errSecUserCanceled,nil) })
    deniedRestore.restoreSavedFleetIfEnabled(); waitFakeKeychain(deniedRestore)
    precondition(deniedFlag && deniedRestore.connectFleetButton.isEnabled && !deniedRestore.disconnectFleetButton.isEnabled)
    let previewApp = App(); previewApp.previewOverride = true; previewApp.connectFleetButton = NSButton(); previewApp.disconnectFleetButton = NSButton()
    precondition(previewApp.previewOnly)
    precondition(endedFleetStatus("status", disconnected: false, preview: previewApp.previewOnly).contains("Read-only preview"))
    let windowCloseApp = App()
    precondition(!windowCloseApp.applicationShouldTerminateAfterLastWindowClosed(NSApp))
    let replacement=SavedFleetCredential(token:fixtureToken,created:101,expires:201)
    var raceDeletes=0
    let replacementStore=LoginFleetCredentialStore(open:{ (errSecSuccess,loginFixture) },copy:{ query in
        let q=query as NSDictionary
        if q[kSecAttrGeneric as String] as? Data != Data(replacement.recordID.utf8) { return (errSecItemNotFound,nil) }
        return (errSecSuccess,itemFixture)
    },delete:{ query in
        precondition((query as NSDictionary)[kSecAttrGeneric as String] as? Data == Data(replacement.recordID.utf8)); raceDeletes += 1; return errSecSuccess
    })
    precondition(replacementStore.forget(matching:saved,authorize:{true}) == errSecItemNotFound)
    precondition(raceDeletes == 0)
    precondition(replacementStore.forget(matching:replacement,authorize:{false}) == errSecUserCanceled)
    precondition(raceDeletes == 0)
    precondition(replacementStore.forget(matching:replacement,authorize:{true}) == errSecSuccess)
    precondition(raceDeletes == 1)

    // S3: Swift recovery decision and bounds unit tests
    let nowVal = 1000.0
    let validExpiry = 2000.0
    let expiredVal = 500.0

    // 1. Preview mode causes .none
    precondition(decideFleetRecovery(reason: "", retryCount: 0, preview: true, generationMatch: true, savedExpires: validExpiry, now: nowVal, ownerActive: true) == .none)

    // 2. Generation mismatch causes .none
    precondition(decideFleetRecovery(reason: "", retryCount: 0, preview: false, generationMatch: false, savedExpires: validExpiry, now: nowVal, ownerActive: true) == .none)

    // 3. Owner inactive causes .none
    precondition(decideFleetRecovery(reason: "", retryCount: 0, preview: false, generationMatch: true, savedExpires: validExpiry, now: nowVal, ownerActive: false) == .none)

    // 4. Auth/scope/expired causes .none
    for r in ["auth_required", "scope_refused", "expired"] {
        precondition(decideFleetRecovery(reason: r, retryCount: 0, preview: false, generationMatch: true, savedExpires: validExpiry, now: nowVal, ownerActive: true) == .none)
    }

    // 5. Expired or missing credential causes .none
    precondition(decideFleetRecovery(reason: "unavailable", retryCount: 0, preview: false, generationMatch: true, savedExpires: expiredVal, now: nowVal, ownerActive: true) == .none)
    precondition(decideFleetRecovery(reason: "unavailable", retryCount: 0, preview: false, generationMatch: true, savedExpires: nil, now: nowVal, ownerActive: true) == .none)

    // 6. Exponential backoff progression for attempts 0..4 (capped at 60s)
    let expectedDelays: [Double] = [3.0, 6.0, 12.0, 24.0, 48.0]
    for count in 0..<5 {
        let dec = decideFleetRecovery(reason: "unavailable", retryCount: count, preview: false, generationMatch: true, savedExpires: validExpiry, now: nowVal, ownerActive: true)
        precondition(dec == .retry(delay: expectedDelays[count], attempt: count + 1))
    }

    // 7. session_busy uses fixed 3.0s delay regardless of attempt
    for count in 0..<5 {
        let dec = decideFleetRecovery(reason: "session_busy", retryCount: count, preview: false, generationMatch: true, savedExpires: validExpiry, now: nowVal, ownerActive: true)
        precondition(dec == .retry(delay: 3.0, attempt: count + 1))
    }

    // 8. 6th attempt (retryCount == 5) reaches .terminal
    precondition(decideFleetRecovery(reason: "unavailable", retryCount: 5, preview: false, generationMatch: true, savedExpires: validExpiry, now: nowVal, ownerActive: true) == .terminal)
    precondition(decideFleetRecovery(reason: "session_busy", retryCount: 5, preview: false, generationMatch: true, savedExpires: validExpiry, now: nowVal, ownerActive: true) == .terminal)

    // Preview app never starts worker or reads credentialStore
    var previewStoreOpens = 0
    var previewStoreCopies = 0
    let testPreviewApp = App(); testPreviewApp.previewOverride = true
    testPreviewApp.readRemember = { true }
    testPreviewApp.fleetOwner = { true }
    testPreviewApp.credentialStore = LoginFleetCredentialStore(
        open: { previewStoreOpens += 1; return (errSecSuccess, nil) },
        copy: { _ in previewStoreCopies += 1; return (errSecSuccess, nil) }
    )
    testPreviewApp.restoreSavedFleetIfEnabled()
    testPreviewApp.credentialQueue.sync {}
    precondition(previewStoreOpens == 0)
    precondition(previewStoreCopies == 0)
    precondition(testPreviewApp.fleetWorker == nil)

    // Disconnect invalidates pending recovery timer
    let timerApp = App(); timerApp.previewOverride = false
    timerApp.connectFleetButton = NSButton(); timerApp.disconnectFleetButton = NSButton()
    timerApp.fleetRecoveryTimer = Timer.scheduledTimer(withTimeInterval: 60.0, repeats: false) { _ in }
    precondition(timerApp.fleetRecoveryTimer != nil)
    let preGen = timerApp.fleetGeneration
    timerApp.disconnectFleet()
    precondition(timerApp.fleetRecoveryTimer == nil)
    precondition(timerApp.fleetGeneration == preGen + 1)

    precondition(viewDestination(URL(string:"gargoyl-view://fleet-restore/"),mainFrame:true) == nil)

    let accountPreview: [String:Any] = ["kind":"fleet-authorization","purpose":"desktop_account","user_code":"TEST-CODE","expires_in":900]
    precondition(validFleetAuthorization(accountPreview))
    precondition(safeAliasText("Studio One")); precondition(!safeAliasText("bad\u{202E}name"))
    let aliasesPreview:[String:Any] = ["kind":"fleet-alias-list","providers":[["id":"test-provider","name":"Mac","alias":"Studio One"]]]
    precondition(aliasRows(aliasesPreview)?.count == 1)
    precondition(aliasRows(["kind":"fleet-alias-list","providers":[["id":"test","name":"Mac","alias":"a"],["id":"test","name":"Mac","alias":"b"]]]) == nil)
    precondition(viewDestination(URL(string:"gargoyl-view://fleet-alias-set/"),mainFrame:true) == nil)
    precondition(fleetSignInURL.absoluteString == "https://console.darkbloom.dev/link?purpose=desktop_account")
    precondition(URLComponents(url:fleetSignInURL,resolvingAgainstBaseURL:false)!.queryItems == [URLQueryItem(name:"purpose",value:"desktop_account")])
    precondition(endedFleetStatus("Account API returned 4 records.",disconnected:false).contains("session ended; cached reports are not live"))
    precondition(endedFleetStatus("scope confirmed",disconnected:true).contains("disconnected"))
    precondition(endedFleetStatus("Account API returned 4 records.",disconnected:false,preview:true).contains("Read-only preview"))
    precondition(!endedFleetStatus("Account API returned 4 records.",disconnected:false,preview:true).contains("Reconnect to resume"))
    precondition(observedExitText(nil) == nil)
    precondition(observedExitText((0,false)) == " The account reader exited with status 0.")
    precondition(observedExitText((301,true)) == " The account reader was terminated by signal 301.")
    for change in [["expires_in":true],["purpose":"provider"],["token":"must-not-cross-native-pipe"],["expires_in":901],["user_code":"bad\ncode"]] as [[String:Any]] {
        var bad = accountPreview; bad.merge(change) { _,new in new }; precondition(!validFleetAuthorization(bad))
    }
    precondition(viewDestination(URL(string:"gargoyl-view://fleet-session/"),mainFrame:true) == nil)
    precondition(viewDestination(URL(string:"gargoyl-view://fleet-node-" + String(repeating:"a",count:64) + "/"),mainFrame:true) != nil)
    precondition(viewDestination(URL(string:"gargoyl-view://fleet-node-../../restart/"),mainFrame:true) == nil)
    var selection = ViewSelection(); precondition(selection.select("history"))
    let firstView = selection.generation
    precondition(selection.select("operation")); precondition(!selection.accepts(firstView))
    let secondView = selection.generation
    precondition(selection.select("operation")); precondition(!selection.accepts(secondView))
    precondition(!selection.select("restart")); precondition(selection.selected == "operation")
    precondition(selection.accepts(selection.generation))
    var gate = ApprovalGate(request:"one",digest:"bound",expires:100)
    precondition(!gate.consume(request:"other",digest:"bound",owner:true,authenticated:true,now:20))
    precondition(gate.consume(request:"one",digest:"bound",owner:true,authenticated:true,now:20))
    precondition(!gate.consume(request:"one",digest:"bound",owner:true,authenticated:true,now:20))
    for pair in [(false,true),(true,false)] { var refused = ApprovalGate(request:"one",digest:"bound",expires:100); precondition(!refused.consume(request:"one",digest:"bound",owner:pair.0,authenticated:pair.1,now:20)) }
    var expired = ApprovalGate(request:"one",digest:"bound",expires:100); precondition(!expired.consume(request:"one",digest:"bound",owner:true,authenticated:true,now:101))
    precondition(!expired.consume(request:"one",digest:"bound",owner:true,authenticated:true,now:20))
    var digest = ApprovalGate(request:"one",digest:"bound",expires:100); precondition(!digest.consume(request:"one",digest:"other",owner:true,authenticated:true,now:20))
    var rollback = ApprovalGate(request:"one",digest:"bound",expires:100); precondition(!rollback.consume(request:"one",digest:"bound",owner:true,authenticated:true,now:0))
    for eofFirst in [false,true] {
        var completion = CompletionGate(); precondition(!completion.finish())
        if eofFirst { completion.eof = true } else { completion.ended = true }; precondition(!completion.finish())
        completion.eof = true; completion.ended = true; precondition(completion.finish()); precondition(!completion.finish())
    }
    var windowEvents = WindowHistory()
    windowEvents.record("didMiniaturize",miniaturized:true,visible:false)
    windowEvents.record("didDeminiaturize",miniaturized:false,visible:true)
    precondition(windowEvents.events[0].contains("miniaturized=true"))
    precondition(windowEvents.events[1].contains("miniaturized=false"))
    var hiddenEvents = WindowHistory(); hiddenEvents.record("didHide",miniaturized:false,visible:true,applicationHidden:true)
    precondition(hiddenEvents.events[0].contains("applicationHidden=true"))
    for _ in 0..<30 { windowEvents.record("reopen",miniaturized:false,visible:true,reopeningVisibleWindows:true) }
    precondition(windowEvents.events.count == 16 && windowEvents.events.last!.hasPrefix("32 "))
    print("Native navigation and authorization-state fixtures passed; no OS authentication requested.")
    exit(0)
}
#endif
let application = NSApplication.shared
let delegate = App(); application.delegate = delegate
application.run()
"""
