"""Build source for an unprivileged native macOS operator shell; no action at import."""

SWIFT = r"""
import AppKit
import WebKit
import LocalAuthentication
import SystemConfiguration

let resourceRules = #"[{"trigger":{"url-filter":".*"},"action":{"type":"block"}},{"trigger":{"url-filter":"^http://127\\.0\\.0\\.1:8766/(report\\.json)?$"},"action":{"type":"ignore-previous-rules"}}]"#

func ownerActive() -> Bool {
    var uid: uid_t = 0; var gid: gid_t = 0
    return SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) != nil && uid == 501 && geteuid() == 501
}

func allowedNavigation(_ url: URL?, mainFrame: Bool) -> Bool {
    guard let url = url else { return false }
    return mainFrame && url.scheme == "http" && url.host == "127.0.0.1" && url.port == 8766 && ["/", "/report.json"].contains(url.path) && url.query == nil && url.user == nil && url.password == nil
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
final class Worker {
    let process = Process()
    let input = Pipe()
    let output = Pipe()
    var buffer = Data()
    var replied = false
    var completion = CompletionGate()
    let event: ([String: Any]) -> Void
    let finished: (Worker) -> Void
    init(mode: String, event: @escaping ([String: Any]) -> Void, finished: @escaping (Worker) -> Void) throws {
        self.event = event; self.finished = finished
        guard ownerActive(), ["restart", "status", "export", "start-monitor", "stop-monitor"].contains(mode),
              let path = Bundle.main.object(forInfoDictionaryKey: "GargoylPython") as? String,
              path.hasPrefix(NSHomeDirectory() + "/"), path.hasSuffix("/.venv/bin/python") || path.hasSuffix("/bin/python")
        else { throw NSError(domain: "Gargoyl", code: 1) }
        let executable = URL(fileURLWithPath: path)
        let attributes = try FileManager.default.attributesOfItem(atPath: executable.resolvingSymlinksInPath().path)
        guard let owner = attributes[.ownerAccountID] as? NSNumber, [0,501].contains(owner.intValue),
              let permissions = attributes[.posixPermissions] as? NSNumber, permissions.intValue & 0o022 == 0
        else { throw NSError(domain: "Gargoyl", code: 2) }
        process.executableURL = executable
        process.arguments = ["-I", "-B", "-m", "gargoyl.gui_runtime", mode]
        process.environment = ["HOME":NSHomeDirectory(), "PATH":"/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE":"1"]
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
        process.terminationHandler = { [weak self] _ in DispatchQueue.main.async { if let self = self { self.completion.ended = true; self.finishIfReady() } } }
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
    // No terminate/interrupt method: closing the app never cancels accepted work.
}

final class App: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate {
    var window: NSWindow!
    var web: WKWebView!
    let status = NSTextField(wrappingLabelWithString: "Read-only evidence. Provider restart requires Mac confirmation; automatic repair is off.")
    var restartButton: NSButton!
    var workers: [Worker] = []
    var restartWorker: Worker?
    var restartVerified = false
    var webReady = false
    var pending: [String: Any]?
    var approvalGate: ApprovalGate?
    var context: LAContext?
    var consentSheet: NSWindow?
    var approvalTimer: Timer?
    var exportData: Data?
    var previewOnly: Bool { Bundle.main.object(forInfoDictionaryKey: "GargoylReadOnlyPreview") as? Bool ?? true }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        let menu = NSMenu(); let appItem = NSMenuItem(); menu.addItem(appItem)
        let appMenu = NSMenu(); appMenu.addItem(withTitle: "Quit Gargoyl", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu; NSApp.mainMenu = menu
        let viewItem = NSMenuItem(); menu.addItem(viewItem); let viewMenu = NSMenu(title:"View"); viewItem.submenu = viewMenu
        let fullScreen = viewMenu.addItem(withTitle:"Enter Full Screen",action:#selector(NSWindow.toggleFullScreen(_:)),keyEquivalent:"f"); fullScreen.keyEquivalentModifierMask = [.command,.control]
        let windowItem = NSMenuItem(); menu.addItem(windowItem); let windowMenu = NSMenu(title:"Window"); windowItem.submenu = windowMenu
        windowMenu.addItem(withTitle:"Minimize",action:#selector(NSWindow.performMiniaturize(_:)),keyEquivalent:"m")
        windowMenu.addItem(withTitle:"Zoom",action:#selector(NSWindow.performZoom(_:)),keyEquivalent:"")
        NSApp.windowsMenu = windowMenu
        window = NSWindow(contentRect: NSRect(x:0,y:0,width:1180,height:820), styleMask:[.titled,.closable,.miniaturizable,.resizable], backing:.buffered, defer:false)
        window.title = previewOnly ? "Gargoyl — Read-only preview" : "Gargoyl"
        window.collectionBehavior.insert(.fullScreenPrimary)
        window.minSize = NSSize(width:390,height:600); window.delegate = self
        let content = NSView(); window.contentView = content
        let bar = NSStackView(); bar.orientation = .horizontal; bar.spacing = 8
        let actions: [(String, Selector)] = [("Start monitoring",#selector(startMonitor)),("Stop monitoring",#selector(stopMonitor)),("Refresh",#selector(refresh)),("Export…",#selector(exportReport)),("Operation status",#selector(operationStatus)),("Restart provider…",#selector(restartProvider))]
        for (title, selector) in actions {
            let button = NSButton(title:title,target:self,action:selector); button.bezelStyle = .rounded
            if selector == #selector(restartProvider) { restartButton = button }
            if previewOnly && [#selector(startMonitor),#selector(stopMonitor),#selector(restartProvider)].contains(selector) { button.isEnabled = false }
            bar.addArrangedSubview(button)
        }
        let config = WKWebViewConfiguration(); config.defaultWebpagePreferences.allowsContentJavaScript = false
        config.websiteDataStore = .nonPersistent()
        web = WKWebView(frame:.zero,configuration:config); web.navigationDelegate = self; web.uiDelegate = self
        let scroll = NSScrollView(); scroll.hasHorizontalScroller = true; scroll.documentView = bar
        bar.frame = NSRect(x:0,y:0,width:bar.fittingSize.width,height:36)
        let stack = NSStackView(views:[scroll,status,web]); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false; content.addSubview(stack)
        scroll.translatesAutoresizingMaskIntoConstraints = false; status.translatesAutoresizingMaskIntoConstraints = false; web.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo:content.leadingAnchor,constant:10),stack.trailingAnchor.constraint(equalTo:content.trailingAnchor,constant:-10),stack.topAnchor.constraint(equalTo:content.topAnchor,constant:10),stack.bottomAnchor.constraint(equalTo:content.bottomAnchor,constant:-10),
            scroll.widthAnchor.constraint(equalTo:stack.widthAnchor),scroll.heightAnchor.constraint(equalToConstant:42),
            status.widthAnchor.constraint(equalTo:stack.widthAnchor),web.widthAnchor.constraint(equalTo:stack.widthAnchor),web.heightAnchor.constraint(greaterThanOrEqualToConstant:300)
        ])
        window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps:true)
        WKContentRuleListStore.default().compileContentRuleList(forIdentifier:"GargoylLoopbackOnly",encodedContentRuleList:resourceRules) { [weak self] list, _ in
            DispatchQueue.main.async {
                guard let self = self, let list = list else { self?.show("Dashboard network isolation unavailable. Display remains blocked."); return }
                self.web.configuration.userContentController.add(list); self.webReady = true; self.refresh()
            }
        }
    }
    @objc func refresh() { if webReady { web.load(URLRequest(url:URL(string:"http://127.0.0.1:8766/")!)) } }
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
    @objc func startMonitor() { if !previewOnly { launch("start-monitor"); refresh() } }
    @objc func stopMonitor() { if !previewOnly { launch("stop-monitor") } }
    @objc func operationStatus() { launch("status") }
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
    @objc func restartProvider() {
        guard !previewOnly, restartWorker == nil, ownerActive() else { show("Restart unavailable: the active Mac owner or an existing operation could not be verified."); return }
        restartButton.isEnabled = false
        restartVerified = false
        do {
            restartWorker = try Worker(mode:"restart",event:{ [weak self] value in self?.restartEvent(value) },finished:{ [weak self] completed in
                guard let self = self, self.restartWorker === completed else { return }
                if completed.process.terminationStatus != 0 || !self.restartVerified { self.show("Restart completion is unverified or was not authorized. No automatic retry. Inspect Operation status before another attempt.") }
                self.context?.invalidate(); self.context = nil; self.approvalTimer?.invalidate(); self.pending = nil; self.approvalGate = nil
                self.restartWorker = nil; self.restartButton.isEnabled = !self.previewOnly
            })
        } catch { restartButton.isEnabled = true; show("Restart unavailable. No provider action was invoked.") }
    }
    func restartEvent(_ value: [String: Any]) {
        guard let kind = value["kind"] as? String else { return }
        if kind == "preview" { review(value) }
        else if kind == "result" {
            if value["state"] as? String == "completed" && value["reason"] as? String == "cli_success_and_replacement_observed" {
                restartVerified = true
                show("Manual restart reported complete; replacement process verified. Protocol health remains unknown."); refresh()
            } else { show("Restart completion is unverified. No retry is permitted. Inspect Operation status.") }
        }
        else if let text = value["text"] as? String { show(text) }
    }
    func review(_ request: [String: Any]) {
        guard ownerActive(), pending == nil, let worker = restartWorker,
              request["policy"] as? String == "native-manual-installation-v1",
              let id = request["request_id"] as? String, id.range(of:"^[a-f0-9]{32}$",options:.regularExpression) != nil,
              let expiry = request["expires_at"] as? Double, expiry >= Date().timeIntervalSince1970, expiry <= Date().timeIntervalSince1970+90,
              let digest = request["preview_digest"] as? String, digest.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil,
              let target = request["target"] as? [String:Any], let process = target["process"] as? [String:Any],
              let pid = process["pid"] as? Int, pid > 0, let birth = process["born_us"] as? Int64,
              process["owner_uid"] as? Int == 501, let version = target["version"] as? String, ["0.10.5","0.10.6"].contains(version)
        else { restartWorker?.reply(request,approved:false); show("Restart preview is unavailable or invalid."); return }
        pending = request
        approvalGate = ApprovalGate(request:id,digest:digest,expires:expiry)
        approvalTimer = Timer.scheduledTimer(withTimeInterval:90,repeats:false) { [weak self] _ in self?.cancelApproval("Confirmation expired. No restart was authorized.") }
        let alert = NSAlert(); alert.messageText = "Restart Darkbloom on MBP-26?"
        alert.informativeText = "Current provider: PID \(pid), birth \(birth), version \(version), owner 501.\nExecutable: ~/.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom\nCommand: restart --timeout 600 --startup-timeout 180 (no force).\n\nThe current provider in this installation will refuse new work, drain accepted work, then restart with existing settings. It may be unavailable while restarting. Darkbloom temporarily disables startup/watchdog, removes recovery history, changes termination allowance and restores configured recovery. Replacement can resume configured coordinator traffic/authorization and existing startup/update behavior. Existing model/settings are reused; no credentials or configuration are supplied. A timeout can leave it draining or disabled. No force or automatic retry is permitted.\n\nThis is installation-scoped consent, not an atomic lock to the displayed process. The target is checked again before execution. One operation may take up to 840 seconds plus cleanup. An uncertain result remains blocked.\n\nThe next step is your Mac’s authentication prompt."
        alert.addButton(withTitle:"Continue to Mac confirmation"); alert.addButton(withTitle:"Cancel")
        consentSheet = alert.window
        alert.beginSheetModal(for:window) { [weak self, weak worker] response in
            guard let self = self, let worker = worker, self.restartWorker === worker, self.pending?["request_id"] as? String == id else { return }
            self.consentSheet = nil
            guard response == .alertFirstButtonReturn, ownerActive() else { self.cancelApproval("Cancelled. No restart was authorized."); return }
            let context = LAContext(); context.touchIDAuthenticationAllowableReuseDuration = 0; context.localizedCancelTitle = "Cancel restart"
            var error: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthentication,error:&error) else { self.cancelApproval("Mac owner authentication is unavailable. Restart remains blocked."); return }
            self.context = context
            context.evaluatePolicy(.deviceOwnerAuthentication,localizedReason:"authorize one manual Darkbloom restart on MBP-26") { success, _ in
                DispatchQueue.main.async {
                    guard self.restartWorker === worker, self.pending?["request_id"] as? String == id else { return }
                    guard var gate = self.approvalGate else { return }
                    let approved = gate.consume(request:id,digest:digest,owner:ownerActive(),authenticated:success,now:Date().timeIntervalSince1970)
                    self.approvalGate = gate
                    guard approved else { self.cancelApproval("Mac confirmation failed or was cancelled. No restart was authorized."); return }
                    self.approvalTimer?.invalidate(); self.context?.invalidate(); self.context = nil
                    self.pending = nil
                    worker.reply(request,approved:true)
                    self.show("Mac owner confirmed. Rechecking the target before one graceful restart. Closing the app will not cancel or retry accepted work.")
                }
            }
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
            return alert.runModal() == .alertSecondButtonReturn ? .terminateNow : .terminateCancel
        }
        return .terminateNow
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { window.makeKeyAndOrderFront(nil); return true }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { return false }
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard allowedNavigation(action.request.url,mainFrame:action.targetFrame?.isMainFrame == true) else { decisionHandler(.cancel); return }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? { return nil }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { show("Monitoring is unavailable. Use Start monitoring; this never starts or restarts Darkbloom. Existing operation outcomes remain separate.") }
}

#if GARGOYL_NATIVE_TESTS
final class ResourceFixture: NSObject, WKNavigationDelegate {
    var finished = false
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { finished = true }
}
if CommandLine.arguments.contains("--self-test") {
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
        let fixture = ResourceFixture(); let page = WKWebView(frame:.zero,configuration:configuration); page.navigationDelegate = fixture
        page.loadHTMLString("<html><img src='\(endpoint)/image'><iframe src='\(endpoint)/frame'></iframe><link rel='stylesheet' href='\(endpoint)/style'></html>",baseURL:URL(string:"http://127.0.0.1:8766/")!)
        let end = Date().addingTimeInterval(5)
        while !fixture.finished && Date() < end { RunLoop.current.run(until:Date().addingTimeInterval(0.01)) }
        precondition(fixture.finished)
    }
    precondition(allowedNavigation(URL(string:"http://127.0.0.1:8766/"),mainFrame:true))
    for value in ["http://localhost:8766/","http://127.0.0.1:8765/","https://127.0.0.1:8766/","http://127.0.0.1:8766/restart","http://127.0.0.1:8766/?action=restart","http://user:pass@127.0.0.1:8766/"] { precondition(!allowedNavigation(URL(string:value),mainFrame:true)) }
    precondition(!allowedNavigation(URL(string:"http://127.0.0.1:8766/"),mainFrame:false))
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
    print("Native navigation and authorization-state fixtures passed; no OS authentication requested.")
    exit(0)
}
#endif
let application = NSApplication.shared
let delegate = App(); application.delegate = delegate
application.run()
"""
