import UIKit
import WebKit

/// Full-screen app that opens the OldWeb gateway running on your PC (port 8106 only).
///
/// - First start: uses http://oldweb.local:8106 (works on the same Wi-Fi / hotspot as the PC).
/// - Can't reach the PC: a box lets you Retry or type the PC address (e.g. 192.168.1.20).
/// - Change the address any time: hold THREE fingers on the screen for 1 second.
final class WebViewController: UIViewController, WKNavigationDelegate, WKUIDelegate, UIGestureRecognizerDelegate {

    static let port = 8106
    static let defaultAddress = "http://oldweb.local:8106"
    private static let addressKey = "serverAddress"

    private var webView: WKWebView!

    private var address: String {
        get { UserDefaults.standard.string(forKey: Self.addressKey) ?? Self.defaultAddress }
        set { UserDefaults.standard.set(newValue, forKey: Self.addressKey) }
    }

    // MARK: - Setup

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        config.websiteDataStore = .default() // keeps the gateway's cookies (your tab + password)

        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.backgroundColor = .black
        webView.scrollView.backgroundColor = .black
        webView.scrollView.bounces = false
        webView.allowsLinkPreview = false
        webView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(webView)

        let safe = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            webView.leadingAnchor.constraint(equalTo: safe.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: safe.trailingAnchor),
            webView.topAnchor.constraint(equalTo: safe.topAnchor),
            webView.bottomAnchor.constraint(equalTo: safe.bottomAnchor),
        ])

        let hold = UILongPressGestureRecognizer(target: self, action: #selector(threeFingerHold(_:)))
        hold.numberOfTouchesRequired = 3
        hold.minimumPressDuration = 1.0
        hold.cancelsTouchesInView = false
        hold.delegate = self
        webView.addGestureRecognizer(hold)

        loadServer()
    }

    override var preferredStatusBarStyle: UIStatusBarStyle { .lightContent }
    override var prefersHomeIndicatorAutoHidden: Bool { true }

    // MARK: - Address

    /// Turns "192.168.1.20", "oldweb.local" or "http://x:80" into "http://<host>:8106/".
    static func normalized(_ text: String) -> URL? {
        var t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { t = defaultAddress }
        if !t.lowercased().hasPrefix("http://") && !t.lowercased().hasPrefix("https://") {
            t = "http://" + t
        }
        guard var c = URLComponents(string: t), let host = c.host, !host.isEmpty else { return nil }
        c.port = port // always 8106
        if c.path.isEmpty { c.path = "/" }
        return c.url
    }

    private func loadServer() {
        guard let url = Self.normalized(address) else {
            askForAddress(message: "That address is not valid. Type the address of your PC.")
            return
        }
        let req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        webView.load(req)
    }

    @objc private func threeFingerHold(_ g: UILongPressGestureRecognizer) {
        if g.state == .began { askForAddress(message: "Address of your PC (port \(Self.port) is added by itself).") }
    }

    func gestureRecognizer(_ g: UIGestureRecognizer,
                           shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool { true }

    private func askForAddress(message: String) {
        guard presentedViewController == nil else { return }
        let a = UIAlertController(title: "OldWeb", message: message, preferredStyle: .alert)
        a.addTextField { [weak self] f in
            f.text = self?.address
            f.placeholder = "192.168.1.20 or oldweb.local"
            f.keyboardType = .URL
            f.autocorrectionType = .no
            f.autocapitalizationType = .none
            f.clearButtonMode = .whileEditing
        }
        a.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        a.addAction(UIAlertAction(title: "Use default", style: .default) { [weak self] _ in
            self?.address = Self.defaultAddress
            self?.loadServer()
        })
        a.addAction(UIAlertAction(title: "Connect", style: .default) { [weak self, weak a] _ in
            guard let self = self else { return }
            let typed = a?.textFields?.first?.text ?? ""
            if let url = Self.normalized(typed) { self.address = url.absoluteString }
            self.loadServer()
        })
        present(a, animated: true)
    }

    private func showCannotConnect(_ error: Error) {
        guard presentedViewController == nil else { return }
        let a = UIAlertController(
            title: "Can't reach your PC",
            message: "Tried \(Self.normalized(address)?.absoluteString ?? address)\n\n"
                + "Is start.bat running on the PC, and is this phone on the same Wi-Fi or hotspot?\n\n"
                + "(\(error.localizedDescription))",
            preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "Change address", style: .default) { [weak self] _ in
            self?.askForAddress(message: "Address of your PC (port \(Self.port) is added by itself).")
        })
        a.addAction(UIAlertAction(title: "Retry", style: .cancel) { [weak self] _ in
            self?.loadServer()
        })
        present(a, animated: true)
    }

    // MARK: - WKNavigationDelegate

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = action.request.url, let scheme = url.scheme?.lowercased() else {
            decisionHandler(.allow); return
        }
        if ["http", "https", "about", "blob", "data"].contains(scheme) {
            decisionHandler(.allow)
        } else {
            // mailto:, tel:, sms:, bankid:, maps: ... -> open the real app on the iPhone
            UIApplication.shared.open(url, options: [:], completionHandler: nil)
            decisionHandler(.cancel)
        }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        handle(error)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        handle(error)
    }

    private func handle(_ error: Error) {
        let e = error as NSError
        if e.domain == NSURLErrorDomain && e.code == NSURLErrorCancelled { return } // a new page replaced it
        if e.domain == "WebKitErrorDomain" && (e.code == 102 || e.code == 204) { return } // frame interrupted / plug-in
        showCannotConnect(error)
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        loadServer() // WebKit crashed or was killed for memory: start again
    }

    // MARK: - WKUIDelegate

    /// target=_blank / window.open: open in the same view.
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if action.targetFrame == nil { webView.load(action.request) }
        return nil
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler() })
        present(a, animated: true)
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let a = UIAlertController(title: nil, message: message, preferredStyle: .alert)
        a.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completionHandler(false) })
        a.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler(true) })
        present(a, animated: true)
    }
}
