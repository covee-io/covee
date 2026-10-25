import SwiftTerm
import SwiftUI

/// A terminal on a device: the terminal itself, with whatever the person must
/// answer before or after signing in laid over it.
struct TerminalScreen: View {
    @ObservedObject var session: TerminalSession
    var close: () -> Void
    @State private var password = ""
    @FocusState private var focused: Field?

    private enum Field { case user, password }

    var body: some View {
        ZStack {
            TerminalHost(session: session)
                .opacity(session.phase == .connected ? 1 : 0.25)
                .ignoresSafeArea(.container, edges: .bottom)
            if session.phase != .connected {
                panel
                    .padding(20)
                    .frame(maxWidth: 460)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
                    .padding(24)
            }
        }
        .safeAreaInset(edge: .top) {
            if session.offersKeyInstall || session.notice != nil, session.phase == .connected {
                banner
            }
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") {
                    session.close()
                    close()
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("Reconnect", systemImage: "arrow.clockwise") { session.reconnect() }
                    Button("Copy Covee's SSH key", systemImage: "key") { copyKey() }
                } label: {
                    Label("More", systemImage: "ellipsis.circle")
                }
            }
        }
        .navigationTitle(session.title)
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }

    @ViewBuilder private var panel: some View {
        VStack(alignment: .leading, spacing: 14) {
            switch session.phase {
            case .needsUser:
                Text("Sign in to \(session.target.name)").font(.headline)
                Text(session.target.hasNetworkSSH
                     ? "This device lets you in with your network identity: no key or password."
                     : "The user to sign in as on the device.")
                    .font(.callout).foregroundStyle(.secondary)
                TextField("User name", text: $session.user)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .focused($focused, equals: .user)
                    .onSubmit { session.start() }
                Button("Connect") { session.start() }
                    .buttonStyle(.borderedProminent)
            case .connecting(let what):
                HStack(spacing: 10) {
                    ProgressView()
                    Text(what)
                }
            case .trustHostKey(let fingerprint):
                Text("First connection to \(session.target.name)").font(.headline)
                Text("Covee has not seen this device's SSH identity before. Trust it if it belongs to the device; Covee warns you if it ever changes.")
                    .font(.callout).foregroundStyle(.secondary)
                Text(fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                HStack {
                    Button("Trust and connect") { session.answerTrust(true) }.buttonStyle(.borderedProminent)
                    Button("Cancel") { session.answerTrust(false) }
                }
            case .needsPassword:
                Text("Password for \(session.user)").font(.headline)
                Text("\(session.target.name) did not accept Covee's key yet. Sign in with the password once, and Covee offers to install its key so you won't need it again.")
                    .font(.callout).foregroundStyle(.secondary)
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused, equals: .password)
                    .onSubmit(signInWithPassword)
                HStack {
                    Button("Sign in", action: signInWithPassword).buttonStyle(.borderedProminent)
                    Button("Change user") { session.close(); session.user = ""; session.start() }
                }
            case .ended(let why):
                Text(why == nil ? "The session ended." : "Not connected").font(.headline)
                if let why { Text(why).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                HStack {
                    Button("Connect again") { session.start() }.buttonStyle(.borderedProminent)
                    if session.hostKeyChanged {
                        Button("Forget the old identity") { session.forgetHostKeyAndReconnect() }
                    }
                }
            case .connected:
                EmptyView()
            }
            if let notice = session.notice, session.phase != .connected {
                Label(notice, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange)
            }
        }
        .onAppear { focused = session.phase == .needsUser ? .user : nil }
        .onChange(of: session.phase) { _, phase in
            focused = phase == .needsPassword ? .password : (phase == .needsUser ? .user : nil)
        }
    }

    @ViewBuilder private var banner: some View {
        HStack(spacing: 12) {
            if session.offersKeyInstall {
                Text("Install Covee's key on \(session.target.name), so next time needs no password?").font(.callout)
                Spacer(minLength: 8)
                Button("Install") { Task { await session.installKey() } }.buttonStyle(.borderedProminent)
                Button("Not now") { session.declineKeyInstall() }
            } else if let notice = session.notice {
                Text(notice).font(.callout)
                Spacer(minLength: 0)
            }
        }
        .padding(12)
        .background(.bar)
    }

    private func signInWithPassword() {
        let entered = password
        password = ""
        session.submitPassword(entered)
    }

    private func copyKey() {
        guard let line = session.coveeKeyLine() else { return }
        #if os(iOS)
        UIPasteboard.general.string = line
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(line, forType: .string)
        #endif
    }
}

#if os(iOS)
/// SwiftTerm's terminal, fed by the session.
private struct TerminalHost: UIViewRepresentable {
    let session: TerminalSession

    func makeCoordinator() -> TerminalBridge { TerminalBridge(session: session) }

    func makeUIView(context: Context) -> SwiftTerm.TerminalView {
        let view = SwiftTerm.TerminalView(frame: .zero)
        view.terminalDelegate = context.coordinator
        view.backgroundColor = .black
        session.attach { [weak view] bytes in view?.feed(byteArray: bytes[...]) }
        return view
    }

    func updateUIView(_ view: SwiftTerm.TerminalView, context: Context) {
        if session.phase == .connected, !view.isFirstResponder { _ = view.becomeFirstResponder() }
    }
}
#else
private struct TerminalHost: NSViewRepresentable {
    let session: TerminalSession

    func makeCoordinator() -> TerminalBridge { TerminalBridge(session: session) }

    func makeNSView(context: Context) -> SwiftTerm.TerminalView {
        let view = SwiftTerm.TerminalView(frame: NSRect(x: 0, y: 0, width: 800, height: 500))
        view.terminalDelegate = context.coordinator
        session.attach { [weak view] bytes in view?.feed(byteArray: bytes[...]) }
        return view
    }

    func updateNSView(_ view: SwiftTerm.TerminalView, context: Context) {
        if session.phase == .connected, view.window?.firstResponder !== view { view.window?.makeFirstResponder(view) }
    }
}
#endif

/// Passes what the person types to the session, and the terminal's size and title changes.
final class TerminalBridge: NSObject, TerminalViewDelegate {
    private let session: TerminalSession
    init(session: TerminalSession) { self.session = session }

    func send(source: SwiftTerm.TerminalView, data: ArraySlice<UInt8>) {
        MainActor.assumeIsolated { session.send(data) }
    }

    func sizeChanged(source: SwiftTerm.TerminalView, newCols: Int, newRows: Int) {
        MainActor.assumeIsolated { session.resize(columns: newCols, rows: newRows) }
    }

    func setTerminalTitle(source: SwiftTerm.TerminalView, title: String) {
        MainActor.assumeIsolated { session.setTitle(title) }
    }

    func hostCurrentDirectoryUpdate(source: SwiftTerm.TerminalView, directory: String?) {}
    func scrolled(source: SwiftTerm.TerminalView, position: Double) {}
    func rangeChanged(source: SwiftTerm.TerminalView, startY: Int, endY: Int) {}

    func requestOpenLink(source: SwiftTerm.TerminalView, link: String, params: [String: String]) {
        guard let url = URL(string: link), url.scheme == "https" || url.scheme == "http" else { return }
        #if os(iOS)
        UIApplication.shared.open(url)
        #else
        NSWorkspace.shared.open(url)
        #endif
    }
}
