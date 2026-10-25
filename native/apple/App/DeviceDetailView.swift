import SwiftUI
#if os(macOS)
import AppKit
#endif

/// One device in the network: its addresses, a terminal on it, and its screen.
struct DeviceDetailView: View {
    let peerID: String
    @ObservedObject var controller: TunnelController
    @State private var sshAnswers: Bool?
    @State private var screenAnswers: Bool?
    #if os(iOS)
    @State private var terminal: TerminalSession?
    @State private var screen: ScreenShareSession?
    #else
    @Environment(\.openWindow) private var openWindow
    #endif

    private var peer: PeerStatus? { controller.providerStatus.peers.first { $0.id == peerID } }

    var body: some View {
        Group {
            if let peer {
                details(peer)
            } else {
                ContentUnavailableView("Not visible", systemImage: "desktopcomputer",
                                       description: Text("This device is not visible from here right now."))
            }
        }
        .task(id: peerID) { await probe() }
        #if os(iOS)
        .fullScreenCover(item: $terminal) { session in
            NavigationStack { TerminalScreen(session: session) { terminal = nil } }
        }
        .fullScreenCover(item: $screen) { session in
            NavigationStack { ScreenShareView(session: session) { screen = nil } }
        }
        #endif
    }

    private func details(_ peer: PeerStatus) -> some View {
        let target = RemoteTarget(peer: peer)
        return Form {
            Section {
                LabeledContent("Status", value: peer.online ? "Online" : "Offline")
                if let os = peer.os, !os.isEmpty { LabeledContent("System", value: os) }
                LabeledContent("Name") { Text(peer.name).textSelection(.enabled) }
                ForEach(peer.ips, id: \.self) { ip in
                    LabeledContent("Address") { Text(ip).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
                }
            }
            if target.canBeReached {
                Section("Connect") {
                    VStack(alignment: .leading, spacing: 4) {
                        Button { openTerminal(target) } label: { Label("Open terminal", systemImage: "terminal") }
                            .disabled(!peer.online)
                        Text(sshCaption(target)).font(.caption).foregroundStyle(.secondary)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Button { shareScreen(target) } label: { Label("Share screen", systemImage: "display") }
                            .disabled(!peer.online)
                        Text(screenCaption(target)).font(.caption).foregroundStyle(.secondary)
                    }
                }
            } else {
                Section {
                    Text("An iPhone or iPad can't be reached with a terminal or screen sharing.").foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(peer.displayName)
    }

    private func sshCaption(_ target: RemoteTarget) -> String {
        if target.hasNetworkSSH { return "Signs in with your network identity: no key or password." }
        if sshAnswers == false {
            return target.isMac ? "SSH is off. On the Mac, turn on Remote Login: System Settings → General → Sharing."
                                : "Nothing answers on the SSH port (22)."
        }
        return "Signs in with Covee's key, or with a password the first time."
    }

    private func screenCaption(_ target: RemoteTarget) -> String {
        if screenAnswers == false {
            return target.isMac ? "Screen sharing is off. On the Mac, turn on Screen Sharing: System Settings → General → Sharing."
                                : "Nothing answers on the screen sharing port (5900)."
        }
        #if os(macOS)
        return "Opens in macOS Screen Sharing."
        #else
        return "Opens here, full screen."
        #endif
    }

    private func probe() async {
        guard let peer, peer.online else { return }
        let target = RemoteTarget(peer: peer)
        guard target.canBeReached else { return }
        async let ssh = PortProbe.isOpen(host: target.address, port: 22)
        async let screen = PortProbe.isOpen(host: target.address, port: 5900)
        let (sshOpen, screenOpen) = await (ssh, screen)
        sshAnswers = sshOpen
        screenAnswers = screenOpen
    }

    private func openTerminal(_ target: RemoteTarget) {
        #if os(iOS)
        terminal = TerminalSession(target: target, localName: controller.configuration.hostname)
        #else
        openWindow(id: "terminal", value: target)
        #endif
    }

    private func shareScreen(_ target: RemoteTarget) {
        #if os(iOS)
        screen = ScreenShareSession(target: target)
        #else
        if let url = URL(string: "vnc://" + target.address) { NSWorkspace.shared.open(url) }
        #endif
    }
}

extension TerminalSession: Identifiable {}

#if os(iOS)
extension ScreenShareSession: Identifiable {}
#else
/// A terminal window on a Mac.
struct TerminalWindow: View {
    @StateObject private var session: TerminalSession
    @Environment(\.dismissWindow) private var dismissWindow

    init(target: RemoteTarget, localName: String) {
        _session = StateObject(wrappedValue: TerminalSession(target: target, localName: localName))
    }

    var body: some View {
        NavigationStack {
            TerminalScreen(session: session) { dismissWindow() }
        }
        .frame(minWidth: 520, minHeight: 320)
        .onDisappear { session.close() }
    }
}
#endif
