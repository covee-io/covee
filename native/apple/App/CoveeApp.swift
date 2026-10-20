import SwiftUI
#if os(macOS)
import AppKit
import ServiceManagement
#endif

@main
struct CoveeApp: App {
    @StateObject private var controller = TunnelController()

    var body: some Scene {
        #if os(macOS)
        WindowGroup(id: "main") {
            ClientRootView(controller: controller)
                .frame(minWidth: 760, minHeight: 600)
        }
        .defaultSize(width: 900, height: 680)
        MenuBarExtra {
            MenuStatusView(controller: controller)
        } label: {
            // The Covee mark, full when connected and faded otherwise (template images follow the menu bar's colour).
            Image(controller.connected ? "MenuBarOn" : "MenuBarOff")
                .renderingMode(.template)
                .accessibilityLabel("Covee: \(controller.statusTitle)")
        }
        Settings {
            ClientRootView(controller: controller, initialPage: .settings)
                .frame(width: 720, height: 600)
        }
        #else
        WindowGroup {
            ClientRootView(controller: controller)
        }
        #endif
    }
}

#if os(macOS)
/// The menu under the Covee mark in the menu bar, like Tailscale's.
private struct MenuStatusView: View {
    @ObservedObject var controller: TunnelController
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openURL) private var openURL
    @State private var startsAtLogin = SMAppService.mainApp.status == .enabled

    var body: some View {
        Text(controller.statusTitle)
        if let host = URL(string: controller.configuration.controlURL)?.host(), !host.isEmpty {
            Text(host).foregroundStyle(.secondary)
        }
        if controller.connected {
            Divider()
            Button("This device: \(controller.configuration.hostname)") { copy(controller.providerStatus.ips.first) }
            if let ip = controller.providerStatus.ips.first {
                Button("\(ip)  (click to copy)") { copy(ip) }
            }
        }
        Divider()
        if controller.active {
            Button("Disconnect") { controller.disconnect() }.disabled(controller.isBusy)
        } else {
            Button("Connect") {
                if (try? controller.configuration.validated()) == nil { show() }
                else { Task { await controller.connect(authKey: "") } }
            }.disabled(controller.isBusy)
        }
        if let signIn = controller.authenticationURL {
            Button("Complete sign in…") { openURL(signIn) }
        }
        if let console = controller.providerStatus.consoleURL {
            Button("Manage network…") { openURL(console) }
        }
        if controller.connected {
            Menu("Devices") {
                let peers = controller.providerStatus.peers.sorted { $0.displayName < $1.displayName }
                if peers.isEmpty {
                    Text("No other devices you can reach")
                }
                ForEach(peers) { peer in
                    Button("\(peer.online ? "●" : "○")  \(peer.displayName)  \(peer.ips.first ?? "")") { copy(peer.ips.first) }
                }
                if !peers.isEmpty {
                    Divider()
                    Text("Click a device to copy its address")
                }
            }
            Menu("Exit node") {
                let status = controller.providerStatus
                Picker("Exit node", selection: exitNodeSelection) {
                    Text("None").tag("")
                    ForEach(status.exitNodeChoices) { peer in
                        Text(peer.online ? peer.displayName : "\(peer.displayName) (offline)").tag(peer.id)
                    }
                }.pickerStyle(.inline).labelsHidden().disabled(status.isOfferingExitNode)
                if status.exitNodeChoices.isEmpty {
                    Text("No device in this network offers one")
                }
                Divider()
                Toggle("Allow local network access", isOn: Binding(get: { status.allowsLANWithExitNode }, set: { allow in
                    Task { await controller.setExitNode(id: status.currentExitNodeID, allowLAN: allow) }
                })).disabled(status.currentExitNodeID == nil)
                Divider()
                Toggle("Offer this Mac as an exit node", isOn: Binding(get: { status.isOfferingExitNode }, set: { offer in
                    Task { await controller.setOfferExitNode(offer) }
                })).disabled(status.currentExitNodeID != nil && !status.isOfferingExitNode)
                if status.isOfferingExitNode {
                    Text(status.isServingAsExitNode ? "Approved: other devices can use this Mac" : "Waiting for approval in the admin console")
                }
            }.disabled(controller.changingExitNode)
        }
        Toggle("Use the network’s gateway", isOn: Binding(get: { controller.usesGatewayRoutes }, set: { accept in
            Task { await controller.setAcceptRoutes(accept) }
        })).disabled(controller.changingExitNode)
        Divider()
        Toggle("Start at login", isOn: Binding(get: { startsAtLogin }, set: { setStartsAtLogin($0) }))
        Button("Open Covee") { show() }
        Divider()
        Button("Quit Covee") { NSApplication.shared.terminate(nil) }
    }

    private func show() {
        openWindow(id: "main")
        NSApplication.shared.activate()
    }

    private func copy(_ text: String?) {
        guard let text, !text.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private var exitNodeSelection: Binding<String> {
        Binding(get: { controller.providerStatus.currentExitNodeID ?? "" }, set: { id in
            let allowLAN = controller.providerStatus.allowsLANWithExitNode
            Task { await controller.setExitNode(id: id.isEmpty ? nil : id, allowLAN: allowLAN) }
        })
    }

    private func setStartsAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            // macOS may ask for approval in System Settings > General > Login Items; reflect the real state.
        }
        startsAtLogin = SMAppService.mainApp.status == .enabled
    }
}
#endif
