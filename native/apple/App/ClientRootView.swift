import SwiftUI

enum ClientPage: String, CaseIterable, Identifiable {
    case network = "Network", devices = "Devices", settings = "Settings"
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .network: return "network"
        case .devices: return "desktopcomputer"
        case .settings: return "gearshape"
        }
    }
}

struct ClientRootView: View {
    @ObservedObject var controller: TunnelController
    @State private var selection: ClientPage?
    @State private var enrollmentKey = ""

    init(controller: TunnelController, initialPage: ClientPage = .network) {
        self.controller = controller
        _selection = State(initialValue: initialPage)
    }

    var body: some View {
        #if os(macOS)
        NavigationSplitView {
            List(ClientPage.allCases, selection: $selection) { page in
                Label(page.rawValue, systemImage: page.symbol).tag(page)
            }
            .navigationTitle("Covee")
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
            .safeAreaInset(edge: .bottom) {
                HStack(spacing: 8) {
                    Circle().fill(controller.connected ? Color.green : Color.secondary).frame(width: 7, height: 7)
                    Text(controller.statusTitle).font(.caption).foregroundStyle(.secondary)
                    Spacer()
                }.padding()
            }
        } detail: {
            page(selection ?? .network)
        }
        #else
        TabView(selection: $selection) {
            ForEach(ClientPage.allCases) { item in
                NavigationStack { page(item) }
                    .tabItem { Label(item.rawValue, systemImage: item.symbol) }
                    .tag(Optional(item))
            }
        }
        #endif
    }

    @ViewBuilder private func page(_ page: ClientPage) -> some View {
        switch page {
        case .network:
            NetworkView(controller: controller, enrollmentKey: $enrollmentKey)
        case .devices:
            #if os(macOS)
            NavigationStack { DevicesView(controller: controller) }
            #else
            DevicesView(controller: controller)
            #endif
        case .settings:
            SettingsView(controller: controller, enrollmentKey: $enrollmentKey)
        }
    }
}

private struct NetworkView: View {
    @ObservedObject var controller: TunnelController
    @Binding var enrollmentKey: String

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack(alignment: .top, spacing: 16) {
                    Image(systemName: controller.connected ? "checkmark.shield.fill" : "network")
                        .font(.system(size: 36, weight: .medium))
                        .foregroundStyle(controller.connected ? Color.green : Color.accentColor)
                        .frame(width: 64, height: 64)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 16))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(controller.statusTitle).font(.largeTitle.bold())
                        Text(statusDetail).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 0)
                }
                if !controller.active, !controller.savedNetworks.networks.isEmpty {
                    SavedNetworksSection(controller: controller)
                }
                if !controller.active {
                    ConfigurationFields(controller: controller, enrollmentKey: $enrollmentKey)
                }
                HStack {
                    if controller.active {
                        Button("Disconnect", systemImage: "stop.circle") { Task { await controller.disconnect() } }
                            .buttonStyle(.bordered).disabled(controller.isBusy)
                        SwitchNetworkMenu(controller: controller)
                    } else {
                        Button("Connect", systemImage: "arrow.right.circle") { startConnection() }
                            .buttonStyle(.borderedProminent).disabled(controller.isBusy)
                    }
                    if controller.isBusy { ProgressView().controlSize(.small).accessibilityLabel("Preparing connection") }
                }.controlSize(.large)
                if let authenticationURL = controller.authenticationURL {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 10) {
                            Label("Complete sign in", systemImage: "person.crop.circle.badge.checkmark").font(.headline)
                            Text("Your coordinator needs you to approve this device. Return here after signing in.")
                                .foregroundStyle(.secondary)
                            Link("Open coordinator sign in", destination: authenticationURL).buttonStyle(.borderedProminent).controlSize(.large)
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                    }
                }
                OperationFeedback(controller: controller)
                if controller.connected {
                    GroupBox("This device") {
                        VStack(alignment: .leading, spacing: 14) {
                            LabeledContent("Name", value: controller.configuration.hostname)
                            ForEach(controller.providerStatus.ips, id: \.self) { ip in
                                LabeledContent("Overlay address") { Text(ip).font(.system(.body, design: .monospaced)).textSelection(.enabled) }
                            }
                            LabeledContent("Visible devices", value: "\(controller.providerStatus.peers.count)")
                        }.padding(8)
                    }
                    ExitNodeSection(controller: controller)
                    if let console = controller.providerStatus.consoleURL {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 10) {
                                Label("Manage network", systemImage: "slider.horizontal.3").font(.headline)
                                Text("Open this network's admin console. Only devices connected to the network can reach it.")
                                    .foregroundStyle(.secondary)
                                Link("Manage network", destination: console).buttonStyle(.borderedProminent).controlSize(.large)
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
                        }
                    }
                }
            }.padding(24).frame(maxWidth: 720, alignment: .leading).frame(maxWidth: .infinity)
        }
        .navigationTitle("Network")
    }

    private var statusDetail: String {
        if controller.connected { return "Your encrypted network is ready." }
        if controller.active { return "Waiting for the network extension and coordinator." }
        return "Connect this device to your own coordinator."
    }
    private func startConnection() {
        let transientKey = enrollmentKey
        enrollmentKey = ""
        Task { await controller.connect(authKey: transientKey) }
    }
}

/// The networks this device has used, each one tap away.
private struct SavedNetworksSection: View {
    @ObservedObject var controller: TunnelController

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 4) {
                Label("Your networks", systemImage: "list.bullet").font(.headline).padding(.bottom, 6)
                ForEach(controller.savedNetworks.networks) { network in
                    Button { Task { await controller.connect(to: network) } } label: {
                        HStack(spacing: 12) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(network.host).font(.body.weight(.semibold))
                                Text([network.suffix, "as " + network.hostname].compactMap { $0 }.joined(separator: " · "))
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 0)
                            Image(systemName: "arrow.right.circle").foregroundStyle(Color.accentColor)
                        }
                        .padding(.vertical, 6)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(controller.isBusy)
                    .contextMenu {
                        Button("Forget", systemImage: "trash", role: .destructive) { controller.forget(network) }
                    }
                    .accessibilityLabel("Connect to \(network.host)")
                }
                #if os(macOS)
                Text("Control-click a network to forget it.").font(.caption).foregroundStyle(.secondary)
                #else
                Text("Touch and hold a network to forget it.").font(.caption).foregroundStyle(.secondary)
                #endif
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
}

/// Leaves this network for another the device has used.
private struct SwitchNetworkMenu: View {
    @ObservedObject var controller: TunnelController

    var body: some View {
        let others = controller.savedNetworks.networks.filter { $0.controlURL != controller.currentControlURL }
        if !others.isEmpty {
            Menu {
                ForEach(others) { network in
                    Button(network.host) { Task { await controller.connect(to: network) } }
                }
            } label: {
                Label("Switch network", systemImage: "arrow.left.arrow.right")
            }
            .disabled(controller.isBusy)
        }
    }
}

private struct ExitNodeSection: View {
    @ObservedObject var controller: TunnelController

    var body: some View {
        let status = controller.providerStatus
        let choices = status.exitNodeChoices
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Label("Exit node", systemImage: "globe").font(.headline)
                Text(status.currentExitNodeID == nil
                     ? "Internet traffic leaves through this device’s own connection."
                     : "Internet traffic goes through the chosen device. Covee devices stay reachable.")
                    .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Picker("Exit node", selection: selection) {
                        Text("None").tag("")
                        ForEach(choices) { peer in
                            Text(peer.online ? peer.displayName : "\(peer.displayName) (offline)").tag(peer.id)
                        }
                    }
                    .disabled(controller.changingExitNode || status.isOfferingExitNode || (choices.isEmpty && status.currentExitNodeID == nil))
                    if controller.changingExitNode { ProgressView().controlSize(.small).accessibilityLabel("Changing exit node") }
                }
                if status.isOfferingExitNode {
                    Text("This Mac is an exit node for other devices, so it cannot use another one.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                } else if choices.isEmpty {
                    Text("No device in this network offers an exit node. An admin approves exit nodes in the admin console.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Toggle("Allow local network access", isOn: allowLAN)
                    .disabled(controller.changingExitNode || status.currentExitNodeID == nil)
                Text("While using an exit node, keep reaching printers and other devices on this device’s local network.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                #if os(macOS)
                Divider()
                Toggle("Offer this Mac as an exit node", isOn: Binding(get: { controller.providerStatus.isOfferingExitNode }, set: { offer in
                    Task { await controller.setOfferExitNode(offer) }
                }))
                .disabled(controller.changingExitNode || (status.currentExitNodeID != nil && !status.isOfferingExitNode))
                Text(status.exitNodeOfferExplanation)
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                #endif
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }

    private var selection: Binding<String> {
        Binding(get: { controller.providerStatus.currentExitNodeID ?? "" }, set: { id in
            let allowLAN = controller.providerStatus.allowsLANWithExitNode
            Task { await controller.setExitNode(id: id.isEmpty ? nil : id, allowLAN: allowLAN) }
        })
    }
    private var allowLAN: Binding<Bool> {
        Binding(get: { controller.providerStatus.allowsLANWithExitNode }, set: { allow in
            let id = controller.providerStatus.currentExitNodeID
            Task { await controller.setExitNode(id: id, allowLAN: allow) }
        })
    }
}

private struct ConfigurationFields: View {
    @ObservedObject var controller: TunnelController
    @Binding var enrollmentKey: String

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Coordinator").font(.headline)
                TextField("https://network.example.com", text: $controller.configuration.controlURL)
                    .textContentType(.URL)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never).keyboardType(.URL)
                    #endif
                    .textFieldStyle(.roundedBorder)
                    .frame(minHeight: 44)
                    .accessibilityLabel("Coordinator HTTPS address")
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("Device name").font(.headline)
                TextField("my-device", text: $controller.configuration.hostname)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .textFieldStyle(.roundedBorder)
                    .frame(minHeight: 44)
                    .accessibilityLabel("Device name")
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("Enrollment key").font(.headline)
                SecureField("Optional for a device already enrolled", text: $enrollmentKey)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .textFieldStyle(.roundedBorder)
                    .frame(minHeight: 44)
                    .accessibilityLabel("Optional enrollment key")
                Text("Passed to the extension for this connection, then cleared from this form.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }.disabled(controller.active || controller.isBusy)
    }
}

private struct SettingsView: View {
    @ObservedObject var controller: TunnelController
    @Binding var enrollmentKey: String
    @State private var showsAcknowledgements = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Text("Your network, your coordinator.").font(.title2.bold())
                ConfigurationFields(controller: controller, enrollmentKey: $enrollmentKey)
                Button("Save settings") { controller.saveSettings() }
                    .buttonStyle(.bordered).controlSize(.large).disabled(controller.active || controller.isBusy)
                if controller.active { Text("Disconnect before changing coordinator or device name.").font(.callout).foregroundStyle(.secondary) }
                OperationFeedback(controller: controller)
                Divider()
                VStack(alignment: .leading, spacing: 8) {
                    Label("Connection settings", systemImage: "lock.shield").font(.headline)
                    Text("Only the coordinator address and device name are saved here. The network extension keeps this device’s network identity in its own Keychain.")
                        .foregroundStyle(.secondary)
                    Toggle("Use the network’s gateway", isOn: Binding(get: { controller.usesGatewayRoutes }, set: { accept in
                        Task { await controller.setAcceptRoutes(accept) }
                    })).disabled(controller.changingExitNode)
                    Text("On: reach what your network’s admin sends through its gateway, such as private cloud networks, and local networks other devices share. Off: only the devices in your network. Choose an internet exit node on the Network page while connected.")
                        .font(.callout).foregroundStyle(.secondary)
                    Text("Covee stays connected. If the connection stops for any reason but Disconnect, it starts again by itself.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                ConnectionHistoryView(status: controller.providerStatus)
                Divider()
                RemoteAccessSettings(hostname: controller.configuration.hostname)
                Divider()
                Button("Open-source software") { showsAcknowledgements = true }
                    .buttonStyle(.borderless)
            }.padding(24).frame(maxWidth: 720, alignment: .leading).frame(maxWidth: .infinity)
        }
        .navigationTitle("Settings")
        .sheet(isPresented: $showsAcknowledgements) { AcknowledgementsView { showsAcknowledgements = false } }
    }
}

/// Covee's SSH key, for adding it to a device by hand.
private struct RemoteAccessSettings: View {
    let hostname: String
    @State private var copied = false
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Terminal and screen sharing", systemImage: "terminal").font(.headline)
            Text("Open a device under Devices to start a terminal on it or share its screen. Covee signs in over SSH with a key made on this device and kept in its Secure Enclave, where it has one. Servers running Tailscale SSH let you in with your network identity instead.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Button(copied ? "Copied" : "Copy Covee's SSH key", systemImage: "key") { copyKey() }
                .buttonStyle(.bordered)
            Text("Add it to ~/.ssh/authorized_keys on a device to sign in without a password. Covee can also install it for you after you sign in once with a password.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let problem { Text(problem).font(.caption).foregroundStyle(.red) }
        }
    }

    private func copyKey() {
        do {
            let line = try SSHIdentity.authorizedKeysLine(deviceName: hostname.isEmpty ? "device" : hostname)
            #if os(iOS)
            UIPasteboard.general.string = line
            #else
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(line, forType: .string)
            #endif
            copied = true
            problem = nil
        } catch {
            problem = error.localizedDescription
        }
    }
}

/// The licenses of the open-source software in Covee.
private struct AcknowledgementsView: View {
    var close: () -> Void
    private let text: String = {
        guard let url = Bundle.main.url(forResource: "Acknowledgements", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return "The license list is missing from this build." }
        return text
    }()

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(text)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .navigationTitle("Open-source software")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done", action: close) } }
        }
        #if os(macOS)
        .frame(minWidth: 620, minHeight: 520)
        #endif
    }
}

/// How recent connections started and ended, newest first, while the network
/// extension runs and can tell.
private struct ConnectionHistoryView: View {
    let status: ProviderStatus

    var body: some View {
        if let history = status.history, !history.isEmpty {
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                Label("Connection history", systemImage: "clock.arrow.circlepath").font(.headline)
                ForEach(history.reversed()) { event in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(event.date?.formatted(date: .abbreviated, time: .shortened) ?? event.at)
                            .font(.caption).foregroundStyle(.secondary)
                        Text(event.text).font(.callout).fixedSize(horizontal: false, vertical: true)
                    }
                }
                if let memory = status.memoryMB {
                    Text("Covee’s network extension uses \(memory) MB of memory now.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

private struct OperationFeedback: View {
    @ObservedObject var controller: TunnelController
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let message = controller.operationMessage {
                Label(message, systemImage: "info.circle").foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if let error = controller.errorMessage {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
                    .accessibilityLabel("Error: \(error)")
            }
        }
    }
}

private struct DevicesView: View {
    @ObservedObject var controller: TunnelController
    var body: some View {
        Group {
            if !controller.connected {
                ContentUnavailableView("Connect to see devices", systemImage: "network", description: Text("Devices appear after the network extension has connected to your coordinator."))
            } else if controller.providerStatus.peers.isEmpty {
                ContentUnavailableView("No visible devices", systemImage: "desktopcomputer", description: Text("Your coordinator has not shared any other devices with this device."))
            } else {
                List(controller.providerStatus.peers) { peer in
                    NavigationLink { DeviceDetailView(peerID: peer.id, controller: controller) } label: { DeviceRow(peer: peer) }
                }
                .refreshable { await controller.refreshStatus() }
            }
        }.navigationTitle("Devices")
    }
}

private struct DeviceRow: View {
    let peer: PeerStatus
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: peer.os?.lowercased() == "ios" ? "iphone" : "desktopcomputer").foregroundStyle(.secondary).frame(width: 28)
            VStack(alignment: .leading, spacing: 5) {
                Text(peer.name).font(.headline)
                Text(peer.ips.joined(separator: " · ")).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                if !peer.subnetRoutes.isEmpty {
                    Text("Local networks: " + peer.subnetRoutes.joined(separator: " · ")).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                }
                if peer.exitNode == true {
                    Label("Exit node in use", systemImage: "globe").font(.caption).foregroundStyle(.secondary)
                } else if peer.offersExitNode {
                    Label("Offers an exit node", systemImage: "globe").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Label(peer.online ? "Online" : "Offline", systemImage: peer.online ? "circle.fill" : "circle")
                .font(.caption).foregroundStyle(peer.online ? Color.green : Color.secondary)
        }.padding(.vertical, 8)
    }
}
