@preconcurrency import RoyalVNCKit
import SwiftUI
import UIKit

/// Another device's screen on iPhone or iPad.
///
/// Tap to click, two-finger tap for a right click, touch and hold then move to
/// drag, one finger alone moves the pointer. Pinch to zoom; two fingers move
/// around a zoomed screen, or scroll when it is not zoomed. The keyboard button
/// types, with Esc, Tab, arrows and the modifier keys above the keyboard.
struct ScreenShareView: View {
    @ObservedObject var session: ScreenShareSession
    var close: () -> Void
    @State private var password = ""
    @State private var keyboard = false

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            FramebufferContainer(session: session, keyboard: $keyboard)
                .ignoresSafeArea()
                .opacity(session.phase == .connected ? 1 : 0.2)
            if session.phase != .connected {
                panel
                    .padding(20)
                    .frame(maxWidth: 440)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
                    .padding(24)
            }
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") {
                    session.disconnect()
                    close()
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    keyboard.toggle()
                } label: {
                    Label("Keyboard", systemImage: keyboard ? "keyboard.chevron.compact.down" : "keyboard")
                }
                .disabled(session.phase != .connected)
            }
        }
        .navigationTitle(session.target.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.visible, for: .navigationBar)
        .onAppear { session.connect() }
        .onDisappear { session.disconnect() }
    }

    @ViewBuilder private var panel: some View {
        VStack(alignment: .leading, spacing: 14) {
            switch session.phase {
            case .connecting:
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Connecting to \(session.target.name)…")
                }
            case .needsCredentials(let needsUser):
                Text(needsUser ? "Sign in to \(session.target.name)" : "Screen sharing password").font(.headline)
                Text(needsUser ? "Use an account on the device that may share its screen." : "The password set for screen sharing on the device.")
                    .font(.callout).foregroundStyle(.secondary)
                if needsUser {
                    TextField("User name", text: $session.user)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(signIn)
                Toggle("Remember the password on this device", isOn: $session.remembersPassword)
                Button("Sign in", action: signIn).buttonStyle(.borderedProminent)
            case .ended(let why):
                Text("Not connected").font(.headline)
                Text(why ?? "The screen sharing session ended.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if session.target.isMac {
                    Text("On the Mac, Screen Sharing must be on: System Settings → General → Sharing.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Button("Connect again") { session.connect() }.buttonStyle(.borderedProminent)
            case .connected:
                EmptyView()
            }
            if let notice = session.notice {
                Label(notice, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange)
            }
        }
    }

    private func signIn() {
        let entered = password
        password = ""
        session.submit(password: entered)
    }
}

/// Draws a VNC framebuffer: its bounds are the framebuffer's pixels, so touch
/// locations in it are framebuffer coordinates. Frames are drawn at most 30
/// times a second, only when something changed.
final class FramebufferDisplay: UIView {
    nonisolated private static let changes = ChangeFlag()
    private var framebuffer: VNCFramebuffer?
    private var link: CADisplayLink?
    private(set) var framebufferSize: CGSize = .zero
    var onSizeChange: ((CGSize) -> Void)?

    nonisolated static func markChanged() { changes.set() }

    func show(_ framebuffer: VNCFramebuffer) {
        self.framebuffer = framebuffer
        if framebufferSize != framebuffer.cgSize {
            framebufferSize = framebuffer.cgSize
            onSizeChange?(framebufferSize)
        }
        Self.changes.set()
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        link?.invalidate()
        link = nil
        guard window != nil else { return }
        let link = CADisplayLink(target: self, selector: #selector(tick))
        link.preferredFrameRateRange = CAFrameRateRange(minimum: 15, maximum: 30, preferred: 30)
        link.add(to: .main, forMode: .common)
        self.link = link
    }

    @objc private func tick() {
        guard Self.changes.take(), let image = framebuffer?.cgImage else { return }
        layer.contents = image
    }

    private final class ChangeFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var changed = false
        func set() { lock.lock(); changed = true; lock.unlock() }
        func take() -> Bool { lock.lock(); defer { lock.unlock() }; let was = changed; changed = false; return was }
    }
}

private struct FramebufferContainer: UIViewRepresentable {
    let session: ScreenShareSession
    @Binding var keyboard: Bool

    func makeCoordinator() -> Coordinator { Coordinator(session: session) }

    func makeUIView(context: Context) -> UIScrollView {
        let coordinator = context.coordinator
        let scroll = UIScrollView()
        scroll.backgroundColor = .black
        scroll.delegate = coordinator
        scroll.bouncesZoom = true
        scroll.showsVerticalScrollIndicator = false
        scroll.showsHorizontalScrollIndicator = false
        scroll.contentInsetAdjustmentBehavior = .never
        // One finger is the pointer; two fingers move around a zoomed screen.
        scroll.panGestureRecognizer.minimumNumberOfTouches = 2
        let display = FramebufferDisplay()
        display.layer.contentsGravity = .resize
        display.layer.magnificationFilter = .linear
        display.isUserInteractionEnabled = true
        scroll.addSubview(display)
        coordinator.scroll = scroll
        coordinator.display = display
        session.display = display
        display.onSizeChange = { [weak coordinator] size in coordinator?.fit(size) }
        coordinator.addGestures(to: display)
        let keys = KeyInputView(session: session)
        scroll.addSubview(keys)
        coordinator.keys = keys
        return scroll
    }

    func updateUIView(_ scroll: UIScrollView, context: Context) {
        let keys = context.coordinator.keys
        if keyboard, keys?.isFirstResponder == false { _ = keys?.becomeFirstResponder() }
        if !keyboard, keys?.isFirstResponder == true { _ = keys?.resignFirstResponder() }
        context.coordinator.fitIfNeeded()
    }

    final class Coordinator: NSObject, UIScrollViewDelegate, UIGestureRecognizerDelegate {
        let session: ScreenShareSession
        weak var scroll: UIScrollView?
        weak var display: FramebufferDisplay?
        weak var keys: KeyInputView?
        private var fittedFor: CGSize = .zero
        private var scrollOrigin: CGPoint = .zero
        private var scrolledSteps = 0

        init(session: ScreenShareSession) { self.session = session }

        func viewForZooming(in scrollView: UIScrollView) -> UIView? { display }

        func scrollViewDidZoom(_ scrollView: UIScrollView) { center() }

        /// Fits the whole screen in view; zooming in goes up to twice its pixels.
        func fit(_ size: CGSize) {
            guard let scroll, let display, size.width > 0, size.height > 0, scroll.bounds.width > 0 else { return }
            fittedFor = scroll.bounds.size
            scroll.zoomScale = 1
            display.frame = CGRect(origin: .zero, size: size)
            scroll.contentSize = size
            let fitScale = min(scroll.bounds.width / size.width, scroll.bounds.height / size.height)
            scroll.minimumZoomScale = fitScale
            scroll.maximumZoomScale = max(fitScale * 6, 2)
            scroll.zoomScale = fitScale
            center()
        }

        func fitIfNeeded() {
            guard let scroll, let display, scroll.bounds.size != fittedFor else { return }
            fit(display.framebufferSize)
        }

        private func center() {
            guard let scroll, let display else { return }
            let x = max((scroll.bounds.width - display.frame.width) / 2, 0)
            let y = max((scroll.bounds.height - display.frame.height) / 2, 0)
            scroll.contentInset = UIEdgeInsets(top: y, left: x, bottom: y, right: x)
        }

        func addGestures(to display: UIView) {
            let tap = UITapGestureRecognizer(target: self, action: #selector(tapped(_:)))
            let doubleTap = UITapGestureRecognizer(target: self, action: #selector(doubleTapped(_:)))
            doubleTap.numberOfTapsRequired = 2
            tap.require(toFail: doubleTap)
            let rightClick = UITapGestureRecognizer(target: self, action: #selector(rightClicked(_:)))
            rightClick.numberOfTouchesRequired = 2
            let drag = UILongPressGestureRecognizer(target: self, action: #selector(dragged(_:)))
            drag.minimumPressDuration = 0.35
            let point = UIPanGestureRecognizer(target: self, action: #selector(pointed(_:)))
            point.maximumNumberOfTouches = 1
            point.require(toFail: drag)
            let wheel = UIPanGestureRecognizer(target: self, action: #selector(scrolled(_:)))
            wheel.minimumNumberOfTouches = 2
            wheel.maximumNumberOfTouches = 2
            wheel.delegate = self
            [tap, doubleTap, rightClick, drag, point, wheel].forEach(display.addGestureRecognizer)
        }

        func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool {
            true
        }

        @objc private func tapped(_ recognizer: UITapGestureRecognizer) {
            guard let display else { return }
            MainActor.assumeIsolated { session.click(at: recognizer.location(in: display)) }
        }

        @objc private func doubleTapped(_ recognizer: UITapGestureRecognizer) {
            guard let display else { return }
            MainActor.assumeIsolated { session.click(at: recognizer.location(in: display), count: 2) }
        }

        @objc private func rightClicked(_ recognizer: UITapGestureRecognizer) {
            guard let display else { return }
            MainActor.assumeIsolated { session.click(at: recognizer.location(in: display), button: .right) }
        }

        @objc private func dragged(_ recognizer: UILongPressGestureRecognizer) {
            guard let display else { return }
            let location = recognizer.location(in: display)
            MainActor.assumeIsolated {
                switch recognizer.state {
                case .began:
                    session.move(to: location)
                    session.press(at: location)
                case .changed:
                    session.move(to: location)
                case .ended, .cancelled, .failed:
                    session.release(at: location)
                default:
                    break
                }
            }
        }

        @objc private func pointed(_ recognizer: UIPanGestureRecognizer) {
            guard let display else { return }
            let location = recognizer.location(in: display)
            MainActor.assumeIsolated { session.move(to: location) }
        }

        /// Two fingers scroll the device's screen while it is not zoomed in.
        @objc private func scrolled(_ recognizer: UIPanGestureRecognizer) {
            guard let display, let scroll, scroll.zoomScale <= scroll.minimumZoomScale + 0.001 else { return }
            switch recognizer.state {
            case .began:
                scrollOrigin = recognizer.location(in: display)
                scrolledSteps = 0
            case .changed:
                let distance = recognizer.translation(in: display).y
                let steps = Int(distance / 24)
                if steps != scrolledSteps {
                    let point = scrollOrigin
                    let delta = steps - scrolledSteps
                    scrolledSteps = steps
                    MainActor.assumeIsolated { session.scroll(at: point, up: delta > 0, steps: abs(delta)) }
                }
            default:
                break
            }
        }
    }
}

/// Takes keyboard input for the shared screen, with a row of keys the iPhone
/// keyboard lacks. Modifier keys stay down for the next key.
final class KeyInputView: UIView, UIKeyInput {
    private let session: ScreenShareSession
    private var held: Set<String> = []
    private lazy var keyRow = makeKeyRow()

    init(session: ScreenShareSession) {
        self.session = session
        super.init(frame: CGRect(x: 0, y: 0, width: 1, height: 1))
        alpha = 0.01
    }

    required init?(coder: NSCoder) { nil }

    override var canBecomeFirstResponder: Bool { true }
    override var inputAccessoryView: UIView? { keyRow }
    var hasText: Bool { true }
    var autocorrectionType: UITextAutocorrectionType { get { .no } set {} }
    var autocapitalizationType: UITextAutocapitalizationType { get { .none } set {} }
    var smartQuotesType: UITextSmartQuotesType { get { .no } set {} }
    var smartDashesType: UITextSmartDashesType { get { .no } set {} }
    var keyboardType: UIKeyboardType { get { .asciiCapable } set {} }

    func insertText(_ text: String) {
        MainActor.assumeIsolated { session.type(text, modifiers: takeModifiers()) }
    }

    func deleteBackward() {
        MainActor.assumeIsolated { session.press(.delete, modifiers: takeModifiers()) }
    }

    private func takeModifiers() -> [VNCKeyCode] {
        let keys = MainActor.assumeIsolated { () -> [VNCKeyCode] in
            var keys: [VNCKeyCode] = []
            if held.contains("ctrl") { keys.append(.control) }
            if held.contains("opt") { keys.append(session.optionKey) }
            if held.contains("cmd") { keys.append(session.commandKey) }
            if held.contains("shift") { keys.append(.shift) }
            return keys
        }
        held.removeAll()
        refreshModifierButtons()
        return keys
    }

    private func makeKeyRow() -> UIView {
        let row = UIInputView(frame: CGRect(x: 0, y: 0, width: 320, height: 44), inputViewStyle: .keyboard)
        let stack = UIStackView()
        stack.axis = .horizontal
        stack.distribution = .fillEqually
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        let keys: [(String, String)] = [("esc", "Esc"), ("tab", "Tab"), ("ctrl", "⌃"), ("opt", "⌥"), ("cmd", "⌘"),
                                        ("shift", "⇧"), ("left", "←"), ("up", "↑"), ("down", "↓"), ("right", "→")]
        for (id, title) in keys {
            let button = UIButton(type: .system)
            button.setTitle(title, for: .normal)
            button.titleLabel?.font = .systemFont(ofSize: 15, weight: .medium)
            button.backgroundColor = .secondarySystemBackground
            button.layer.cornerRadius = 6
            button.accessibilityIdentifier = id
            button.addAction(UIAction { [weak self] _ in self?.tapped(id) }, for: .touchUpInside)
            stack.addArrangedSubview(button)
        }
        row.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: row.leadingAnchor, constant: 6),
            stack.trailingAnchor.constraint(equalTo: row.trailingAnchor, constant: -6),
            stack.topAnchor.constraint(equalTo: row.topAnchor, constant: 5),
            stack.bottomAnchor.constraint(equalTo: row.bottomAnchor, constant: -5),
        ])
        return row
    }

    private func tapped(_ id: String) {
        switch id {
        case "ctrl", "opt", "cmd", "shift":
            if held.contains(id) { held.remove(id) } else { held.insert(id) }
            refreshModifierButtons()
        default:
            let key: VNCKeyCode
            switch id {
            case "esc": key = .escape
            case "tab": key = .tab
            case "left": key = .leftArrow
            case "right": key = .rightArrow
            case "up": key = .upArrow
            default: key = .downArrow
            }
            let modifiers = takeModifiers()
            MainActor.assumeIsolated { session.press(key, modifiers: modifiers) }
        }
    }

    private func refreshModifierButtons() {
        guard let stack = keyRow.subviews.first as? UIStackView else { return }
        for case let button as UIButton in stack.arrangedSubviews {
            let on = held.contains(button.accessibilityIdentifier ?? "")
            button.backgroundColor = on ? .tintColor : .secondarySystemBackground
            button.setTitleColor(on ? .white : .tintColor, for: .normal)
        }
    }
}
