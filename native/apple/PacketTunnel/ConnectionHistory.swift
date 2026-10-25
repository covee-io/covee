import Foundation
import NetworkExtension
import Darwin
import os

private let historyLog = Logger(subsystem: "io.covee.tunnel", category: "history")

/// How this device's recent connections started and ended, kept by the network
/// extension in its own container and shown in the app's settings, so that a
/// dropped connection says why. A running connection also leaves a mark, with
/// the most memory it used, that it renews as it runs. A mark still there at the
/// next start means the system ended the extension without stopping it, as it
/// does when the extension uses more memory than allowed.
final class ConnectionHistory {
    struct Event: Codable, Equatable {
        let at: Date
        let text: String
    }
    private struct Running: Codable {
        var lastSeen: Date
        var peakMemoryMB: Int?
        var build: String?
    }
    private struct Record: Codable {
        var events: [Event] = []
        var running: Running?
    }

    /// How many events are kept, and how soon the same note may repeat.
    static let kept = 30
    static let repeatAfter: TimeInterval = 600

    private let lock = NSLock()
    private let file: URL?
    private let now: () -> Date
    private let bootTime: () -> Date?
    private let build: String?
    private var record = Record()
    private var lastSave = Date.distantPast

    init(file: URL? = ConnectionHistory.defaultFile, now: @escaping () -> Date = Date.init,
         bootTime: @escaping () -> Date? = systemBootTime,
         build: String? = Bundle.main.infoDictionary?["CFBundleVersion"] as? String) {
        self.file = file
        self.now = now
        self.bootTime = bootTime
        self.build = build
        if let file, let data = try? Data(contentsOf: file), let saved = try? JSONDecoder().decode(Record.self, from: data) {
            record = saved
        }
    }

    static var defaultFile: URL? {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("connection-history.json")
    }

    var events: [Event] {
        lock.lock()
        defer { lock.unlock() }
        return record.events
    }

    /// A connection starts: from the app, or from the system reconnecting by itself.
    func started(byApp: Bool) {
        lock.lock()
        defer { lock.unlock() }
        if let previous = record.running {
            if let boot = bootTime(), boot > previous.lastSeen {
                append("The connection ended when the device restarted.", at: previous.lastSeen)
            } else if previous.build != build {
                append("The connection ended for a Covee update.", at: previous.lastSeen)
            } else {
                var text = "The connection was cut off: the system ended Covee's network extension without stopping it"
                if let peak = previous.peakMemoryMB { text += " (it had used up to \(peak) MB)" }
                append(text + ". That usually means it needed more memory than the system allows, or it crashed.", at: previous.lastSeen)
            }
        }
        append(byApp ? "Connected from the Covee app." : "Started by the system: reconnecting by itself, or from Settings.")
        record.running = Running(lastSeen: now(), peakMemoryMB: nil, build: build)
        save()
    }

    /// Memory above which a note is kept: the system ends a network extension at 50 MB.
    static let highMemoryMB = 40

    /// The running connection is still alive and uses this much memory. The
    /// mark is saved once a minute, and at once when memory rose by 5 MB, so
    /// the last peak survives the system ending the extension.
    func alive(memoryMB: Int?) {
        lock.lock()
        defer { lock.unlock() }
        guard var running = record.running else { return }
        let time = now()
        let before = running.peakMemoryMB ?? 0
        running.lastSeen = time
        if let memoryMB { running.peakMemoryMB = max(before, memoryMB) }
        record.running = running
        if let memoryMB, memoryMB >= Self.highMemoryMB {
            noteLocked("Memory use went over \(Self.highMemoryMB) MB; the system ends the connection at 50 MB.", at: time)
        }
        if time.timeIntervalSince(lastSave) >= 60 || (running.peakMemoryMB ?? 0) >= before + 5 {
            lastSave = time
            save()
        }
    }

    /// The system stopped the connection.
    func stopped(_ reason: NEProviderStopReason) {
        lock.lock()
        defer { lock.unlock() }
        // A connection that stopped itself has already said why.
        guard record.running != nil else { return }
        record.running = nil
        append(Self.describe(reason))
        save()
    }

    /// The connection stopped itself after a problem.
    func failed(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        record.running = nil
        append("Stopped after a problem: " + message)
        save()
    }

    /// A problem the connection kept running through.
    func note(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        noteLocked(message, at: now())
    }

    private func noteLocked(_ message: String, at time: Date) {
        if let last = record.events.last(where: { $0.text == message }), time.timeIntervalSince(last.at) < Self.repeatAfter { return }
        append(message, at: time)
        save()
    }

    /// The newest events, oldest first, as the app receives them.
    func recent(_ count: Int) -> [[String: String]] {
        lock.lock()
        defer { lock.unlock() }
        let formatter = ISO8601DateFormatter()
        return record.events.suffix(count).map { ["at": formatter.string(from: $0.at), "text": $0.text] }
    }

    static func describe(_ reason: NEProviderStopReason) -> String {
        switch reason {
        case .userInitiated: return "Disconnected by you, in Covee or in Settings."
        case .superceded: return "Another VPN took over. The device runs one VPN at a time."
        case .noNetworkAvailable: return "Stopped by the system: no network was available."
        case .unrecoverableNetworkChange: return "Stopped by the system after a network change."
        case .sleep: return "Stopped by the system while the device slept."
        case .appUpdate: return "Stopped for a Covee update."
        case .providerDisabled, .configurationDisabled: return "Stopped: the Covee VPN was turned off in the system's settings."
        case .configurationRemoved: return "Stopped: the Covee VPN configuration was removed."
        case .idleTimeout: return "Stopped by the system after being idle."
        case .userLogout, .userSwitch: return "Stopped: the user signed out or switched."
        case .providerFailed, .connectionFailed: return "Stopped by the system: the connection failed."
        case .configurationFailed: return "Stopped by the system: the VPN configuration could not be used."
        case .authenticationCanceled: return "Stopped: sign-in was cancelled."
        default: return "Stopped by the system (reason \(reason.rawValue))."
        }
    }

    private func append(_ text: String, at time: Date? = nil) {
        record.events.append(Event(at: time ?? now(), text: text))
        if record.events.count > Self.kept { record.events.removeFirst(record.events.count - Self.kept) }
    }

    private func save() {
        guard let file else { return }
        do {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(record).write(to: file, options: .atomic)
        } catch {
            historyLog.error("connection history could not be saved: \(error.localizedDescription, privacy: .public)")
        }
    }
}

/// When the device last started.
func systemBootTime() -> Date? {
    var boot = timeval()
    var size = MemoryLayout<timeval>.size
    var name: [Int32] = [CTL_KERN, KERN_BOOTTIME]
    guard sysctl(&name, 2, &boot, &size, nil, 0) == 0 else { return nil }
    return Date(timeIntervalSince1970: TimeInterval(boot.tv_sec) + TimeInterval(boot.tv_usec) / 1_000_000)
}

/// The memory the system counts against the extension's limit, in MB.
func memoryFootprintMB() -> Int? {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
    let result = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
        }
    }
    guard result == KERN_SUCCESS else { return nil }
    return Int(info.phys_footprint / 1_048_576)
}
