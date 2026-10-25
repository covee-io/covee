import XCTest
import NetworkExtension

final class ConnectionHistoryTests: XCTestCase {
    private var folder: URL!
    private var file: URL { folder.appendingPathComponent("history/connection-history.json") }
    private var clock = Date(timeIntervalSince1970: 1_800_000_000)

    override func setUpWithError() throws {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: folder)
    }

    /// One extension process: each new instance reads what the last one saved.
    private func process(build: String = "1", boot: Date? = Date(timeIntervalSince1970: 1_700_000_000)) -> ConnectionHistory {
        ConnectionHistory(file: file, now: { [unowned self] in self.clock }, bootTime: { boot }, build: build)
    }

    func testAStopSaysWhyAndIsNotRepeatedAfterAFailure() {
        let history = process()
        history.started(byApp: true)
        clock += 60
        history.stopped(.superceded)
        XCTAssertEqual(history.events.map(\.text), ["Connected from the Covee app.",
                                                    "Another VPN took over. The device runs one VPN at a time."])
        history.started(byApp: false)
        history.failed("Connection timed out.")
        history.stopped(.providerFailed)
        XCTAssertEqual(history.events.suffix(2).map(\.text), ["Started by the system: reconnecting by itself, or from Settings.",
                                                              "Stopped after a problem: Connection timed out."])
    }

    func testAConnectionTheSystemEndedWithoutAStopIsReportedAtTheNextStart() {
        let first = process()
        first.started(byApp: true)
        clock += 60
        first.alive(memoryMB: 31)
        clock += 60
        first.alive(memoryMB: 47)
        let lastSeen = clock
        clock += 600

        let next = process()
        next.started(byApp: false)
        let cutOff = next.events[next.events.count - 2]
        XCTAssertEqual(cutOff.at, lastSeen)
        XCTAssertTrue(cutOff.text.contains("without stopping it (it had used up to 47 MB)"), cutOff.text)
        XCTAssertEqual(next.events.last?.text, "Started by the system: reconnecting by itself, or from Settings.")
    }

    func testHighMemoryIsNotedOnceAndARisingPeakIsSavedAtOnce() {
        let history = process()
        history.started(byApp: true)
        clock += 10
        history.alive(memoryMB: 20)
        clock += 10
        history.alive(memoryMB: 22)
        clock += 10
        history.alive(memoryMB: 30)
        clock += 10
        history.alive(memoryMB: 44)
        clock += 10
        history.alive(memoryMB: 46)
        let notes = history.events.filter { $0.text.hasPrefix("Memory use went over 40 MB") }
        XCTAssertEqual(notes.count, 1, "the high-memory note is not repeated")
        XCTAssertEqual(notes.first?.at, Date(timeIntervalSince1970: 1_800_000_040))
        // The extension ended here: the next start reports the last saved peak,
        // 44 MB (46 rose by less than 5 MB within the minute).
        let next = process()
        next.started(byApp: false)
        XCTAssertTrue(next.events.contains { $0.text.contains("used up to 44 MB") }, next.events.map(\.text).joined(separator: " | "))
    }

    func testARestartOrAnUpdateIsNotCalledACutOff() {
        let first = process()
        first.started(byApp: true)
        clock += 600
        process(boot: clock - 60).started(byApp: false)
        XCTAssertEqual(process().events.suffix(2).first?.text, "The connection ended when the device restarted.")

        clock += 600
        process(build: "2").started(byApp: true)
        XCTAssertEqual(process().events.suffix(2).first?.text, "The connection ended for a Covee update.")
    }

    func testTheSameNoteWaitsBeforeRepeatingAndOnlyRecentEventsAreKept() {
        let history = process()
        history.note("late settings")
        clock += 60
        history.note("late settings")
        XCTAssertEqual(history.events.count, 1)
        clock += ConnectionHistory.repeatAfter
        history.note("late settings")
        XCTAssertEqual(history.events.count, 2)

        for index in 0..<(ConnectionHistory.kept + 5) {
            clock += 1
            history.note("note \(index)")
        }
        XCTAssertEqual(history.events.count, ConnectionHistory.kept)
        XCTAssertEqual(history.events.last?.text, "note \(ConnectionHistory.kept + 4)")
        let recent = history.recent(3)
        XCTAssertEqual(recent.map { $0["text"] }, ["note \(ConnectionHistory.kept + 2)", "note \(ConnectionHistory.kept + 3)", "note \(ConnectionHistory.kept + 4)"])
        XCTAssertNotNil(recent.first?["at"].flatMap { ISO8601DateFormatter().date(from: $0) })
    }

    func testMemoryAndBootTimeCanBeRead() {
        XCTAssertGreaterThan(memoryFootprintMB() ?? 0, 0)
        XCTAssertLessThan(systemBootTime() ?? .distantFuture, Date())
    }
}
