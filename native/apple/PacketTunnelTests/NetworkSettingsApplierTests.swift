import XCTest
import NetworkExtension

final class NetworkSettingsApplierTests: XCTestCase {
    func testStopDrainsInflightApplyAndWithdrawsBeforeCompletion() {
        let firstStarted = expectation(description: "first settings apply")
        let withdrawalStarted = expectation(description: "withdrawal after in-flight operation")
        let firstCancelled = expectation(description: "old apply cancelled")
        let queuedCancelled = expectation(description: "queued apply cancelled")
        let stopped = expectation(description: "stop completed after withdrawal")
        let lock = NSLock()
        var firstCallback: ((Error?) -> Void)?
        var withdrawCallback: ((Error?) -> Void)?
        var stopCompleted = false
        var nonemptyApplies = 0
        let applier = NetworkSettingsApplier { settings, callback in
            lock.lock()
            if settings == nil { withdrawCallback = callback }
            else { nonemptyApplies += 1; firstCallback = callback }
            lock.unlock()
            if settings == nil { withdrawalStarted.fulfill() } else { firstStarted.fulfill() }
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        applier.submit(settings) { error in XCTAssertNotNil(error); firstCancelled.fulfill() }
        wait(for: [firstStarted], timeout: 2)
        applier.submit(settings) { error in XCTAssertNotNil(error); queuedCancelled.fulfill() }
        applier.stop {
            lock.lock(); stopCompleted = true; lock.unlock()
            stopped.fulfill()
        }
        wait(for: [queuedCancelled], timeout: 2)
        lock.lock()
        let initial = firstCallback
        XCTAssertFalse(stopCompleted)
        lock.unlock()
        initial?(nil)
        wait(for: [firstCancelled, withdrawalStarted], timeout: 2)
        lock.lock()
        let withdrawal = withdrawCallback
        XCTAssertFalse(stopCompleted)
        XCTAssertEqual(nonemptyApplies, 1)
        lock.unlock()
        withdrawal?(nil)
        wait(for: [stopped], timeout: 2)
    }

    func testSubmissionAfterStopCannotApplyNewRoutes() {
        let stopped = expectation(description: "stopped")
        let rejected = expectation(description: "rejected settings")
        let applier = NetworkSettingsApplier { settings, callback in
            XCTAssertNil(settings)
            callback(nil)
        }
        applier.stop { stopped.fulfill() }
        wait(for: [stopped], timeout: 2)
        applier.submit(NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")) { error in
            XCTAssertNotNil(error)
            rejected.fulfill()
        }
        wait(for: [rejected], timeout: 2)
    }
}
