#if os(macOS)
import IOKit.pwr_mgt

/// Keeps the Mac from going to sleep on its own while other devices use it as
/// an exit node. The display can still sleep, and closing a laptop's lid or
/// choosing Sleep still sleeps the Mac.
final class SleepGuard {
    private var assertion: IOPMAssertionID = 0
    private(set) var holding = false

    func hold(_ on: Bool) {
        if on, !holding {
            holding = IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleSystemSleep as CFString,
                                                  IOPMAssertionLevel(kIOPMAssertionLevelOn),
                                                  "Covee: other devices use this Mac as an exit node" as CFString,
                                                  &assertion) == kIOReturnSuccess
        } else if !on, holding {
            IOPMAssertionRelease(assertion)
            holding = false
        }
    }

    deinit {
        if holding { IOPMAssertionRelease(assertion) }
    }
}
#endif
