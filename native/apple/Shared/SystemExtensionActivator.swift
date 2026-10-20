#if os(macOS)
import Foundation
import SystemExtensions

@MainActor
final class SystemExtensionActivator: NSObject, @preconcurrency OSSystemExtensionRequestDelegate {
    private var completion: CheckedContinuation<Void, Error>?
    private var needsApproval: (() -> Void)?

    /// Activates the extension. needsApproval runs when macOS waits for the
    /// person to allow it in System Settings; activation then finishes by itself.
    func activate(identifier: String, needsApproval: @escaping () -> Void) async throws {
        guard completion == nil else { throw ActivationError.alreadyPending }
        try await withCheckedThrowingContinuation { continuation in
            completion = continuation
            self.needsApproval = needsApproval
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { needsApproval?() }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { finish(.failure(error)) }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed { finish(.success(())) }
        else { finish(.failure(ActivationError.restartRequired)) }
    }
    private func finish(_ result: Result<Void, Error>) {
        let pending = completion
        completion = nil
        needsApproval = nil
        pending?.resume(with: result)
    }
}

private enum ActivationError: LocalizedError {
    case alreadyPending, restartRequired
    var errorDescription: String? {
        switch self {
        case .alreadyPending: return "A network extension approval is already pending."
        case .restartRequired: return "macOS requires a restart to finish activating the network extension. Restart, then connect again."
        }
    }
}
#endif
