import Foundation

/// A request from the Covee app to its network extension: a small JSON object
/// with exactly the keys its command uses.
enum AppMessage: Equatable {
    case status
    /// An empty id means no exit node.
    case setExitNode(id: String, allowLAN: Bool)
    /// Offer this device to the network as an exit node, or stop offering it.
    case setOfferExitNode(offer: Bool)
    /// Use the routes other devices offer, such as the network gateway's.
    case setAcceptRoutes(accept: Bool)

    init?(_ data: Data) {
        guard data.count <= 1024,
              let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let command = request["command"] as? String else { return nil }
        switch command {
        case "status" where request.count == 1:
            self = .status
        case "setExitNode" where Set(request.keys) == ["command", "id", "allowLAN"]:
            guard let id = request["id"] as? String, id.utf8.count <= 256,
                  id.unicodeScalars.allSatisfy({ $0.value > 32 && $0.value < 127 }),
                  let allowLAN = request["allowLAN"] as? NSNumber,
                  CFGetTypeID(allowLAN) == CFBooleanGetTypeID() else { return nil }
            self = .setExitNode(id: id, allowLAN: allowLAN.boolValue)
        case "setOfferExitNode" where Set(request.keys) == ["command", "offer"]:
            guard let offer = request["offer"] as? NSNumber, CFGetTypeID(offer) == CFBooleanGetTypeID() else { return nil }
            self = .setOfferExitNode(offer: offer.boolValue)
        case "setAcceptRoutes" where Set(request.keys) == ["command", "accept"]:
            guard let accept = request["accept"] as? NSNumber, CFGetTypeID(accept) == CFBooleanGetTypeID() else { return nil }
            self = .setAcceptRoutes(accept: accept.boolValue)
        default:
            return nil
        }
    }
}
