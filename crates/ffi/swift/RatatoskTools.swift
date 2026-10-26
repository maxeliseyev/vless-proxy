// Calls of the vproxy core that need no tunnel: server ping and subscription
// download. Shared by the app and the Packet Tunnel extension (the app
// pings itself while the VPN is off; with it on, the extension pings, since
// the app's own sockets would go through the tunnel). Both block: call them
// off the main thread.

import Foundation
import RatatoskCore

enum RatatoskTools {
    /// Handshake time per link in milliseconds, nil where the link is bad
    /// or the server did not answer in `timeout`.
    static func ping(_ links: [String], timeout: Duration = .seconds(3)) -> [Int?] {
        guard let json = try? JSONEncoder().encode(links),
              let input = String(data: json, encoding: .utf8) else {
            return links.map { _ in nil }
        }
        let millis = UInt32(clamping: timeout.components.seconds * 1000)
        guard let out = take(ratatosk_ping(input, millis)),
              let ms = try? JSONDecoder().decode([Int?].self, from: Data(out.utf8)),
              ms.count == links.count else {
            return links.map { _ in nil }
        }
        return ms
    }

    /// What a subscription URL serves (see `ratatosk_fetch_subscription`).
    struct Subscription: Decodable, Sendable {
        var title: String?
        var links: [String]
        var skipped: Int
        var upload: UInt64?
        var download: UInt64?
        var total: UInt64?
        /// Unix seconds; 0 or nil for none.
        var expire: UInt64?
        var interval_hours: UInt64
    }

    struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    static func fetchSubscription(_ url: String) -> Result<Subscription, Failure> {
        guard let out = take(ratatosk_fetch_subscription(url)) else {
            return .failure(Failure(description: "no answer from the core"))
        }
        let data = Data(out.utf8)
        if let sub = try? JSONDecoder().decode(Subscription.self, from: data) {
            return .success(sub)
        }
        let error = (try? JSONDecoder().decode([String: String].self, from: data))?["error"]
        return .failure(Failure(description: error ?? "unreadable subscription"))
    }

    private static func take(_ s: UnsafeMutablePointer<CChar>?) -> String? {
        guard let s else { return nil }
        defer { ratatosk_string_free(s) }
        return String(cString: s)
    }
}
