// Swift side of the vproxy core for the Ratatosk Packet Tunnel extension.
// Add RatatoskCore.xcframework (scripts/build-xcframework.sh) and this file
// to the extension target.

import Foundation
import NetworkExtension
import RatatoskCore

enum RatatoskError: Error, CustomStringConvertible {
    case start(String)

    var description: String {
        switch self {
        case .start(let reason): return reason
        }
    }
}

/// One running core: reads packets from `packetFlow` into the netstack and
/// writes the netstack's packets back.
final class RatatoskEngine {
    static let mtu = 1500

    private let flow: NEPacketTunnelFlow
    private let lock = NSLock()
    private var tunnel: OpaquePointer?

    init(flow: NEPacketTunnelFlow) {
        self.flow = flow
    }

    static var version: String { String(cString: ratatosk_version()) }

    /// Send core logs to `sink` (call once, before `start`).
    static func setLogger(maxLevel: UInt8 = 3, _ sink: @escaping (UInt8, String) -> Void) {
        let box = Unmanaged.passRetained(LogSink(sink)).toOpaque() // lives for the process
        ratatosk_set_logger({ ctx, level, line in
            guard let ctx, let line else { return }
            Unmanaged<LogSink>.fromOpaque(ctx).takeUnretainedValue().sink(level, String(cString: line))
        }, box, maxLevel)
    }

    /// Settings for `setTunnelNetworkSettings`: everything into the tunnel,
    /// DNS answered by the core. `serverAddress` is only informational here.
    static func networkSettings(serverAddress: String) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverAddress)
        let ipv4 = NEIPv4Settings(addresses: [RATATOSK_TUNNEL_ADDRESS],
                                  subnetMasks: [RATATOSK_TUNNEL_NETMASK])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        // IPv6 goes into the tunnel too, so it cannot bypass it; the core
        // routes it by address (fake DNS only hands out IPv4).
        let ipv6 = NEIPv6Settings(addresses: ["fd52:6174:6174::1"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: [RATATOSK_DNS_ADDRESS])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: mtu)
        return settings
    }

    /// Start the core for a vless:// or vpn:// link and begin moving packets.
    func start(link: String) throws {
        var error = [CChar](repeating: 0, count: 512)
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        let started = link.withCString { cLink in
            ratatosk_start(cLink, UInt16(Self.mtu), { ctx, packet, len in
                guard let ctx, let packet else { return }
                let engine = Unmanaged<RatatoskEngine>.fromOpaque(ctx).takeUnretainedValue()
                engine.write(Data(bytes: packet, count: len))
            }, ctx, &error, error.count)
        }
        guard let started else {
            throw RatatoskError.start(String(cString: error))
        }
        lock.lock()
        tunnel = started
        lock.unlock()
        readLoop()
    }

    func stop() {
        lock.lock()
        let running = tunnel
        tunnel = nil
        lock.unlock()
        if let running { ratatosk_stop(running) }
    }

    var stats: RatatoskStats {
        var stats = RatatoskStats()
        ratatosk_stats(&stats)
        return stats
    }

    private func readLoop() {
        flow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.lock.lock()
            guard let tunnel = self.tunnel else {
                self.lock.unlock()
                return
            }
            for packet in packets {
                packet.withUnsafeBytes { raw in
                    if let base = raw.bindMemory(to: UInt8.self).baseAddress {
                        _ = ratatosk_push_packet(tunnel, base, raw.count)
                    }
                }
            }
            self.lock.unlock()
            self.readLoop()
        }
    }

    private func write(_ packet: Data) {
        // IP version from the first nibble: 4 or 6.
        let family = (packet.first ?? 0) >> 4 == 6 ? AF_INET6 : AF_INET
        flow.writePackets([packet], withProtocols: [NSNumber(value: family)])
    }
}

private final class LogSink {
    let sink: (UInt8, String) -> Void
    init(_ sink: @escaping (UInt8, String) -> Void) { self.sink = sink }
}
