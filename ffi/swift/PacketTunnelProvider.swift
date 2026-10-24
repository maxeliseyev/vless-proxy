// Template for the Ratatosk Packet Tunnel extension's principal class.
// The app passes the link in the tunnel configuration:
//   (manager.protocolConfiguration as? NETunnelProviderProtocol)?
//       .providerConfiguration = ["link": "vless://..."]

import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "ratatosk", category: "tunnel")
    private var engine: RatatoskEngine?

    override func startTunnel(options: [String: NSObject]?) async throws {
        let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let link = config?["link"] as? String else {
            throw RatatoskError.start("no link in the tunnel configuration")
        }
        let log = self.log
        RatatoskEngine.setLogger { level, line in
            log.log(level: level <= 1 ? .error : level == 2 ? .default : .info, "\(line, privacy: .public)")
        }
        log.info("\(RatatoskEngine.version, privacy: .public)")

        try await setTunnelNetworkSettings(RatatoskEngine.networkSettings(serverAddress: "127.0.0.1"))
        let engine = RatatoskEngine(flow: packetFlow)
        try engine.start(link: link)
        self.engine = engine
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        engine?.stop()
        engine = nil
    }
}
