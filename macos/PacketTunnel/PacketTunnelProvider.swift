import Foundation
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var session: RustTunnelSession?
    private var pump: PacketPump?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let configuration = tunnelProtocol.providerConfiguration,
              let endpoint = configuration[ProviderConfigurationKey.endpoint] as? String,
              let serverPublicKey = configuration[ProviderConfigurationKey.serverPublicKey] as? String,
              let secretReference = tunnelProtocol.passwordReference else {
            completionHandler(PacketTunnelError.invalidConfiguration)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let clientPrivateKey = try KeychainSecret.load(
                    persistentReference: secretReference
                )
                let session = try RustTunnelSession.connect(
                    endpoint: endpoint,
                    serverPublicKey: serverPublicKey,
                    clientPrivateKey: clientPrivateKey
                )
                let settings = self.makeNetworkSettings(session.parameters)
                self.setTunnelNetworkSettings(settings) { [weak self] error in
                    guard let self else { return }
                    if let error {
                        completionHandler(error)
                        return
                    }
                    self.session = session
                    let pump = PacketPump(
                        packetFlow: self.packetFlow,
                        session: session,
                        onFailure: { [weak self] error in
                            self?.cancelTunnelWithError(error)
                        }
                    )
                    self.pump = pump
                    pump.start()
                    completionHandler(nil)
                }
            } catch {
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        pump?.stop()
        pump = nil
        session = nil
        completionHandler()
    }

    private func makeNetworkSettings(_ parameters: TunnelParameters) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: parameters.remoteAddress
        )
        settings.mtu = NSNumber(value: parameters.mtu)

        let ipv4 = NEIPv4Settings(
            addresses: [parameters.address],
            subnetMasks: [Self.subnetMask(prefixLength: parameters.prefix)]
        )
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        // MouseVPN v1 carries IPv4 only. Route IPv6 into the extension and drop
        // it in PacketPump instead of silently leaking it outside the VPN.
        let ipv6 = NEIPv6Settings(
            addresses: ["fd00::1"],
            networkPrefixLengths: [128]
        )
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        let dns = NEDNSSettings(servers: [parameters.dns])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        return settings
    }

    private static func subnetMask(prefixLength: UInt8) -> String {
        guard prefixLength > 0 else { return "0.0.0.0" }
        let prefix = min(UInt32(prefixLength), 32)
        let mask = UInt32.max << (32 - prefix)
        return [24, 16, 8, 0]
            .map { String((mask >> UInt32($0)) & 0xff) }
            .joined(separator: ".")
    }
}

private enum PacketTunnelError: LocalizedError {
    case invalidConfiguration

    var errorDescription: String? {
        "MouseVPN profile is missing or damaged"
    }
}
