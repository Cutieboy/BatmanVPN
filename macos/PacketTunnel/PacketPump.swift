import Darwin
import Foundation
import NetworkExtension

final class PacketPump {
    private let packetFlow: NEPacketTunnelFlow
    private let session: RustTunnelSession
    private let onFailure: (Error) -> Void
    private let outboundQueue = DispatchQueue(label: "dev.mousevpn.packet-out", qos: .userInitiated)
    private let inboundQueue = DispatchQueue(label: "dev.mousevpn.packet-in", qos: .userInitiated)
    private let stateLock = NSLock()
    private var running = false
    private var keepaliveTimer: DispatchSourceTimer?

    init(
        packetFlow: NEPacketTunnelFlow,
        session: RustTunnelSession,
        onFailure: @escaping (Error) -> Void
    ) {
        self.packetFlow = packetFlow
        self.session = session
        self.onFailure = onFailure
    }

    func start() {
        setRunning(true)
        readNextBatch()
        receiveLoop()
        startKeepalive()
    }

    func stop() {
        setRunning(false)
        keepaliveTimer?.cancel()
        keepaliveTimer = nil
    }

    private func readNextBatch() {
        guard isRunning else { return }
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.isRunning else { return }
            let ipv4Packets = zip(packets, protocols).compactMap { packet, protocolNumber in
                protocolNumber.int32Value == AF_INET ? packet : nil
            }
            outboundQueue.async { [weak self] in
                guard let self, self.isRunning else { return }
                do {
                    var offset = 0
                    while offset < ipv4Packets.count {
                        let end = min(offset + 32, ipv4Packets.count)
                        try self.session.send(Array(ipv4Packets[offset..<end]))
                        offset = end
                    }
                    self.readNextBatch()
                } catch {
                    self.fail(error)
                }
            }
        }
    }

    private func receiveLoop() {
        inboundQueue.async { [weak self] in
            while let self, self.isRunning {
                do {
                    let packets = try self.session.receive()
                    guard !packets.isEmpty else { continue }
                    let protocols = Array(repeating: NSNumber(value: AF_INET), count: packets.count)
                    guard self.packetFlow.writePackets(packets, withProtocols: protocols) else {
                        throw PacketPumpError.packetFlowWriteFailed
                    }
                } catch {
                    self.fail(error)
                    return
                }
            }
        }
    }

    private func startKeepalive() {
        let timer = DispatchSource.makeTimerSource(queue: outboundQueue)
        timer.schedule(deadline: .now() + 10, repeating: 10, leeway: .milliseconds(250))
        timer.setEventHandler { [weak self] in
            guard let self, self.isRunning else { return }
            do {
                try self.session.sendKeepalive()
            } catch {
                self.fail(error)
            }
        }
        keepaliveTimer = timer
        timer.resume()
    }

    private var isRunning: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return running
    }

    private func setRunning(_ value: Bool) {
        stateLock.lock()
        running = value
        stateLock.unlock()
    }

    private func fail(_ error: Error) {
        let shouldReport: Bool
        stateLock.lock()
        shouldReport = running
        running = false
        stateLock.unlock()
        if shouldReport { onFailure(error) }
    }
}

private enum PacketPumpError: LocalizedError {
    case packetFlowWriteFailed

    var errorDescription: String? {
        "macOS rejected packets written by the tunnel"
    }
}
