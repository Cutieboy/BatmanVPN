import Foundation

struct TunnelParameters: Decodable {
    let address: String
    let prefix: UInt8
    let dns: String
    let mtu: UInt16
    let remoteAddress: String
}

final class RustTunnelSession {
    let parameters: TunnelParameters
    private let handle: OpaquePointer

    private init(handle: OpaquePointer, parameters: TunnelParameters) {
        self.handle = handle
        self.parameters = parameters
    }

    deinit {
        mousevpn_apple_session_free(handle)
    }

    static func connect(
        endpoint: String,
        serverPublicKey: String,
        clientPrivateKey: String
    ) throws -> RustTunnelSession {
        var parameters = MvOwnedBytes(data: nil, len: 0, capacity: 0)
        var error = MvError(message: nil)
        let handle = endpoint.withCString { endpointPointer in
            serverPublicKey.withCString { serverPointer in
                clientPrivateKey.withCString { clientPointer in
                    mousevpn_apple_connect(
                        endpointPointer,
                        serverPointer,
                        clientPointer,
                        &parameters,
                        &error
                    )
                }
            }
        }
        guard let handle else {
            throw takeError(&error)
        }
        do {
            let data = copyAndFree(&parameters)
            let decoded = try JSONDecoder().decode(TunnelParameters.self, from: data)
            return RustTunnelSession(handle: handle, parameters: decoded)
        } catch {
            mousevpn_apple_session_free(handle)
            throw error
        }
    }

    func send(_ packets: [Data]) throws {
        guard !packets.isEmpty else { return }
        let framed = try PacketBatchCodec.encode(packets)
        var error = MvError(message: nil)
        let succeeded = framed.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress else {
                return false
            }
            return mousevpn_apple_send_packet_batch(
                handle,
                baseAddress,
                bytes.count,
                &error
            )
        }
        guard succeeded else { throw takeError(&error) }
    }

    func receive(timeoutMilliseconds: UInt64 = 250, maximumPackets: Int = 32) throws -> [Data] {
        var framed = MvOwnedBytes(data: nil, len: 0, capacity: 0)
        var error = MvError(message: nil)
        let status = mousevpn_apple_receive_packet_batch(
            handle,
            timeoutMilliseconds,
            maximumPackets,
            &framed,
            &error
        )
        switch status {
        case 1:
            return try PacketBatchCodec.decode(copyAndFree(&framed))
        case 0:
            return []
        default:
            throw takeError(&error)
        }
    }

    func sendKeepalive() throws {
        var error = MvError(message: nil)
        guard mousevpn_apple_send_keepalive(handle, &error) else {
            throw takeError(&error)
        }
    }
}

private enum PacketBatchCodec {
    static let maximumPackets = 32

    static func encode(_ packets: [Data]) throws -> Data {
        guard (1...maximumPackets).contains(packets.count) else {
            throw RustBridgeError.invalidPacketBatch
        }
        var output = Data()
        output.reserveCapacity(4 + packets.reduce(0) { $0 + 4 + $1.count })
        try appendUInt32(packets.count, to: &output)
        for packet in packets {
            guard !packet.isEmpty else { throw RustBridgeError.invalidPacketBatch }
            try appendUInt32(packet.count, to: &output)
            output.append(packet)
        }
        return output
    }

    static func decode(_ data: Data) throws -> [Data] {
        var offset = 0
        let count = Int(try readUInt32(data, offset: &offset))
        guard (1...maximumPackets).contains(count) else {
            throw RustBridgeError.invalidPacketBatch
        }
        var packets: [Data] = []
        packets.reserveCapacity(count)
        for _ in 0..<count {
            let length = Int(try readUInt32(data, offset: &offset))
            guard length > 0, data.count - offset >= length else {
                throw RustBridgeError.invalidPacketBatch
            }
            packets.append(data.subdata(in: offset..<(offset + length)))
            offset += length
        }
        guard offset == data.count else { throw RustBridgeError.invalidPacketBatch }
        return packets
    }

    private static func appendUInt32(_ value: Int, to output: inout Data) throws {
        guard let value = UInt32(exactly: value) else {
            throw RustBridgeError.invalidPacketBatch
        }
        var networkValue = value.bigEndian
        Swift.withUnsafeBytes(of: &networkValue) { output.append(contentsOf: $0) }
    }

    private static func readUInt32(_ data: Data, offset: inout Int) throws -> UInt32 {
        guard data.count - offset >= 4 else { throw RustBridgeError.invalidPacketBatch }
        let value = data[offset..<(offset + 4)].reduce(UInt32.zero) { partial, byte in
            (partial << 8) | UInt32(byte)
        }
        offset += 4
        return value
    }
}

private enum RustBridgeError: LocalizedError {
    case native(String)
    case invalidPacketBatch

    var errorDescription: String? {
        switch self {
        case let .native(message): return message
        case .invalidPacketBatch: return "Rust bridge returned an invalid packet batch"
        }
    }
}

private func copyAndFree(_ bytes: inout MvOwnedBytes) -> Data {
    defer { mousevpn_apple_bytes_free(&bytes) }
    guard let pointer = bytes.data, bytes.len > 0 else { return Data() }
    return Data(bytes: pointer, count: bytes.len)
}

private func takeError(_ error: inout MvError) -> Error {
    defer { mousevpn_apple_error_free(&error) }
    let message = error.message.map { String(cString: $0) } ?? "Unknown native error"
    return RustBridgeError.native(message)
}
