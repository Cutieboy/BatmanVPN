use mousevpn_crypto::SecureSession;
use mousevpn_protocol::{Datagram, Header, InnerPacket, InnerPacketKind, PacketKind};

use crate::{DataPlaneError, Ipv4Packet};

#[derive(Debug, Eq, PartialEq)]
pub enum DecodedPacket {
    Ip(Vec<u8>),
    Keepalive,
}

pub struct TunnelDataPlane {
    session_id: u64,
    next_sequence: u64,
    mtu: usize,
    crypto: SecureSession,
}

impl TunnelDataPlane {
    #[must_use]
    pub const fn new(session_id: u64, mtu: usize, crypto: SecureSession) -> Self {
        Self {
            session_id,
            next_sequence: 0,
            mtu,
            crypto,
        }
    }

    /// Encrypts one IPv4 packet into a complete transport datagram.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid IP, MTU overflow, crypto failure or exhausted
    /// sequence numbers.
    pub fn encode_ip(&mut self, ip_packet: &[u8]) -> Result<Vec<u8>, DataPlaneError> {
        let ip = Ipv4Packet::parse(ip_packet)?;
        if ip.as_bytes().len() > self.mtu {
            return Err(DataPlaneError::PacketExceedsMtu {
                actual: ip.as_bytes().len(),
                mtu: self.mtu,
            });
        }
        let inner = InnerPacket::new(InnerPacketKind::Data, ip.as_bytes()).encode();
        self.encode(PacketKind::Data, &inner)
    }

    /// Creates an authenticated empty liveness packet.
    ///
    /// # Errors
    ///
    /// Returns an error for crypto failure or an exhausted sequence counter.
    pub fn encode_keepalive(&mut self) -> Result<Vec<u8>, DataPlaneError> {
        let inner = InnerPacket::new(InnerPacketKind::Keepalive, &[]).encode();
        self.encode(PacketKind::Keepalive, &inner)
    }

    /// Authenticates and decodes one transport datagram into an IPv4 packet.
    ///
    /// # Errors
    ///
    /// Returns an error for another session, unexpected framing, replay,
    /// authentication failure, invalid IP or MTU overflow.
    pub fn decode_ip(&mut self, input: &[u8]) -> Result<Vec<u8>, DataPlaneError> {
        match self.decode(input)? {
            DecodedPacket::Ip(packet) => Ok(packet),
            DecodedPacket::Keepalive => {
                Err(DataPlaneError::UnexpectedPacketKind(PacketKind::Keepalive))
            }
        }
    }

    /// Authenticates and decodes a data or keepalive datagram.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed framing, replay, authentication failure,
    /// inconsistent inner/outer kinds or an invalid IPv4 packet.
    pub fn decode(&mut self, input: &[u8]) -> Result<DecodedPacket, DataPlaneError> {
        let datagram = Datagram::decode(input)?;
        if datagram.header.session_id != self.session_id {
            return Err(DataPlaneError::SessionMismatch);
        }
        if !matches!(
            datagram.header.kind,
            PacketKind::Data | PacketKind::Keepalive
        ) {
            return Err(DataPlaneError::UnexpectedPacketKind(datagram.header.kind));
        }
        let plaintext = self
            .crypto
            .decrypt(datagram.header.sequence, datagram.payload)?;
        let inner = InnerPacket::decode(&plaintext)?;
        match (datagram.header.kind, inner.kind) {
            (PacketKind::Data, InnerPacketKind::Data) => {
                let ip = Ipv4Packet::parse(inner.payload)?;
                if ip.as_bytes().len() > self.mtu {
                    return Err(DataPlaneError::PacketExceedsMtu {
                        actual: ip.as_bytes().len(),
                        mtu: self.mtu,
                    });
                }
                Ok(DecodedPacket::Ip(ip.as_bytes().to_vec()))
            }
            (PacketKind::Keepalive, InnerPacketKind::Keepalive) if inner.payload.is_empty() => {
                Ok(DecodedPacket::Keepalive)
            }
            (_, kind) => Err(DataPlaneError::UnexpectedInnerPacketKind(kind)),
        }
    }

    fn encode(&mut self, kind: PacketKind, inner: &[u8]) -> Result<Vec<u8>, DataPlaneError> {
        let sequence = self.next_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(DataPlaneError::SequenceExhausted)?;
        let ciphertext = self.crypto.encrypt(sequence, inner)?;
        let header = Header {
            kind,
            flags: 0,
            session_id: self.session_id,
            sequence,
        };
        self.next_sequence = next;
        Ok(Datagram::new(header, &ciphertext).encode())
    }
}
