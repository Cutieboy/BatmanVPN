use mousevpn_crypto::{ReceiveHalf, SecureSession, SendHalf, AUTH_TAG_LEN};
use mousevpn_protocol::{
    Datagram, Header, InnerPacket, InnerPacketKind, PacketKind, HEADER_LEN, VERSION,
};

use crate::{DataPlaneError, Ipv4Packet};

/// Bytes each tunnelled IP packet costs on the wire, excluding outer IP/UDP.
///
/// Outer header plus the inner packet-kind byte plus the AEAD tag.
pub const TUNNEL_OVERHEAD: usize = HEADER_LEN + 1 + AUTH_TAG_LEN;

#[derive(Debug, Eq, PartialEq)]
pub enum DecodedPacket {
    Ip(Vec<u8>),
    Keepalive,
}

/// Borrowed result of a zero-allocation decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decoded<'a> {
    Ip(&'a [u8]),
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

    /// Splits the plane into halves that can be driven from separate threads.
    ///
    /// The sending and receiving directions share no mutable state, so neither
    /// needs to wait on the other.
    #[must_use]
    pub fn split(self) -> (TunnelSender, TunnelReceiver) {
        let (send, receive) = self.crypto.split();
        (
            TunnelSender {
                session_id: self.session_id,
                next_sequence: self.next_sequence,
                mtu: self.mtu,
                crypto: send,
                plaintext: Vec::with_capacity(self.mtu + 1),
            },
            TunnelReceiver {
                session_id: self.session_id,
                mtu: self.mtu,
                crypto: receive,
            },
        )
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

/// Sending half of a tunnel: framing, encryption and the outgoing sequence.
///
/// Every method writes into a caller-owned buffer, so a steady packet flow
/// performs no heap allocation at all once the buffers have grown.
pub struct TunnelSender {
    session_id: u64,
    next_sequence: u64,
    mtu: usize,
    crypto: SendHalf,
    plaintext: Vec<u8>,
}

impl TunnelSender {
    /// Encrypts one IPv4 packet into `output` as a complete transport datagram.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid IP, MTU overflow, crypto failure or exhausted
    /// sequence numbers.
    pub fn encode_ip_into(
        &mut self,
        ip_packet: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), DataPlaneError> {
        let ip = Ipv4Packet::parse(ip_packet)?;
        if ip.as_bytes().len() > self.mtu {
            return Err(DataPlaneError::PacketExceedsMtu {
                actual: ip.as_bytes().len(),
                mtu: self.mtu,
            });
        }
        // `ip` borrows `ip_packet`, which is disjoint from `self`.
        let payload = ip.as_bytes();
        self.encode_into(PacketKind::Data, InnerPacketKind::Data, payload, output)
    }

    /// Writes an authenticated empty liveness packet into `output`.
    ///
    /// # Errors
    ///
    /// Returns an error for crypto failure or an exhausted sequence counter.
    pub fn encode_keepalive_into(&mut self, output: &mut Vec<u8>) -> Result<(), DataPlaneError> {
        self.encode_into(
            PacketKind::Keepalive,
            InnerPacketKind::Keepalive,
            &[],
            output,
        )
    }

    fn encode_into(
        &mut self,
        kind: PacketKind,
        inner_kind: InnerPacketKind,
        payload: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), DataPlaneError> {
        let sequence = self.next_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(DataPlaneError::SequenceExhausted)?;

        self.plaintext.clear();
        self.plaintext.push(inner_kind as u8);
        self.plaintext.extend_from_slice(payload);

        output.resize(HEADER_LEN + self.plaintext.len() + AUTH_TAG_LEN, 0);
        let length =
            self.crypto
                .encrypt_into(sequence, &self.plaintext, &mut output[HEADER_LEN..])?;
        output.truncate(HEADER_LEN + length);
        output[..HEADER_LEN].copy_from_slice(
            &Header {
                kind,
                flags: 0,
                session_id: self.session_id,
                sequence,
            }
            .encode(),
        );
        self.next_sequence = next;
        Ok(())
    }
}

/// Receiving half of a tunnel: session binding, replay window and decryption.
pub struct TunnelReceiver {
    session_id: u64,
    mtu: usize,
    crypto: ReceiveHalf,
}

impl TunnelReceiver {
    /// Authenticates one already-framed datagram into `output`.
    ///
    /// The returned IP slice borrows `output`; no packet data is copied out.
    ///
    /// # Errors
    ///
    /// Returns an error for another session, unexpected framing, replay,
    /// authentication failure, invalid IPv4 or MTU overflow.
    pub fn decode_into<'a>(
        &mut self,
        datagram: Datagram<'_>,
        output: &'a mut Vec<u8>,
    ) -> Result<Decoded<'a>, DataPlaneError> {
        if datagram.header.session_id != self.session_id {
            return Err(DataPlaneError::SessionMismatch);
        }
        if !matches!(
            datagram.header.kind,
            PacketKind::Data | PacketKind::Keepalive
        ) {
            return Err(DataPlaneError::UnexpectedPacketKind(datagram.header.kind));
        }

        output.resize(datagram.payload.len(), 0);
        let length =
            self.crypto
                .decrypt_into(datagram.header.sequence, datagram.payload, output)?;
        output.truncate(length);

        let inner = InnerPacket::decode(output)?;
        match (datagram.header.kind, inner.kind) {
            (PacketKind::Data, InnerPacketKind::Data) => {
                let ip_len = Ipv4Packet::parse(inner.payload)?.as_bytes().len();
                if ip_len > self.mtu {
                    return Err(DataPlaneError::PacketExceedsMtu {
                        actual: ip_len,
                        mtu: self.mtu,
                    });
                }
                Ok(Decoded::Ip(&output[1..=ip_len]))
            }
            (PacketKind::Keepalive, InnerPacketKind::Keepalive) if inner.payload.is_empty() => {
                Ok(Decoded::Keepalive)
            }
            (_, kind) => Err(DataPlaneError::UnexpectedInnerPacketKind(kind)),
        }
    }
}

/// Rejects datagrams that cannot belong to this protocol before any lookup.
///
/// Cheap enough to run on every received packet and keeps scanner traffic out
/// of the session map and the rate limiter.
#[must_use]
pub fn looks_like_protocol_datagram(input: &[u8]) -> bool {
    input.len() >= HEADER_LEN && input[0] == VERSION
}
