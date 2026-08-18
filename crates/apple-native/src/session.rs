use std::{
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    sync::Mutex,
    time::Duration,
};

use mousevpn_config::{ClientConfig, ValidatedClientConfig};
use mousevpn_data_plane::{
    looks_like_protocol_datagram, Decoded, TunnelReceiver, TunnelSender, TUNNEL_OVERHEAD,
};
use mousevpn_protocol::{Datagram, SessionParameters};
use mousevpn_transport::{DatagramTransport, UdpTransport};

use crate::{handshake, AppleClientError};

pub const MAX_PACKET_BATCH: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelParameters {
    pub client_address: Ipv4Addr,
    pub prefix_len: u8,
    pub dns: Ipv4Addr,
    pub mtu: u16,
    pub remote_address: IpAddr,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct ReceiveBatch {
    pub packets: Vec<Vec<u8>>,
    pub had_activity: bool,
}

struct Outbound {
    transport: UdpTransport,
    sender: TunnelSender,
    datagram: Vec<u8>,
}

struct Inbound {
    transport: UdpTransport,
    receiver: TunnelReceiver,
    datagram: Vec<u8>,
    plaintext: Vec<u8>,
}

pub struct AppleSession {
    parameters: TunnelParameters,
    outbound: Mutex<Outbound>,
    inbound: Mutex<Inbound>,
}

impl AppleSession {
    /// Performs the authenticated UDP handshake before macOS installs the full-tunnel route.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid profile data, socket setup, timeout, or authentication failure.
    pub fn connect(
        endpoint: &str,
        server_public_key: String,
        client_private_key: String,
    ) -> Result<Self, AppleClientError> {
        Self::connect_from(endpoint, server_public_key, client_private_key, None)
    }

    /// Connects while binding the outer UDP socket to a specific local address.
    ///
    /// A privileged macOS client uses this before installing full-tunnel routes
    /// so the socket keeps the physical interface's source address.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid profile data, socket setup, timeout, or authentication failure.
    pub fn connect_from(
        endpoint: &str,
        server_public_key: String,
        client_private_key: String,
        local_address: Option<IpAddr>,
    ) -> Result<Self, AppleClientError> {
        let addresses = endpoint
            .to_socket_addrs()
            .map_err(|error| AppleClientError::new(format!("invalid endpoint: {error}")))?;
        let server = addresses
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .ok_or_else(|| AppleClientError::new("endpoint did not resolve to an IPv4 address"))?;
        let config = ClientConfig {
            server,
            server_public_key,
            client_private_key,
            tun_name: "utun".to_owned(),
        }
        .validate()?;
        Self::connect_validated(&config, local_address)
    }

    fn connect_validated(
        config: &ValidatedClientConfig,
        local_address: Option<IpAddr>,
    ) -> Result<Self, AppleClientError> {
        let (transport, plane, negotiated) = handshake::connect(config, local_address)?;
        let outbound_transport = transport.try_clone()?;
        let (sender, receiver) = plane.split();
        let parameters = tunnel_parameters(negotiated, config.server.ip());
        let packet_capacity = usize::from(parameters.mtu) + TUNNEL_OVERHEAD;
        Ok(Self {
            parameters,
            outbound: Mutex::new(Outbound {
                transport: outbound_transport,
                sender,
                datagram: Vec::with_capacity(packet_capacity),
            }),
            inbound: Mutex::new(Inbound {
                transport,
                receiver,
                datagram: vec![0_u8; packet_capacity],
                plaintext: Vec::with_capacity(packet_capacity),
            }),
        })
    }

    #[must_use]
    pub fn parameters(&self) -> &TunnelParameters {
        &self.parameters
    }

    /// Encrypts and sends up to 32 IPv4 packets while reusing one datagram buffer.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid batch, packet, or UDP write.
    pub fn send_packets(&self, packets: &[&[u8]]) -> Result<usize, AppleClientError> {
        validate_batch_size(packets.len())?;
        let mut outbound = self
            .outbound
            .lock()
            .map_err(|_| AppleClientError::new("outbound session lock is poisoned"))?;
        for packet in packets {
            let Outbound {
                transport,
                sender,
                datagram,
            } = &mut *outbound;
            sender.encode_ip_into(packet, datagram)?;
            transport
                .send(datagram)
                .map_err(AppleClientError::from)
                .map_err(|error| error.context("sending encrypted UDP packet failed"))?;
        }
        Ok(packets.len())
    }

    /// Receives and decrypts one or more IPv4 packets.
    ///
    /// The first UDP receive waits for `timeout`; subsequent receives drain the
    /// socket with a 1 ms timeout so Swift crosses the FFI boundary once per burst.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit or non-retryable socket failure.
    pub fn receive_packets(
        &self,
        timeout: Duration,
        maximum: usize,
    ) -> Result<ReceiveBatch, AppleClientError> {
        validate_batch_size(maximum)?;
        let mut inbound = self
            .inbound
            .lock()
            .map_err(|_| AppleClientError::new("inbound session lock is poisoned"))?;
        inbound.transport.set_read_timeout(Some(timeout))?;
        let mut packets = Vec::with_capacity(maximum);
        let mut had_activity = false;

        while packets.len() < maximum {
            let Inbound {
                transport,
                receiver,
                datagram,
                plaintext,
            } = &mut *inbound;
            let length = match transport.receive(datagram) {
                Ok(length) => length,
                Err(error) if handshake::is_retryable(&error) => break,
                Err(error) => {
                    return Err(AppleClientError::from(error)
                        .context("receiving encrypted UDP packet failed"));
                }
            };
            let input = &datagram[..length];
            if !looks_like_protocol_datagram(input) {
                continue;
            }
            let Ok(decoded) = Datagram::decode(input) else {
                continue;
            };
            match receiver.decode_into(decoded, plaintext) {
                Ok(Decoded::Ip(packet)) => {
                    had_activity = true;
                    packets.push(packet.to_vec());
                }
                Ok(Decoded::Keepalive) => had_activity = true,
                Err(_) => {}
            }
            if packets.len() == 1 {
                transport.set_read_timeout(Some(Duration::from_millis(1)))?;
            }
        }
        Ok(ReceiveBatch {
            packets,
            had_activity,
        })
    }

    /// Sends one authenticated keepalive datagram.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or UDP sending fails.
    pub fn send_keepalive(&self) -> Result<(), AppleClientError> {
        let mut outbound = self
            .outbound
            .lock()
            .map_err(|_| AppleClientError::new("outbound session lock is poisoned"))?;
        let Outbound {
            transport,
            sender,
            datagram,
        } = &mut *outbound;
        sender.encode_keepalive_into(datagram)?;
        transport
            .send(datagram)
            .map_err(AppleClientError::from)
            .map_err(|error| error.context("sending keepalive failed"))?;
        Ok(())
    }
}

fn tunnel_parameters(parameters: SessionParameters, remote_address: IpAddr) -> TunnelParameters {
    TunnelParameters {
        client_address: parameters.client_address,
        prefix_len: parameters.prefix_len,
        dns: parameters.dns,
        mtu: parameters.mtu,
        remote_address,
    }
}

fn validate_batch_size(length: usize) -> Result<(), AppleClientError> {
    if (1..=MAX_PACKET_BATCH).contains(&length) {
        Ok(())
    } else {
        Err(AppleClientError::new(format!(
            "packet batch must contain 1 to {MAX_PACKET_BATCH} packets"
        )))
    }
}
