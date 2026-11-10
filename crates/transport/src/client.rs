//! Datagram operations shared by UDP and TCP tunnel runtimes.
#![allow(clippy::missing_errors_doc)]
use std::{io, time::Duration};

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::UdpBatch;
use crate::{DatagramTransport, MousalityTransport, UdpTransport};

/// The packet loops operate on datagrams regardless of the outer transport.
pub enum ClientTransport {
    Udp(UdpTransport),
    Mousality(MousalityTransport),
}

impl ClientTransport {
    #[must_use]
    pub fn is_mousality(&self) -> bool {
        matches!(self, Self::Mousality(_))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Udp(transport) => transport.try_clone().map(Self::Udp),
            Self::Mousality(transport) => Ok(Self::Mousality(transport.clone())),
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Udp(transport) => transport.set_read_timeout(timeout),
            Self::Mousality(transport) => {
                transport.set_read_timeout(timeout);
                Ok(())
            }
        }
    }

    pub fn shutdown(&self) -> io::Result<()> {
        match self {
            Self::Udp(transport) => transport.shutdown(),
            Self::Mousality(transport) => transport.shutdown(),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn send_batch_with(
        &mut self,
        packets: &[Vec<u8>],
        batch: &mut UdpBatch,
    ) -> io::Result<usize> {
        match self {
            Self::Udp(transport) => transport.send_batch_with(packets, batch),
            Self::Mousality(transport) => {
                let mut sent = 0;
                for packet in packets {
                    match transport.send(packet) {
                        Ok(()) => sent += 1,
                        Err(_) if sent > 0 => return Ok(sent),
                        Err(error) => return Err(error),
                    }
                }
                Ok(sent)
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn receive_batch_with(
        &mut self,
        buffers: &mut [Vec<u8>],
        lengths: &mut Vec<usize>,
        batch: &mut UdpBatch,
    ) -> io::Result<()> {
        match self {
            Self::Udp(transport) => transport.receive_batch_with(buffers, lengths, batch),
            Self::Mousality(transport) => {
                lengths.clear();
                lengths.push(transport.receive(&mut buffers[0])?);
                Ok(())
            }
        }
    }
}

impl DatagramTransport for ClientTransport {
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        match self {
            Self::Udp(t) => t.send(packet),
            Self::Mousality(t) => t.send(packet),
        }
    }

    fn receive(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(t) => t.receive(output),
            Self::Mousality(t) => t.receive(output),
        }
    }
}
