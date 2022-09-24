#[macro_use]
extern crate tracing;

use sdp::Codec;
use std::fmt;
use thiserror::Error;

mod g7xx;
use g7xx::{G711Packetizer, G722Packetizer};

mod h264;
use h264::{H264Depacketizer, H264Packetizer};

mod h265;
use h265::H265Depacketizer;

mod opus;
use opus::{OpusDepacketizer, OpusPacketizer};

mod vp8;
use vp8::{Vp8Depacketizer, Vp8Packetizer};

mod vp9;
use vp9::{Vp9Depacketizer, Vp9Packetizer};

mod buffer_rx;
pub use buffer_rx::DepacketizingBuffer;

mod buffer_tx;
pub use buffer_tx::{Packetized, PacketizingBuffer};

/// Packetizes some bytes for use as RTP packet.
pub trait Packetizer: fmt::Debug {
    /// Chunk the data up into RTP packets.
    fn packetize(&mut self, mtu: usize, b: &[u8]) -> Result<Vec<Vec<u8>>, PacketError>;
}

/// Depacketizes an RTP payload.
///
/// Removes any RTP specific data from the payload.
pub trait Depacketizer {
    /// Unpack the RTP packet into a provided Vec<u8>.
    fn depacketize(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), PacketError>;

    /// Checks if the packet is at the beginning of a partition.
    ///
    /// Returns false if the result could not be determined.
    fn is_partition_head(&self, packet: &[u8]) -> bool;

    /// Checks if the packet is at the end of a partition.
    ///
    /// Returns false if the result could not be determined.
    fn is_partition_tail(&self, marker: bool, packet: &[u8]) -> bool;
}

/// Errors arising in packet- and depacketization.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("Packet is too short")]
    ErrShortPacket,
    #[error("Too many spatial layers")]
    ErrTooManySpatialLayers,
    #[error("Too many P-Diff")]
    ErrTooManyPDiff,
    #[error("H265 corrupted packet")]
    ErrH265CorruptedPacket,
    #[error("H265 invalid packet type")]
    ErrInvalidH265PacketType,
    #[error("H264 StapA size larger than buffer: {0} > {1}")]
    StapASizeLargerThanBuffer(usize, usize),
    #[error("H264 NALU type is not handled: {0}")]
    NaluTypeIsNotHandled(u8),
}

/// Helper to replace Bytes. Provides get_u8 and get_u16 over some buffer of bytes.
pub(crate) trait BitRead {
    fn remaining(&self) -> usize;
    fn get_u8(&mut self) -> u8;
    fn get_u16(&mut self) -> u16;
}

impl BitRead for (&[u8], usize) {
    #[inline(always)]
    fn remaining(&self) -> usize {
        (self.0.len() * 8).checked_sub(self.1).unwrap_or(0)
    }

    #[inline(always)]
    fn get_u8(&mut self) -> u8 {
        if self.remaining() == 0 {
            panic!("Too few bits left");
        }

        let offs = self.1 / 8;
        let shift = (self.1 % 8) as u32;
        self.1 += 8;

        let mut n = self.0[offs];

        if shift > 0 {
            n <<= shift;
            n |= self.0[offs + 1] >> (8 - shift)
        }

        n
    }

    fn get_u16(&mut self) -> u16 {
        u16::from_be_bytes([self.get_u8(), self.get_u8()])
    }
}

#[derive(Debug)]
pub enum CodecPacketizer {
    G711(G711Packetizer),
    G722(G722Packetizer),
    H264(H264Packetizer),
    // H265() TODO
    Opus(OpusPacketizer),
    Vp8(Vp8Packetizer),
    Vp9(Vp9Packetizer),
}

#[derive(Debug)]
pub enum CodecDepacketizer {
    H264(H264Depacketizer),
    H265(H265Depacketizer),
    Opus(OpusDepacketizer),
    Vp8(Vp8Depacketizer),
    Vp9(Vp9Depacketizer),
}

impl From<Codec> for CodecPacketizer {
    fn from(c: Codec) -> Self {
        match c {
            Codec::Opus => CodecPacketizer::Opus(OpusPacketizer),
            Codec::H264 => CodecPacketizer::H264(H264Packetizer::default()),
            Codec::H265 => unimplemented!("Missing packetizer for H265"),
            Codec::Vp8 => CodecPacketizer::Vp8(Vp8Packetizer::default()),
            Codec::Vp9 => CodecPacketizer::Vp9(Vp9Packetizer::default()),
            Codec::Av1 => unimplemented!("Missing packetizer for AV1"),
            Codec::Rtx => panic!("Cant instantiate packetizer for RTX codec"),
            Codec::Unknown => panic!("Cant instantiate packetizer for unknown codec"),
        }
    }
}

impl From<Codec> for CodecDepacketizer {
    fn from(c: Codec) -> Self {
        match c {
            Codec::Opus => CodecDepacketizer::Opus(OpusDepacketizer),
            Codec::H264 => CodecDepacketizer::H264(H264Depacketizer::default()),
            Codec::H265 => CodecDepacketizer::H265(H265Depacketizer::default()),
            Codec::Vp8 => CodecDepacketizer::Vp8(Vp8Depacketizer::default()),
            Codec::Vp9 => CodecDepacketizer::Vp9(Vp9Depacketizer::default()),
            Codec::Av1 => unimplemented!("Missing depacketizer for AV1"),
            Codec::Rtx => panic!("Cant instantiate depacketizer for RTX codec"),
            Codec::Unknown => panic!("Cant instantiate depacketizer for unknown codec"),
        }
    }
}

impl Packetizer for CodecPacketizer {
    fn packetize(&mut self, mtu: usize, b: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        use CodecPacketizer::*;
        match self {
            G711(v) => v.packetize(mtu, b),
            G722(v) => v.packetize(mtu, b),
            H264(v) => v.packetize(mtu, b),
            Opus(v) => v.packetize(mtu, b),
            Vp8(v) => v.packetize(mtu, b),
            Vp9(v) => v.packetize(mtu, b),
        }
    }
}

impl Depacketizer for CodecDepacketizer {
    fn depacketize(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), PacketError> {
        use CodecDepacketizer::*;
        match self {
            H264(v) => v.depacketize(packet, out),
            H265(v) => v.depacketize(packet, out),
            Opus(v) => v.depacketize(packet, out),
            Vp8(v) => v.depacketize(packet, out),
            Vp9(v) => v.depacketize(packet, out),
        }
    }

    fn is_partition_head(&self, packet: &[u8]) -> bool {
        use CodecDepacketizer::*;
        match self {
            H264(v) => v.is_partition_head(packet),
            H265(v) => v.is_partition_head(packet),
            Opus(v) => v.is_partition_head(packet),
            Vp8(v) => v.is_partition_head(packet),
            Vp9(v) => v.is_partition_head(packet),
        }
    }

    fn is_partition_tail(&self, marker: bool, packet: &[u8]) -> bool {
        use CodecDepacketizer::*;
        match self {
            H264(v) => v.is_partition_tail(marker, packet),
            H265(v) => v.is_partition_tail(marker, packet),
            Opus(v) => v.is_partition_tail(marker, packet),
            Vp8(v) => v.is_partition_tail(marker, packet),
            Vp9(v) => v.is_partition_tail(marker, packet),
        }
    }
}