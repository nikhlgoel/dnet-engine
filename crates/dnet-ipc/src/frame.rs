//! Length-prefixed framing: a 4-byte little-endian length followed by UTF-8 JSON.
//!
//! Every byte arriving here is hostile input (Principle V). Decoding must reject
//! malformed, oversized, and truncated frames without panicking (IPC-08).

/// Size of the length prefix, in bytes.
pub const HEADER_LEN: usize = 4;

/// Largest payload accepted, in bytes.
///
/// The contract requires that oversized lengths be rejected, but it does not set the
/// limit. 1 MiB is a chosen default: every contract message is small JSON, and since
/// the length prefix is attacker-controlled, the ceiling bounds the allocation.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Why a frame can never be decoded. The connection should be closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The length prefix declares a payload larger than the limit.
    #[error("declared frame length {declared} exceeds the {max}-byte limit")]
    Oversized {
        /// Length declared by the prefix.
        declared: usize,
        /// The enforced limit.
        max: usize,
    },
    /// The payload is not valid UTF-8.
    #[error("frame payload is not valid UTF-8")]
    Malformed,
}

/// One complete, validated frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The UTF-8 payload.
    pub payload: String,
    /// Bytes consumed from the input, header included.
    pub consumed: usize,
}

/// Decode one frame from the front of `buf`.
///
/// - `Ok(Some(frame))`: a complete frame was decoded.
/// - `Ok(None)`: more bytes are needed (the header or payload is truncated).
/// - `Err(_)`: the input can never become a valid frame.
pub fn decode(_buf: &[u8]) -> Result<Option<Frame>, FrameError> {
    todo!("T032: implement length-prefixed frame decoding")
}

/// Encode `payload` as a frame.
pub fn encode(_payload: &str) -> Result<Vec<u8>, FrameError> {
    todo!("T032: implement frame encoding")
}
