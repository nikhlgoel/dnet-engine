//! Length-prefixed framing: a 4-byte little-endian length followed by UTF-8 JSON.
//!
//! Every byte arriving here is hostile input (Principle V). Decoding must reject
//! malformed, oversized, and truncated frames without panicking (IPC-08).

/// Size of the length prefix, in bytes.
pub const HEADER_LEN: usize = 4;

/// Largest payload accepted, in bytes.
///
/// The contract requires that oversized lengths be rejected but does not set the
/// limit. 1 MiB is the accepted default: every contract message is small JSON, and
/// since the length prefix is attacker-controlled, this bounds the allocation a
/// single frame can request.
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
/// - `Err(_)`: the input can never become a valid frame; close the connection.
///
/// The oversized check runs on the header alone, so a hostile prefix is rejected
/// before its claimed payload is ever waited for or allocated.
pub fn decode(buf: &[u8]) -> Result<Option<Frame>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let header: [u8; HEADER_LEN] = buf[..HEADER_LEN]
        .try_into()
        .expect("slice is exactly HEADER_LEN bytes");
    let declared = u32::from_le_bytes(header) as usize;

    if declared > MAX_FRAME_LEN {
        return Err(FrameError::Oversized {
            declared,
            max: MAX_FRAME_LEN,
        });
    }

    let end = HEADER_LEN + declared;
    if buf.len() < end {
        return Ok(None);
    }

    let payload = std::str::from_utf8(&buf[HEADER_LEN..end])
        .map_err(|_| FrameError::Malformed)?
        .to_owned();
    Ok(Some(Frame {
        payload,
        consumed: end,
    }))
}

/// Encode `payload` as a frame.
pub fn encode(payload: &str) -> Result<Vec<u8>, FrameError> {
    let bytes = payload.as_bytes();
    if bytes.len() > MAX_FRAME_LEN {
        return Err(FrameError::Oversized {
            declared: bytes.len(),
            max: MAX_FRAME_LEN,
        });
    }
    let len = bytes.len() as u32;
    let mut out = Vec::with_capacity(HEADER_LEN + bytes.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}
