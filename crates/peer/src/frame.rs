//! Length-prefixed frame protocol: `[u32 BE len][payload]`.
//!
//! Used to delimit Noise-encrypted messages over the UDP transport. The 4-byte
//! length header allows the receiver to know exactly how many bytes to feed
//! into `snow::TransportState::read_message`.

use seednet_common::{Error, Result};

pub const HEADER_LEN: usize = 4;

pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub fn decode_frame(data: &[u8]) -> Result<&[u8]> {
    if data.len() < HEADER_LEN {
        return Err(Error::NoiseTransport(format!(
            "frame too short: {} bytes",
            data.len()
        )));
    }
    let len = u32::from_be_bytes(
        data[..HEADER_LEN]
            .try_into()
            .expect("HEADER_LEN == 4"),
    ) as usize;
    if data.len() < HEADER_LEN + len {
        return Err(Error::NoiseTransport(format!(
            "frame truncated: expected {} payload bytes, got {}",
            len,
            data.len() - HEADER_LEN
        )));
    }
    Ok(&data[HEADER_LEN..HEADER_LEN + len])
}

pub fn frame_overhead() -> usize {
    HEADER_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = b"hello world";
        let framed = encode_frame(payload);
        let decoded = decode_frame(&framed).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn empty_payload() {
        let framed = encode_frame(&[]);
        let decoded = decode_frame(&framed).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn truncated_header() {
        assert!(decode_frame(&[0, 0]).is_err());
    }

    #[test]
    fn truncated_payload() {
        let mut framed = encode_frame(b"12345");
        framed.truncate(framed.len() - 2);
        assert!(decode_frame(&framed).is_err());
    }

    #[test]
    fn extra_data_after_payload_ignored() {
        let mut framed = encode_frame(b"data");
        framed.extend_from_slice(b"extra");
        let decoded = decode_frame(&framed).unwrap();
        assert_eq!(decoded, b"data");
    }
}
