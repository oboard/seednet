//! 4-byte big-endian length framing for stream-based transports (TCP, WS, WSS).

use bytes::{BufMut, Bytes, BytesMut};
use std::io::{self, IoSlice};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Encode `payload` with a 4-byte length prefix into `buf`.
#[allow(dead_code)]
pub fn encode(payload: &[u8], buf: &mut BytesMut) {
    buf.put_u32(payload.len() as u32);
    buf.put_slice(payload);
}

/// Encode a frame for use in tests / inspection.
#[allow(dead_code)]
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    encode(payload, &mut buf);
    buf.to_vec()
}

/// Decode a frame for use in tests.
#[allow(dead_code)]
pub fn decode_frame(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    Some(&buf[4..4 + len])
}

/// Read one length-prefixed frame from `reader`.
pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<Bytes> {
    let len = reader.read_u32().await? as usize;
    if len > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

/// Write one length-prefixed frame to `writer`.
///
/// Uses `write_vectored` to send header + body in a single syscall, halving
/// the number of syscalls compared to two separate `write_all` calls.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    let mut header = [0u8; 4];
    (&mut header[..]).put_u32(payload.len() as u32);
    let bufs = [IoSlice::new(&header), IoSlice::new(payload)];
    // write_vectored may write fewer bytes than requested on some platforms;
    // fall back to individual writes if it does not complete in one call.
    let total = 4 + payload.len();
    let n = writer.write_vectored(&bufs).await?;
    if n < total {
        // Partial write: finish remaining bytes.
        let sent_header = n.min(4);
        if sent_header < 4 {
            writer.write_all(&header[sent_header..]).await?;
            writer.write_all(payload).await?;
        } else {
            let sent_body = n - 4;
            writer.write_all(&payload[sent_body..]).await?;
        }
    }
    Ok(())
}
