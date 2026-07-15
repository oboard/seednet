//! 4-byte big-endian length framing for stream-based transports (TCP, WS, WSS).

use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Encode `payload` with a 4-byte length prefix into `buf`.
#[allow(dead_code)]
pub fn encode(payload: &[u8], buf: &mut BytesMut) {
    buf.put_u32(payload.len() as u32);
    buf.put_slice(payload);
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
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    let mut header = [0u8; 4];
    (&mut header[..]).put_u32(payload.len() as u32);
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    Ok(())
}
