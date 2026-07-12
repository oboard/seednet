use seednet_common::{Error, Result};

pub struct TunReader;

pub struct TunWriter;

pub struct AsyncTunDevice {
    tun_name: String,
}

impl TunReader {
    pub async fn recv(&mut self, _buf: &mut [u8]) -> Result<usize> {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN device is not supported on this platform",
        )))
    }
}

impl TunWriter {
    pub async fn send(&mut self, _buf: &[u8]) -> Result<usize> {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN device is not supported on this platform",
        )))
    }
}

impl AsyncTunDevice {
    pub fn create(_config: &crate::TunConfig) -> Result<Self> {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN device creation is not supported on this platform (requires Unix)",
        )))
    }

    pub fn into_split(self) -> (TunReader, TunWriter, String) {
        (TunReader, TunWriter, self.tun_name)
    }

    pub fn name(&self) -> &str {
        &self.tun_name
    }

    pub fn mtu(&self) -> usize {
        crate::OVERLAY_MTU
    }
}
