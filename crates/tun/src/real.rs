use std::net::IpAddr;

use seednet_common::{Error, Result, OVERLAY_MTU};
use tun::{AbstractDevice, AsyncDevice, Configuration, Layer};

use crate::TunConfig;

pub struct TunReader {
    inner: tun::DeviceReader,
}

pub struct TunWriter {
    inner: tun::DeviceWriter,
}

impl TunReader {
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        use tokio::io::AsyncReadExt;
        self.inner.read(buf).await.map_err(Error::Io)
    }
}

impl TunWriter {
    pub async fn send(&mut self, buf: &[u8]) -> Result<usize> {
        use tokio::io::AsyncWriteExt;
        self.inner.write(buf).await.map_err(Error::Io)
    }
}

pub struct AsyncTunDevice {
    reader: TunReader,
    writer: TunWriter,
    tun_name: String,
}

impl AsyncTunDevice {
    pub fn create(config: &TunConfig) -> Result<Self> {
        let mut tun_config = Configuration::default();
        tun_config
            .address(config.overlay_addr)
            .netmask(config.netmask)
            .mtu(config.mtu as u16)
            .layer(Layer::L3)
            .up();

        #[cfg(target_os = "linux")]
        {
            tun_config.platform(|p| {
                p.packet_information(false);
            });
        }

        if let Some(name) = &config.name {
            tun_config.tun_name(name);
        }

        let mut device = tun::create(&tun_config)
            .map_err(|e| Error::Io(std::io::Error::other(format!("TUN create: {e}"))))?;

        let tun_name = device.tun_name()
            .map_err(|e| Error::Io(std::io::Error::other(format!("TUN name: {e}"))))?;

        device.set_address(IpAddr::V4(config.overlay_addr))
            .map_err(|e| Error::Io(std::io::Error::other(format!("TUN set_address: {e}"))))?;
        device.set_netmask(IpAddr::V4(config.netmask))
            .map_err(|e| Error::Io(std::io::Error::other(format!("TUN set_netmask: {e}"))))?;
        device.enabled(true)
            .map_err(|e| Error::Io(std::io::Error::other(format!("TUN enabled: {e}"))))?;

        let async_dev = AsyncDevice::new(device)
            .map_err(|e| Error::Io(std::io::Error::other(format!("TUN async: {e}"))))?;

        let (writer, reader) = async_dev.split()
            .map_err(|e| Error::Io(std::io::Error::other(format!("TUN split: {e}"))))?;

        tracing::info!(target: "seednet", name = %tun_name, ip = %config.overlay_addr, "TUN device created");

        Ok(Self {
            reader: TunReader { inner: reader },
            writer: TunWriter { inner: writer },
            tun_name,
        })
    }

    pub fn into_split(self) -> (TunReader, TunWriter, String) {
        (self.reader, self.writer, self.tun_name)
    }

    pub fn name(&self) -> &str {
        &self.tun_name
    }

    pub fn mtu(&self) -> usize {
        OVERLAY_MTU
    }
}
