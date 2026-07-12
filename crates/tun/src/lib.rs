use std::net::Ipv4Addr;

use seednet_common::{
    Error, OVERLAY_MTU, OVERLAY_SUBNET_BASE, OVERLAY_SUBNET_PREFIX, OverlayAddr, Result,
};

#[derive(Clone, Debug)]
pub struct TunConfig {
    pub overlay_addr: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: usize,
    pub name: Option<String>,
}

impl TunConfig {
    pub fn new(overlay: OverlayAddr) -> Self {
        Self {
            overlay_addr: overlay.ip(),
            netmask: subnet_mask(OVERLAY_SUBNET_PREFIX),
            mtu: OVERLAY_MTU,
            name: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    pub fn overlay_addr(&self) -> Ipv4Addr {
        self.overlay_addr
    }

    pub fn network(&self) -> Ipv4Addr {
        let base = OVERLAY_SUBNET_BASE.octets();
        Ipv4Addr::new(base[0], base[1], 0, 0)
    }
}

pub fn subnet_mask(prefix: u8) -> Ipv4Addr {
    if prefix > 32 {
        return Ipv4Addr::BROADCAST;
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    Ipv4Addr::from(mask)
}

#[derive(Debug)]
pub enum TunEvent {
    Packet(Vec<u8>),
    Closed,
}

pub trait TunDevice: Send + Sync {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()>;
    fn name(&self) -> &str;
    fn mtu(&self) -> usize;
}

pub fn create_tun(_config: &TunConfig) -> Result<Box<dyn TunDevice>> {
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "TUN creation requires platform privileges; enable 'real-tun' feature and run as root",
    )))
}

#[cfg(unix)]
mod real;

#[cfg(unix)]
pub mod platform;

#[cfg(unix)]
pub use real::{AsyncTunDevice, TunReader, TunWriter};

#[cfg(not(unix))]
mod stub;

#[cfg(not(unix))]
pub use stub::{AsyncTunDevice, TunReader, TunWriter};

#[cfg(not(unix))]
pub mod platform;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_config_overlay_ip() {
        let overlay = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 42));
        let cfg = TunConfig::new(overlay);
        assert_eq!(cfg.overlay_addr(), Ipv4Addr::new(10, 88, 1, 42));
        assert_eq!(cfg.netmask, Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(cfg.mtu, OVERLAY_MTU);
        assert_eq!(cfg.network(), Ipv4Addr::new(10, 88, 0, 0));
    }

    #[test]
    fn subnet_mask_calculation() {
        assert_eq!(subnet_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(subnet_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(subnet_mask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(subnet_mask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn with_name_and_mtu() {
        let overlay = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 1));
        let cfg = TunConfig::new(overlay).with_name("seednet0").with_mtu(9000);
        assert_eq!(cfg.name.as_deref(), Some("seednet0"));
        assert_eq!(cfg.mtu, 9000);
    }

    #[test]
    fn create_tun_requires_privileges() {
        let overlay = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 1));
        let cfg = TunConfig::new(overlay);
        let result = create_tun(&cfg);
        assert!(result.is_err());
    }
}
