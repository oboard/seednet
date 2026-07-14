use std::net::Ipv4Addr;

use seednet_common::{Error, Result};

use crate::TunConfig;

#[cfg(unix)]
pub async fn configure_interface(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
    configure_interface_full(name, ip, netmask, None).await
}

#[cfg(unix)]
pub async fn configure_interface_full(
    name: &str,
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    config: Option<&TunConfig>,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let ip_str = ip.to_string();
        let netmask_str = netmask.to_string();
        let dest_str = seednet_common::OVERLAY_SUBNET_BASE.to_string();

        let output = tokio::process::Command::new("ifconfig")
            .args([
                name,
                &ip_str as &str,
                &dest_str as &str,
                "netmask",
                &netmask_str as &str,
                "up",
            ])
            .output()
            .await
            .map_err(Error::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(target: "seednet", "ifconfig failed: {stderr}");
        }

        let prefix = seednet_common::OVERLAY_SUBNET_PREFIX;
        let subnet = format!("{}/{}", seednet_common::OVERLAY_SUBNET_BASE, prefix);
        let route_output = tokio::process::Command::new("route")
            .args(["-q", "-n", "add", "-net", &subnet, "-interface", name])
            .output()
            .await;

        match route_output {
            Ok(o) if o.status.success() => {
                tracing::info!(target: "seednet", subnet = %subnet, dev = %name, "IPv4 route added");
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("exists") {
                    tracing::warn!(target: "seednet", "route add failed: {stderr}");
                }
            }
            Err(e) => {
                tracing::warn!(target: "seednet", "route command failed: {e}");
            }
        }

        // Add IPv6 address if provided.
        if let Some(ipv6) = config.and_then(|c| c.overlay_ipv6) {
            let ipv6_str = format!("{ipv6}/48");
            let v6_output = tokio::process::Command::new("ifconfig")
                .args([name, "inet6", &ipv6_str, "alias"])
                .output()
                .await;
            match v6_output {
                Ok(o) if o.status.success() => {
                    tracing::info!(target: "seednet", addr = %ipv6, dev = %name, "IPv6 address added");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if !stderr.contains("exists") && !stderr.contains("SIOCDIFADDR") {
                        tracing::warn!(target: "seednet", "ifconfig inet6 failed: {stderr}");
                    }
                }
                Err(e) => tracing::warn!(target: "seednet", "ifconfig inet6 failed: {e}"),
            }

            // Route the /48 ULA prefix into the TUN.
            let prefix48 = format!(
                "fd{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/48",
                ipv6.octets()[1],
                ipv6.octets()[2],
                ipv6.octets()[3],
                ipv6.octets()[4],
                ipv6.octets()[5],
                ipv6.octets()[6],
            );
            let v6_route = tokio::process::Command::new("route")
                .args(["-q", "-n", "add", "-inet6", &prefix48, "-interface", name])
                .output()
                .await;
            if let Ok(o) = v6_route {
                if !o.status.success() {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if !stderr.contains("exists") {
                        tracing::warn!(target: "seednet", "IPv6 route add failed: {stderr}");
                    }
                } else {
                    tracing::info!(target: "seednet", prefix = %prefix48, dev = %name, "IPv6 route added");
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = tokio::process::Command::new("ip")
            .args(["link", "set", name, "up"])
            .output()
            .await
            .map_err(Error::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(target: "seednet", "ip link set up failed: {stderr}");
        }

        // Assign IPv4 address.
        let prefix = seednet_common::OVERLAY_SUBNET_PREFIX;
        let addr_str = format!("{ip}/{prefix}");
        let addr_out = tokio::process::Command::new("ip")
            .args(["addr", "add", &addr_str, "dev", name])
            .output()
            .await;
        match addr_out {
            Ok(o) if o.status.success() => {
                tracing::info!(target: "seednet", addr = %addr_str, dev = %name, "IPv4 address assigned");
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("File exists") {
                    tracing::warn!(target: "seednet", "ip addr add failed: {stderr}");
                }
            }
            Err(e) => tracing::warn!(target: "seednet", "ip addr add failed: {e}"),
        }

        let subnet = format!("{}/{prefix}", seednet_common::OVERLAY_SUBNET_BASE);
        let route_out = tokio::process::Command::new("ip")
            .args(["route", "add", &subnet, "dev", name])
            .output()
            .await;
        match route_out {
            Ok(o) if o.status.success() => {
                tracing::info!(target: "seednet", subnet = %subnet, dev = %name, "IPv4 route added");
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("File exists") {
                    tracing::warn!(target: "seednet", "ip route add failed: {stderr}");
                }
            }
            Err(e) => tracing::warn!(target: "seednet", "ip route command failed: {e}"),
        }

        // Add IPv6 address if provided.
        if let Some(ipv6) = config.and_then(|c| c.overlay_ipv6) {
            let ipv6_str = format!("{ipv6}/48");
            let v6_addr = tokio::process::Command::new("ip")
                .args(["-6", "addr", "add", &ipv6_str, "dev", name])
                .output()
                .await;
            match v6_addr {
                Ok(o) if o.status.success() => {
                    tracing::info!(target: "seednet", addr = %ipv6, dev = %name, "IPv6 address assigned");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if !stderr.contains("File exists") {
                        tracing::warn!(target: "seednet", "ip -6 addr add failed: {stderr}");
                    }
                }
                Err(e) => tracing::warn!(target: "seednet", "ip -6 addr add failed: {e}"),
            }

            // Route the /48 ULA prefix.
            let prefix48 = format!(
                "fd{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/48",
                ipv6.octets()[1],
                ipv6.octets()[2],
                ipv6.octets()[3],
                ipv6.octets()[4],
                ipv6.octets()[5],
                ipv6.octets()[6],
            );
            let v6_route = tokio::process::Command::new("ip")
                .args(["-6", "route", "add", &prefix48, "dev", name])
                .output()
                .await;
            match v6_route {
                Ok(o) if o.status.success() => {
                    tracing::info!(target: "seednet", prefix = %prefix48, dev = %name, "IPv6 route added");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if !stderr.contains("File exists") {
                        tracing::warn!(target: "seednet", "ip -6 route add failed: {stderr}");
                    }
                }
                Err(e) => tracing::warn!(target: "seednet", "ip -6 route add failed: {e}"),
            }
        }
    }

    Ok(())
}

#[cfg(not(unix))]
pub async fn configure_interface(_name: &str, _ip: Ipv4Addr, _netmask: Ipv4Addr) -> Result<()> {
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "TUN interface configuration is not supported on this platform",
    )))
}

#[cfg(not(unix))]
pub async fn configure_interface_full(
    _name: &str,
    _ip: Ipv4Addr,
    _netmask: Ipv4Addr,
    _config: Option<&TunConfig>,
) -> Result<()> {
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "TUN interface configuration is not supported on this platform",
    )))
}
