use std::net::Ipv4Addr;

use seednet_common::{Error, Result};

#[cfg(unix)]
pub async fn configure_interface(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let ip_str = ip.to_string();
        let netmask_str = netmask.to_string();

        // Set interface address.
        let output = tokio::process::Command::new("ifconfig")
            .args([
                name,
                &ip_str as &str,
                &ip_str as &str,
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

        // Add subnet route so the kernel forwards 10.88.0.0/16 into the TUN.
        // Without this, packets to remote overlay IPs are dropped by the kernel.
        let prefix = seednet_common::OVERLAY_SUBNET_PREFIX;
        let subnet = format!("{}/{}", seednet_common::OVERLAY_SUBNET_BASE, prefix);
        let route_output = tokio::process::Command::new("route")
            .args(["-q", "-n", "add", "-net", &subnet, "-interface", name])
            .output()
            .await;

        match route_output {
            Ok(o) if o.status.success() => {
                tracing::info!(target: "seednet", subnet = %subnet, dev = %name, "route added");
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // "route already exists" is fine on re-launch.
                if !stderr.contains("exists") {
                    tracing::warn!(target: "seednet", "route add failed: {stderr}");
                }
            }
            Err(e) => {
                tracing::warn!(target: "seednet", "route command failed: {e}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let _ = (ip, netmask);

        let output = tokio::process::Command::new("ip")
            .args(["link", "set", name, "up"])
            .output()
            .await
            .map_err(Error::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(target: "seednet", "ip link set up failed: {stderr}");
        }

        let prefix = seednet_common::OVERLAY_SUBNET_PREFIX;
        let subnet = format!("{}/{prefix}", seednet_common::OVERLAY_SUBNET_BASE);
        let output = tokio::process::Command::new("ip")
            .args(["route", "add", &subnet, "dev", name])
            .output()
            .await;

        match output {
            Ok(o) if o.status.success() => {
                tracing::info!(target: "seednet", subnet = %subnet, dev = %name, "route added");
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("File exists") {
                    tracing::warn!(target: "seednet", "ip route add failed: {stderr}");
                }
            }
            Err(e) => {
                tracing::warn!(target: "seednet", "ip route command failed: {e}");
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
