use std::net::Ipv4Addr;

use seednet_common::{Error, Result};

pub async fn configure_interface(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let ip_str = ip.to_string();
        let netmask_str = netmask.to_string();
        let output = tokio::process::Command::new("ifconfig")
            .args([name, &ip_str as &str, &ip_str as &str, "netmask", &netmask_str as &str, "up"])
            .output()
            .await
            .map_err(Error::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(target: "seednet", "ifconfig failed: {stderr}");
        }
    }

    #[cfg(target_os = "linux")]
    {
        let ip_str = format!("{}/16", ip);
        let output = tokio::process::Command::new("ip")
            .args(["addr", "add", &ip_str, "dev", name])
            .output()
            .await;

        match output {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("File exists") {
                    tracing::warn!(target: "seednet", "ip addr add failed: {stderr}");
                }
            }
            Err(e) => {
                tracing::warn!(target: "seednet", "ip command failed: {e}");
            }
        }

        let output = tokio::process::Command::new("ip")
            .args(["link", "set", name, "up"])
            .output()
            .await
            .map_err(Error::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(target: "seednet", "ip link set up failed: {stderr}");
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (name, ip, netmask);
    }

    Ok(())
}
