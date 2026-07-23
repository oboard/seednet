use seednet_nat::is_publicly_routable;
use std::net::SocketAddr;

pub(crate) fn local_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Scan local network interfaces for a publicly-routable IPv4 address.
/// Used as STUN fallback on servers where STUN packets are filtered.
pub(crate) fn local_public_ip(port: u16) -> Option<SocketAddr> {
    // Try cloud metadata services first (AWS, Alibaba Cloud, etc.)
    let metadata_urls = [
        "http://169.254.169.254/latest/meta-data/public-ipv4", // AWS
        "http://100.100.100.200/latest/meta-data/eipv4",       // Alibaba Cloud
    ];
    for url in metadata_urls {
        let result = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .ok()
            .and_then(|c| c.get(url).send().ok())
            .and_then(|r| r.text().ok());
        if let Some(s) = result
            && let Ok(ip) = s.trim().parse::<std::net::Ipv4Addr>()
            && is_publicly_routable(SocketAddr::from((ip, port)))
        {
            return Some(SocketAddr::from((ip, port)));
        }
    }

    // Fall back to routing table: find the outbound interface IP.
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("ip")
            .args(["route", "get", "1.1.1.1"])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        for part in s.split_whitespace().collect::<Vec<_>>().windows(2) {
            if part[0] == "src"
                && let Ok(ip) = part[1].parse::<std::net::Ipv4Addr>()
                && is_publicly_routable(SocketAddr::from((ip, port)))
            {
                return Some(SocketAddr::from((ip, port)));
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("route")
            .args(["-n", "get", "1.1.1.1"])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        for line in s.lines() {
            if let Some(rest) = line.trim().strip_prefix("interface:") {
                let iface = rest.trim();
                if let Ok(out2) = std::process::Command::new("ipconfig")
                    .args(["getifaddr", iface])
                    .output()
                    && let Ok(ip_str) = String::from_utf8(out2.stdout)
                    && let Ok(ip) = ip_str.trim().parse::<std::net::Ipv4Addr>()
                    && is_publicly_routable(SocketAddr::from((ip, port)))
                {
                    return Some(SocketAddr::from((ip, port)));
                }
            }
        }
    }
    None
}
