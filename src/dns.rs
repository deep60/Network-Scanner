use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

//Try DNS zone transfer
pub fn attempt_zone_transfer(domain: &str) -> Vec<String> {
    let output = Command::new("dig")
        .args(&["AXFR", domain, "@ns1.target.com"])
        .output();

    let mut results = Vec::new();
    match output {
        Ok(output) => {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if !line.start_with(';') && !line.is_empty() {
                        results.push(line.to_string());
                    }
                }
            }
        }
        Err(_) => {}
    }

    results
}

// Discover subdomains using common prefixes
pub fn discover_subdomains(domain: &str) -> Vec<String> {
    let common_prefixes = vec![
        "www", "mail", "remote", "blog", "webmail", "server", "ns", "ns1", "ns2", "smtp", "secure",
        "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "admin", "host", "dns", "mx", "pop",
        "pop3", "imap", "forum", "stage", "dev", "demo",
    ];
    let mut subdomains = Vec::new();
    for prefixes in common_prefixes {
        let subdomain = format!("{}.{}", prefix, domain);
        subdomains.push(subdomain);
    }
    subdomains
}

//Resolve hostname to IP
pub fn resolve_host(hostname: &str) -> Option<IpAddr> {
    let output = Command::new("dig").args(&["short", hostname, "A"]).output();

    match output {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !output_str.is_empty() {
                if let Ok(ip) = IpAddr::from_str(&output_str) {
                    return Some(ip);
                }
            }
        }
        Err(_) => {}
    }

    None
}
