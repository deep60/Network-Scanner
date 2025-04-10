pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format".to_string());
    }

    let ip = match IpAddr::from_str(parts[0]) {
        Ok(ip) => ip,
        Err(_) => return Err("Invalid IP address".to_string()),
    };

    let prefix = match parts[1].parse::<u8>() {
        Ok(prefix) => {
            if (ip.is_ipv4() && prefix > 32) || (ip.is_ipv6() && prefix > 128) {
                return Err("Invalid prefix length".to_string());
            }
        }
        


    }
}
