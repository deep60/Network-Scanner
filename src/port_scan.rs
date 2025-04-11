use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

// Check if a port is open
pub fn check_port(ip: IpAddr, port: u16) -> bool {
    let socket = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&socket, Duration::from_millis(500)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

//Try to identify the service running on a port
pub fn identify_service(port: u16) -> String {
    match port {
        21 => "FTP".to_string(),
        22 => "SSH".to_string(),
        23 => "Telnet".to_string(),
        25 => "SMTP".to_string(),
        53 => "DNS".to_string(),
        80 => "HTTP".to_string(),
        110 => "POP3".to_string(),
        111 => "RPC".to_string(),
        135 => "RPC".to_string(),
        139 => "NetBIOS".to_string(),
        143 => "IMAP".to_string(),
        161 => "SNMP".to_string(),
        443 => "HTTPS".to_string(),
        445 => "SMB".to_string(),
        993 => "IMAPS".to_string(),
        995 => "POP3S".to_string(),
        1723 => "PPTP".to_string(),
        3306 => "MySQL".to_string(),
        3389 => "RDP".to_string(),
        5900 => "VNC".to_string(),
        8080 => "HTTP-Proxy".to_string(),
        _ => "Unknown".to_string(),
    }
}
