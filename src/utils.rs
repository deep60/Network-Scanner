use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use dirs::home_dir;

fn get_db_path(filename: &str) -> String {
    let home = home_dir().expect("Could not get home directory");
    let db_path = home.join(filename);
    db_path.to_str().unwrap().to_string()
}

const HOSTS_DB_FILE: &str = "network_scanner_hosts.db";
const SERVICES_DB_FILE: &str = "network_scanner_services.db";

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
            prefix
        }
        Err(_) => return Err("Invalid prefix length".to_string()),
    };
    Ok((ip, prefix))
}

// Generate all IP addr in a CIDR range
pub fn generate_ip_range(base_ip: IpAddr, prefix: u8) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    match base_ip {
        IpAddr::V4(ipv4) => {
            let ipv4_int = u32::from(ipv4);
            let mask = !((1 << (32 - prefix)) - 1);
            let network = ipv4_int & mask;
            let broadcast = network | !mask;

            //Skip ntwrk and broadcast addr from /31 and larger
            let start = if prefix < 31 { network + 1 } else { network };

            let end = if prefix < 31 {
                broadcast - 1
            } else {
                broadcast
            };

            for i in start..=end {
                let octets = [(i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8];
                ips.push(IpAddr::V4(std::net::Ipv4Addr::from(octets)));
            }
        }
        IpAddr::V6(_) => {
            println!("IPv6 ranges not fully supportes yet");
        }
    }

    ips
}

//Save a discovered host to the database
pub fn save_host(host: &str) {
    let mut hosts = load_hosts();

    if !hosts.contains(host) {
        hosts.insert(host.to_string());

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(HOSTS_DB_FILE)
            .unwrap_or_else(|_| panic!("Could not open database file: {}", HOSTS_DB_FILE));

        for h in hosts {
            writeln!(file, "{}", h).unwrap();
        }
    }
}

// load discovered hosts from database
pub fn load_hosts() -> HashSet<String> {
    let mut hosts = HashSet::new();

    if Path::new(HOSTS_DB_FILE).exists() {
        let mut file = match File::open(HOSTS_DB_FILE) {
            Ok(file) => file,
            Err(_) => return hosts,
        };

        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for line in contents.lines() {
                hosts.insert(line.to_string());
            }
        }
    }

    hosts
}

pub fn save_service(host: &str, port: u16, service: &str) {
    let entry = format!("{}:{}:{}", host, port, service);

    let mut services = HashSet::new();

    if Path::new(SERVICES_DB_FILE).exists() {
        if let Ok(mut file) = File::open(SERVICES_DB_FILE) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                for line in contents.lines() {
                    services.insert(line.trim().to_string());
                }
            }
        }
    }

    if !services.contains(&entry) {
        services.insert(entry);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(SERVICES_DB_FILE)
            .unwrap_or_else(|_| panic!("Could not open database file: {}", SERVICES_DB_FILE));

        for s in services {
            writeln!(file, "{}", s).unwrap();
        }
    }
}

// load discovered services from the database
pub fn load_services() -> Vec<(String, u16, String)> {
    let mut services = Vec::new();

    if Path::new(SERVICES_DB_FILE).exists() {
        let mut file = match File::open(SERVICES_DB_FILE) {
            Ok(file) => file,
            Err(_) => return services,
        };

        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for line in contents.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    let host = parts[0].to_string();
                    if let Ok(port) = parts[1].parse::<u16>() {
                        let service = parts[2..].join(":");
                        services.push((host, port, service));
                    }
                }
            }
        }
    }

    services
}
