use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use dirs::home_dir;

fn get_db_path(filename: &str) -> String {
    println!("Getting path for database file: {}", filename);
    let home = match home_dir() {
        Some(path) => {
            println!("Home directory found: {:?}", path);
            path
        },
        None => {
            println!("Failed to get home directory");
            // Fallback to a location we know exists - current directory
            std::env::current_dir().unwrap_or_else(|_| {
                println!("Failed to get current directory too");
                Path::new(".").to_path_buf()
            })
        }
    };
    
    let db_path = home.join(".network_scanner").join(filename);
    println!("Full database path: {:?}", db_path);
    
    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                println!("Warning: Could not create parent directory: {}", e);
            });
        }
    }
    
    db_path.to_str().unwrap_or_else(|| {
        println!("Path contains invalid UTF-8");
        "."  // Fallback to current directory as a last resort
    }).to_string()
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
                let octets = i.to_be_bytes();
                ips.push(IpAddr::V4(std::net::Ipv4Addr::from(octets)));
            }
        }
        IpAddr::V6(_) => {
            println!("IPv6 ranges not fully supported yet");
        }
    }

    ips
}

//Save a discovered host to the database
pub fn save_host(host: &str) {
    let mut hosts = load_hosts();

    if !hosts.contains(host) {
        hosts.insert(host.to_string());

        let hosts_db_path = get_db_path(HOSTS_DB_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&hosts_db_path)
            .unwrap_or_else(|_| panic!("Could not open database file: {}", hosts_db_path));

        for h in hosts {
            writeln!(file, "{}", h).unwrap();
        }
    }
}

// load discovered hosts from database
pub fn load_hosts() -> HashSet<String> {
    let mut hosts = HashSet::new();
    let hosts_db_path = get_db_path(HOSTS_DB_FILE);
    if Path::new(&hosts_db_path).exists() {
        let mut file = match File::open(&hosts_db_path) {
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
    
    let services_db_path = get_db_path(SERVICES_DB_FILE);
    if Path::new(&services_db_path).exists() {
        if let Ok(mut file) = File::open(&services_db_path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                for line in contents.lines() {
                    services.insert(line.trim().to_string());
                }
            }
        }
    }

    services.insert(entry);
    
    let services_db_path = get_db_path(SERVICES_DB_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&services_db_path)
        .unwrap_or_else(|_| panic!("Could not open database file: {}", services_db_path));

    for s in services {
        writeln!(file, "{}", s).unwrap();
    }
}

pub fn load_services() -> Vec<(String, u16, String)> {
    let mut services = Vec::new();

    let services_db_path = get_db_path(SERVICES_DB_FILE);
    if Path::new(&services_db_path).exists() {
        let mut file = match File::open(&services_db_path) {
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
