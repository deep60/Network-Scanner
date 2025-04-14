use clap::{Command, Arg};
use std::net::{IpAddr, ToSocketAddrs};
use std::process::{Command as ProcessCommand, Stdio};
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

mod dns;
mod ping;
mod port_scan;
mod utils;

fn main() {
    let app = Command::new("NetworkScan")
        .version("")
        .author("")
        .about("")
        .subcommand(
            Command::new("scan")
                .about("")
                .subcommand(
                    Command::new("ping").about("").arg(
                        Arg::new("cidr")
                            .help("CIDR notation, eg 192.168.1.0")
                            .required(true)
                            .index(1),
                    ),
                )
                .subcommand(
                    Command::new("portscan")
                        .about("")
                        .arg(Arg::new("target").help("").required(true).index(1))
                        .arg(
                            Arg::new("ports")
                                .help("")
                                .short('p')
                                .long("ports")
                                .value_parser(clap::value_parser!(String))
                                .default_value("1-1000"),
                        ),
                )
                .subcommand(
                    Command::new("dns").about("DNS enumeration").arg(
                        Arg::new("domain")
                            .help("Domain to enumerate")
                            .required(true)
                            .index(1),
                    ),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("")
                .subcommand(Command::new("hosts").about("Show discovered hosts"))
                .subcommand(Command::new("services").about("Show discovered services")),
        );

    let matches = app.get_matches();

    match matches.subcommand() {
        Some(("scan", scan_matches)) => match scan_matches.subcommand() {
            Some(("ping", ping_matches)) => {
                let cidr = ping_matches.get_one::<String>("cidr").unwrap();
                run_ping_scan(cidr);
            }
            Some(("portscan", portscan_matches)) => {
                let target = portscan_matches.get_one::<String>("target").unwrap();
                let ports = portscan_matches.get_one::<String>("ports").unwrap();
                run_port_scan(target, ports);
            }
            Some(("dns", dns_matches)) => {
                let domain = dns_matches.get_one::<String>("domain").unwrap();
                run_dns_scan(domain);
            }
            _ => println!("Unknown scan subcommand"),
        },
        Some(("show", show_matches)) => match show_matches.subcommand() {
            Some(("hosts", _)) => show_hosts(),
            Some(("services", _)) => show_services(),
            _ => println!("Unknown show subcommand"),
        },
        _ => println!("Unknown command, Use --help for use information."),
    }
}

// Implementation of ping scanning functionality
fn run_ping_scan(cidr: &str) {
    println!("Running ping sweep on: {}", cidr);

    let network = match utils::parse_cidr(cidr) {
        Ok((base_ip, prefix)) => (base_ip, prefix),
        Err(e) => {
            eprint!("Error parsing CIDR: {}", e);
            return;
        }
    };

    let (tx, rx) = channel();
    let mut threads = vec![];

    //Generate all IPs in the range
    let hosts = utils::generate_ip_range(network.0, network.1);
    println!("Scanning {} hosts...", hosts.len());

    for ip in hosts {
        let tx = tx.clone();
        let thread = thread::spawn(move || {
            if ping::ping_host(&ip.to_string()) {
                tx.send(ip).unwrap();
            }
        });
        threads.push(thread);
    }

    // Join all threads
    for thread in threads {
        thread.join().unwrap();
    }

    // Process results
    drop(tx);
    let mut live_hosts = vec![];
    for ip in rx {
        live_hosts.push(ip);
    }

    println!("\nFound {} live hosts:", live_hosts.len());
    for host in live_hosts {
        println!(" {}", host);
        utils::save_host(&host.to_string());
    }
}

// Implementation of port scanning functionality
fn run_port_scan(target: &str, port_range: &str) {
    println!("Scanning ports on: {} (range: {})", target, port_range);

    //Parse port range
    let (start_port, end_port) = match parse_port_range(port_range) {
        Ok(range) => range,
        Err(e) => {
            eprintln!("Error parsing port range: {}", e);
            return;
        }
    };

    //Resolve the target to an IP address
    let target_ip = match IpAddr::from_str(target) {
        Ok(ip) => {
            // Successfully parsed as an IP address
            ip
        },
        Err(_) => {
            // If not a valid IP address, try to resolve as hostname
            // to_socket_addrs requires a port, so we add a dummy port
            let target_with_port = format!("{}:80", target);
            let addrs = match target_with_port.to_socket_addrs() {
                Ok(addrs) => addrs.collect::<Vec<_>>(),
                Err(e) => {
                    eprintln!("Error resolving target: {}", e);
                    return;
                }
            };

            if addrs.is_empty() {
                eprintln!("Could not resolve target");
                return;
            }

            addrs[0].ip()
        }
    };
    
    println!("Resolved {} to {}", target, target_ip);

    //create threads for port scanning
    let (tx, rx) = channel();
    let mut threads = vec![];

    for port in start_port..=end_port {
        let tx = tx.clone();
        let ip = target_ip.clone();

        let thread = thread::spawn(move || {
            if port_scan::check_port(ip, port) {
                tx.send(port).unwrap();
            }
        });
        threads.push(thread);

        //limit max concurrent threads
        if threads.len() >= 100 {
            threads.remove(0).join().unwrap();
        }
    }

    //join all threads
    for thread in threads {
        thread.join().unwrap();
    }

    //Process results
    drop(tx);
    let mut open_ports = vec![];
    for port in rx {
        open_ports.push(port);
    }

    open_ports.sort();

    println!("\nFound {} open ports on {}:", open_ports.len(), target);
    for port in open_ports {
        let service = port_scan::identify_service(port);
        println!(" {:5} - {}", port, service);
        utils::save_service(&target_ip.to_string(), port, &service);
    }
}

//Implementation of dns scanning functionality
fn run_dns_scan(domain: &str) {
    println!("Running DNS enumeration on: {}", domain);
    // try zone transfer
    println!("\nAttempting zone transfer:");
    let results = dns::attempt_zone_transfer(domain);
    if results.is_empty() {
        println!("Zone transfer failed or not allowed");
    } else {
        for record in results {
            println!(" {}", record);
        }
    }

    // Discover subdomains
    println!("\nDiscovering subdomains:");
    let subdomains = dns::discover_subdomains(domain);
    for subdomain in subdomains {
        println!(" {}", subdomain);
        //try to resolve each subdomains
        match dns::resolve_host(&subdomain) {
            Some(ip) => {
                println!("  -> {}", ip);
                utils::save_host(&ip.to_string());
            }
            None => println!("   -> Could not resolve"),
        }
    }
}
//Show discovered hosts from database
fn show_hosts() {
    println!("Discovered hosts:");
    let hosts = utils::load_hosts();
    if hosts.is_empty() {
        println!("  No hosts discovered yet");
    } else {
        for host in hosts {
            println!("  {}", host);
        }
    }
}

//show discovered services from database
fn show_services() {
    println!("Discovered services:");
    let services = utils::load_services();
    if services.is_empty() {
        println!("  No services discovered yet");
    } else {
        for (host, port, service) in services {
            println!("  {}:{} -{}", host, port, service);
        }
    }
}

// Helper func to parse port range (e.g., "1-1000")
fn parse_port_range(range: &str) -> Result<(u16, u16), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() == 1 {
        //Single port
        let port = parts[0].parse::<u16>().map_err(|e| e.to_string())?;
        Ok((port, port))
    } else if parts.len() == 2 {
        // Port range
        let start = parts[0].parse::<u16>().map_err(|e| e.to_string())?;
        let end = parts[1].parse::<u16>().map_err(|e| e.to_string())?;
        if start > end {
            return Err("Start port cannot be greater than end port".to_string());
        }
        Ok((start, end))
    } else {
        Err("Invalid port range format".to_string())
    }
}
