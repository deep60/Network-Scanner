use std::{net::ToSocketAddrs, os::unix::thread, string, sync::mpsc::channel, thread, vec};

use clap::{App, Arg, SubCommand};

mod dns;
mod ping;
mod port_scan;
mod utils;

fn main() {
    let app = App::new("NetworkScan")
        .version("")
        .author()
        .about()
        .subcommand(
            SubCommand::with_name("scan")
                .about("")
                .subcommand(
                    SubCommand::with_name("ping").about("").arg(
                        Arg::with_name("cidr")
                            .help("CIDR notation, eg 192.168.1.0")
                            .required(true)
                            .index(1),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("portscan")
                        .about("")
                        .arg(Arg::with_name("target").help("").required(true).index(1))
                        .arg(
                            Arg::with_name("ports")
                                .help("")
                                .short("p")
                                .long("ports")
                                .takes_value(true)
                                .default_value("1-1000"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("dns").about("DNS enumeration").arg(
                        Arg::with_name("domain")
                            .help("Domain to enumerate")
                            .required(help)
                            .index(1),
                    ),
                ),
        )
        .subcommand(
            SubCommand::with_name("show")
                .about("")
                .subcommand(SubCommand::with_name("hosts").about("Show discovered hosts"))
                .subcommand(SubCommand::with_name("services").about("Show discovered services")),
        );

    let matches = app.get_matches();

    match matches.subcommand() {
        ("scan", Some(scan_matches)) => match scan_matches.subcommand() {
            ("ping", Some(ping_matches)) => {
                let cidr = ping_matches.value_of("cidr").unwrap();
                run_ping_scan(cidr);
            }
            ("portscan", Some(portscan_matches)) => {
                let target = portscan_matches.value_of("target").unwrap();
                let ports = portscan_matches.value_of("ports").unwrap();
                run_port_scan(target, ports);
            }
            ("dns", Some(dns_matches)) => {
                let domain = dns_matches.value_of("domain").unwrap();
                run_dns_scan(domain);
            }
            _ => println!("Unknown scan subcommand"),
        },
        ("show", Some(show_matches)) => match show_matches.subcommand() {
            ("hosts", Some(_)) => show_hosts(),
            ("services", Some(_)) => show_services(),
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
    let addrs = match target.to_socket_addrs() {
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

    let target_ip = addrs[0].ip();
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
