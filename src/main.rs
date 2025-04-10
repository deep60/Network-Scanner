use clap::{App, Arg, SubCommand};

fn main() {
    let app = App::new("NetworkScan")
        .version("")
        .author()
        .about()
        .subcommand(
            SubCommand::with_name("scan")
               .about("")
               .subcommand(
                   SubCommand::with_name("ping")
                      .about("")
                      .arg(
                          Arg::with_name("cidr")
                            .help("CIDR notation, eg 192.168.1.0")
                            .required(true)
                            .index(1)
                      ),
               )
               .subcommand(
                   SubCommand::with_name("portscan")
                      .about("")
                      .arg(
                          Arg::with_name("target")
                              .help("")
                              .required(true)
                              .index(1),
                      )
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
                   SubCommand::with_name("dns")
                       .about("DNS enumeration")
                       .arg(
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
     println!("Runnning ping sweep on: {}", cidr);

     let network =
 }
