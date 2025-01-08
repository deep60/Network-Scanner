use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{arp, ethernet, Packet};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::Ipv4Addr;

fn scan_network(target_ip: &str) -> Vec<(Ipv4Addr, MacAddr)> {
    let mut clients = Vec::new();
    let intefaces = datalink::intefaces();
    let intefaces = interfaces
        .into_iter()
        .find(|iface| {
            iface.is_up() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.ip().is_ipv4())
        })
        .expect("No suitable ntwrk interface found.");

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => panic!("Failed to create datalink channel."),
    };

    let target_ip: Ipv4Addr = target_ip.parse().expect("Invalid IP address");
    let source_mac = interface.mac.expect("Failed to get MAC address.");
    let source_ip = interface
        .ips
        .iter()
        .find_map(|ip| {
            if let std::net::Ipv4Addr::V4(v4) = ip.ip() {
                Some(v4)
            } else {
                None
            }
        })
        .expect("No Ipv4 address found on interface");

    let arp_request = arp::ArpPacket::new(
        ethernet::EthernetPacket::new_ethernet_packet_builder()
            .set_destination(MacAddr::broadcast())
            .set_source(source_mac)
            .set_payload(
                &arp::ArpPacket::new_arp_request(source_mac, source_ip, target_ip).unwrap(),
            )
            .build()
            .unwrap(),
    );

    tx.send_to(&arp_request.packet(), None).unwrap();

    for packet in rx.iter() {
        if let Some(arp_packet) = arp::ArpPacket::new(packet.packet()) {
            if arp_packet.get_operatioon() == arp::ArpOperation::Reply {
                clients.push((
                    arp_packet.get_sender_proto_addr(),
                    arp_packet.get_sender_hw_addr(),
                ));
            }
        }
    }
    clients
}

fn save_to_pcap(clients: &[(Ipv4Addr, MacAddr)], filename: &str) {
    use pcap::Capture;
    let mut capture = Capture::savefile(filename).expect("Failed to create pcap file.");

    for &(ip, mac) in clients {
        println!("Saving packet for IP: {}, MAC: {}", ip, mac);
    }
    println!("Captured packets saved to {}", filename);
}

fn main() {
    print!("Enter your IP address too scan the network: ");
    io::stdout().flush().unwrap();
    let mut target_ip = String::new();
    io::stdin().read_line(&mut target_ip).unwrap();
    let target_ip = target_ip.trim();

    let clients = scan_network(target_ip);

    println!("Available devices on the network:");
    println!("{:<16}   {}", "IP", "MAC");
    for (ip, mac) in &clients {
        println!("{:<16}   {}", ip, mac);
    }

    print!("Enter the filename to save the captured packets (e.g., network_scan.pcap): ");
    io::stdout().flush().unwrap();
    let mut filename = String::new();
    io::stdin().read_line(&mut filename).unwrap();
    let filename = filename.trim();

    save_to_pcap(&clients, filename);
}
