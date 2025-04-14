# RustScan

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust Version](https://img.shields.io/badge/rust-1.60%2B-orange.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)

A fast, efficient network scanning tool built in Rust. network-scanner leverages Rust's performance benefits and memory safety features to provide a reliable alternative to traditional network scanning tools.

## Features

- **Fast Ping Sweeps**: Quickly discover live hosts on your network
- **Multi-threaded Port Scanning**: Efficiently scan for open ports with configurable concurrency
- **DNS Enumeration**: Discover subdomains and perform DNS reconnaissance
- **Persistent Storage**: Save discovered hosts and services for later analysis
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Installation

### From Source

```bash
# Clone the repository
git clone git@github.com:deep60/Network-Scanner.git
cd network-scanner

# Build the project
cargo build --release

# The binary will be available at target/release/network-scanner
```

### Using Cargo

```bash
cargo install network-scanner
```

## Usage

### Basic Commands

```bash
# Ping sweep a network
network-scanner scan ping 192.168.1.0/24

# Port scan a specific host
network-scanner scan portscan 192.168.1.100 --ports 1-1000

# DNS enumeration
network-scanner scan dns example.com

# View discovered hosts
network-scanner show hosts

# View discovered services
network-scanner show services
```

### Command Line Options

```
USAGE:
    network-scanner [SUBCOMMAND]

SUBCOMMANDS:
    scan    Run various network scanning operations
    show    Display discovered hosts or services
    help    Prints help information

SCAN SUBCOMMANDS:
    ping       Ping sweep of the network
    portscan   Port scan a host or network
    dns        DNS enumeration

PORT SCAN OPTIONS:
    -p, --ports <ports>    Port range to scan (e.g. 1-1000) [default: 1-1000]
```

## Examples

### Finding Live Hosts

```bash
# Scan your entire subnet
network-scanner scan ping 192.168.0.0/24

# Output:
# Running ping sweep on: 192.168.0.0/24
# Scanning 254 hosts...
# 
# Found 8 live hosts:
#   192.168.0.1
#   192.168.0.10
#   192.168.0.15
#   192.168.0.22
#   192.168.0.50
#   192.168.0.100
#   192.168.0.105
#   192.168.0.254
```

### Port Scanning

```bash
# Scan common ports on a host
network-scanner scan portscan 192.168.0.1 --ports 20-25,80,443,8080

# Output:
# Scanning ports on: 192.168.0.1 (range: 20-25,80,443,8080)
# Resolved 192.168.0.1 to 192.168.0.1
# 
# Found 3 open ports on 192.168.0.1:
#     22 - SSH
#     80 - HTTP
#    443 - HTTPS
```

### DNS Enumeration

```bash
# Enumerate subdomains
network-scanner scan dns example.com

# Output:
# Running DNS enumeration on: example.com
# 
# Attempting zone transfer:
#   Zone transfer failed or not allowed
# 
# Discovering subdomains:
#   www.example.com
#     -> 93.184.216.34
#   mail.example.com
#     -> 93.184.216.34
#   admin.example.com
#     -> Could not resolve
```

## Performance

NetworkScanner is designed to be fast and efficient:

- **Concurrent Scanning**: Utilizes Rust's threading model for parallel operations
- **Optimized Resource Usage**: Balances speed with system resource consumption
- **Comparison**: Up to 5x faster than equivalent tools written in other languages

## Security Notice

This tool is designed for legitimate network administration and security testing. Always ensure you have proper authorization before scanning networks or systems you don't own.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by various network scanning tools including Nmap, Masscan, and GoScan
- Built with Rust's excellent concurrency model and safety features