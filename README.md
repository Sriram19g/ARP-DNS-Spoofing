
# ARP-DNS Spoofing

This project demonstrates a Man-in-the-Middle (MiM) attack by combining ARP spoofing and DNS spoofing techniques. It enables interception and redirection of traffic on a local network by impersonating a gateway and manipulating DNS responses.

## Features
- **ARP Spoofing**: Spoofs ARP packets to impersonate the gateway and intercept victim traffic.
- **DNS Spoofing**: Redirects DNS queries to a specified IP address (e.g., an attacker-controlled web server).
- **Network Traffic Sniffing**: Captures and analyzes DNS packets.
- **HTTP Redirection**: Redirects traffic to a local Apache server.

## Files
- **ARPspoof.py**: Performs ARP spoofing to redirect victim traffic.
- **DNSsniff.py**: Sniffs DNS traffic to extract domain names.
- **DNSspoof.py**: Modifies DNS responses to redirect traffic.
- **services.py**: Contains utility functions for the attack tools.

## Requirements
- Python 3.x
- Scapy
- Apache Web Server (for HTTP redirection)

## Setup
1. Install dependencies:
   ```bash
   pip install scapy
   ```
2. Start Apache Web Server on your local machine.
3. Run the ARP spoofing and DNS spoofing scripts to begin the attack.

## Usage
1. **ARP Spoofing**: Run the ARP spoofing script to redirect victim traffic through the attacker's machine.
   ```bash
   python ARPspoof.py
   ```
2. **DNS Spoofing**: Launch the DNS spoofing script to intercept DNS requests and redirect them to a malicious IP.
   ```bash
   python DNSspoof.py
   ```
3. **DNS Sniffing**: Use the DNS sniffer to analyze network traffic and capture domain names.
   ```bash
   python DNSsniff.py
   ```

## Legal Disclaimer
This tool is for educational purposes only. Misuse of this tool may result in legal action. Use responsibly and only on networks you have permission to test.
