from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
from prettytable import PrettyTable
from colorama import init, Fore, Style
import socket

# Initialize colorama
init(autoreset=True)

# Dictionary to store tables for each source IP
tables = {}

def resolve_domain_to_ip(domain_name):
    try:
        # Resolve the domain name to IP address
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.error:
        return "N/A"  # Return "N/A" if resolution fails

def display_packet_info(src_ip, domain_name):
    domain_ip = resolve_domain_to_ip(domain_name)  # Get the domain IP
    # Check if there is already a table for the source IP
    if src_ip not in tables:
        # Create a new table for the source IP
        table = PrettyTable([f"{Fore.CYAN}Source IP{Style.RESET_ALL}", 
                             f"{Fore.YELLOW}Domain Name{Style.RESET_ALL}", 
                             f"{Fore.GREEN}Domain IP{Style.RESET_ALL}"])
        tables[src_ip] = table

    # Add the new entry to the table
    tables[src_ip].add_row([f"{Fore.CYAN}{src_ip}{Style.RESET_ALL}", 
                             f"{Fore.YELLOW}{domain_name}{Style.RESET_ALL}", 
                             f"{Fore.GREEN}{domain_ip}{Style.RESET_ALL}"])

    # Clear the console and print all tables
    os.system('clear')
    for ip, table in tables.items():
        print(f"\n{Fore.MAGENTA}Source IP: {ip}{Style.RESET_ALL}")
        print(table)

def process_packet(packet):
    # Convert NetfilterQueue packet to Scapy packet
    scapy_packet = IP(packet.get_payload())

    # Check if the packet has DNS Query
    if scapy_packet.haslayer(DNSQR):
        # Extract source IP (end user) and domain name
        src_ip = scapy_packet[IP].src  # Client's source IP
        domain_name = scapy_packet[DNSQR].qname.decode().rstrip('.')  # Remove trailing dot

        # Display the packet info in the table
        display_packet_info(src_ip, domain_name)

    # Accept the packet for further processing
    packet.accept()

QUEUE_NUM = 0

# Add iptables rule to redirect DNS traffic to NFQUEUE
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))

queue = NetfilterQueue()

try:
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except Exception as e:
    print(f"Error: {e}")
except KeyboardInterrupt:
    # Remove iptables rule on exit
    os.system("iptables --flush")
    print("[!] Iptables rule flushed, exiting.")