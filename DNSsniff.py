from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
from prettytable import PrettyTable
from colorama import init, Fore, Style
import socket

init(autoreset=True)

# Get the local machine's IP address
my_ip = socket.gethostbyname(socket.gethostname())


tables = {}

def resolve_domain_to_ip(domain_name):
    try:
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.error:
        return "N/A"  

def display_packet_info(src_ip, domain_name):
    domain_ip = resolve_domain_to_ip(domain_name) 
   
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

    os.system('clear')
    for ip, table in tables.items():
        print(f"\n{Fore.MAGENTA}Source IP: {ip}{Style.RESET_ALL}")
        print(table)

def process_packet(packet):
   
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(DNSQR):
        
        src_ip = scapy_packet[IP].src  

        
        if src_ip == my_ip:
            packet.accept()  
            return

        domain_name = scapy_packet[DNSQR].qname.decode().rstrip('.')  
        display_packet_info(src_ip, domain_name)
    packet.accept()

QUEUE_NUM = 0

os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))

queue = NetfilterQueue()

try:
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except Exception as e:
    print(f"Error: {e}")
except KeyboardInterrupt:
    os.system("iptables --flush")
    print("[!] Iptables rule flushed, exiting.")
