from scapy.all import *

# Define a function to analyze ping packets
def ping_monitor(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        print("Ping detected from source: ", pkt[IP].src)

# Define a function to analyze DNS packets
def dns_monitor(pkt):
    if pkt.haslayer(DNSQR):
        print("DNS query detected for: ", pkt[DNSQR].qname.decode())

# Define a function to analyze HTTP packets
def http_monitor(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if b"GET" in pkt[Raw].load:
            print("HTTP GET request detected from source: ", pkt[IP].src)

# Start capturing packets and analyzing them
sniff(filter="icmp or udp port 53 or tcp port 80", prn=lambda x: ping_monitor(x) or dns_monitor(x) or http_monitor(x))