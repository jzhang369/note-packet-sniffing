from scapy.all import *

print("packet sniffing starts......")

def print_pkt(pkt):
    print("Src IP: ", pkt[IP].src)
    print("Dst IP: ", pkt[IP].dst)
    print("Protocol: ", pkt[IP].proto)
    print("\n")


pkt = sniff(filter="udp", prn=print_pkt)


