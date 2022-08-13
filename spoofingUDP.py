from scapy.all import *

print("Sending spoofed udp packets......")
ip = IP(src="1.2.3.4", dst = "8.8.8.8")
udp = UDP(sport = 8888, dport=53)
data = "TTTTTTT\n"
pkt = ip/udp/data
pkt.show()
send(pkt)
