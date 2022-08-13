from scapy.all import *

print("Sending spoofed udp packets......")
ip = IP(src="1.2.3.4", dst = "8.8.8.8")
udp = UDP(sport = 8888, dport=53)
data = "TTTTTTT\n"
pkt = ip/udp/data
pkt.show()
send(pkt)

# You can use a dst IP under your management to actually receive the packet.
# You can also quickly set up a server to observe the packet - "nc -luv port_num"

