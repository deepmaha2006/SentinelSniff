"""
Generate a realistic test PCAP for SentinelSniff.
Simulates: port scan, SYN flood, credential exposure, ICMP flood, Telnet.
"""
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap
import random

packets = []
attacker = "192.168.1.100"
victim   = "192.168.1.1"
server   = "10.0.0.50"

# 1. Port scan (T1046): rapid SYN to many ports
print("[*] Simulating port scan...")
for port in range(20, 70):
    pkt = IP(src=attacker, dst=victim) / TCP(sport=random.randint(40000, 60000), dport=port, flags="S")
    packets.append(pkt)

# 2. SYN flood (T1498): many SYNs to port 80
print("[*] Simulating SYN flood...")
for i in range(80):
    pkt = IP(src=f"10.0.{random.randint(1,254)}.{random.randint(1,254)}", dst=server) / \
          TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
    packets.append(pkt)

# 3. Plaintext credentials over FTP (T1557.002)
print("[*] Simulating FTP credential exposure...")
ftp_payload = b"USER admin\r\nPASS secret123\r\n"
pkt = IP(src=attacker, dst=server) / TCP(sport=54321, dport=21, flags="PA") / Raw(load=ftp_payload)
packets.append(pkt)

# 4. Telnet session (T1040)
telnet_payload = b"login: root\r\nPassword: toor\r\n"
pkt = IP(src=attacker, dst=server) / TCP(sport=54322, dport=23, flags="PA") / Raw(load=telnet_payload)
packets.append(pkt)

# 5. ICMP flood (T1498.001)
print("[*] Simulating ICMP flood...")
for i in range(120):
    pkt = IP(src=attacker, dst=victim) / ICMP()
    packets.append(pkt)

# 6. Normal HTTP traffic (benign)
for i in range(10):
    pkt = IP(src="172.16.0.5", dst=server) / TCP(sport=random.randint(30000, 50000), dport=80, flags="S")
    packets.append(pkt)

random.shuffle(packets)
wrpcap("test_capture.pcap", packets)
print(f"[+] Written {len(packets)} packets to test_capture.pcap")
print("[*] Run: sentinelsniff pcap --pcap test_capture.pcap")
