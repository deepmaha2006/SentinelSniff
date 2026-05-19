"""
Threat Detection Engine — MITRE ATT&CK mapped packet analysis.
"""
import logging
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class SecurityAlert:
    timestamp: str
    severity: str
    category: str
    description: str
    source_ip: str
    destination_ip: str
    protocol: str
    port: Optional[int]
    packet_number: int
    raw_payload_hex: Optional[str] = None
    mitre_technique: Optional[str] = None
    def to_dict(self): return asdict(self)

@dataclass
class TrafficStats:
    total_packets: int = 0
    total_bytes: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    protocols: dict = field(default_factory=dict)
    top_talkers: dict = field(default_factory=dict)
    top_destinations: dict = field(default_factory=dict)
    top_ports: dict = field(default_factory=dict)
    alerts_by_severity: dict = field(default_factory=lambda: {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0})

class ThreatDetectionEngine:
    MITRE_MAP = {
        "Port Scan": "T1046 - Network Service Discovery",
        "Plaintext Credentials": "T1557.002 - Cleartext Protocol",
        "ICMP Flood": "T1498.001 - Direct Network Flood",
        "DNS Exfiltration": "T1048.003 - Exfiltration Over DNS",
        "SYN Flood": "T1498 - Network Denial of Service",
        "Large ICMP": "T1001 - Data Obfuscation",
    }
    CREDENTIAL_PATTERNS = [b"user=",b"username=",b"password=",b"pass=",b"passwd=",b"login=",b"auth=",b"secret=",b"Authorization: Basic",b"PASS ",b"USER "]
    PORT_SERVICES = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",27017:"MongoDB"}

    def __init__(self, config):
        t = config.get("thresholds", {})
        self.port_scan_threshold  = t.get("port_scan_ports", 20)
        self.icmp_flood_threshold = t.get("icmp_flood_count", 100)
        self.syn_flood_threshold  = t.get("syn_flood_count", 50)
        self.large_icmp_threshold = t.get("large_icmp_bytes", 1024)
        self.connection_tracker = defaultdict(set)
        self.icmp_counter = defaultdict(int)
        self.syn_tracker = defaultdict(int)
        self.dns_query_tracker = defaultdict(list)

    def analyze(self, packet, packet_number):
        alerts = []
        if not packet.haslayer(IP): return alerts
        ip = packet[IP]; src, dst, proto, port = ip.src, ip.dst, "OTHER", None
        try:
            if packet.haslayer(TCP):
                proto = "TCP"; tcp = packet[TCP]; port = tcp.dport
                self.connection_tracker[src].add((dst, tcp.dport))
                unique_ports = len({p for _, p in self.connection_tracker[src]})
                if unique_ports >= self.port_scan_threshold:
                    alerts.append(self._alert("HIGH","Port Scan Detected",f"{src} probed {unique_ports} unique ports.",src,dst,proto,port,packet_number,mitre="Port Scan"))
                if tcp.flags == 0x02:
                    self.syn_tracker[src] += 1
                    if self.syn_tracker[src] >= self.syn_flood_threshold:
                        alerts.append(self._alert("HIGH","TCP SYN Flood",f"{src} sent {self.syn_tracker[src]} SYN packets.",src,dst,proto,port,packet_number,mitre="SYN Flood"))
                if packet.haslayer(Raw):
                    a = self._check_credentials(packet[Raw].load, src, dst, port, packet_number)
                    if a: alerts.append(a)
                    if port == 23 or tcp.sport == 23:
                        alerts.append(self._alert("MEDIUM","Insecure Protocol: Telnet",f"Unencrypted Telnet: {src}<->{dst}.",src,dst,proto,port,packet_number))
            elif packet.haslayer(UDP):
                proto = "UDP"; port = packet[UDP].dport
                if SCAPY_AVAILABLE and packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    domain = packet[DNSQR].qname.decode(errors="ignore").strip(".")
                    self.dns_query_tracker[src].append(domain)
                    if len(domain) > 50:
                        alerts.append(self._alert("MEDIUM","DNS Anomaly: Long Query",f"Long DNS domain ({len(domain)} chars): {domain[:60]}...",src,dst,"DNS",53,packet_number,mitre="DNS Exfiltration"))
                    if len(self.dns_query_tracker[src]) > 30:
                        alerts.append(self._alert("MEDIUM","DNS Exfiltration Indicator",f"{src} issued {len(self.dns_query_tracker[src])} DNS queries.",src,dst,"DNS",53,packet_number,mitre="DNS Exfiltration"))
            elif packet.haslayer(ICMP):
                proto = "ICMP"; self.icmp_counter[src] += 1
                if self.icmp_counter[src] >= self.icmp_flood_threshold:
                    alerts.append(self._alert("MEDIUM","ICMP Flood",f"{src} generated {self.icmp_counter[src]} ICMP packets.",src,dst,proto,None,packet_number,mitre="ICMP Flood"))
                if len(packet) > self.large_icmp_threshold:
                    alerts.append(self._alert("LOW","Oversized ICMP",f"ICMP {len(packet)} bytes from {src}.",src,dst,proto,None,packet_number,mitre="Large ICMP"))
        except Exception as e:
            logger.warning("Packet #%d error: %s", packet_number, e)
        return alerts

    def _check_credentials(self, payload, src, dst, port, pkt_num):
        try:
            low = payload.lower()
            for p in self.CREDENTIAL_PATTERNS:
                if p.lower() in low:
                    kw = p.decode(errors="ignore").strip("= :")
                    svc = self.PORT_SERVICES.get(port, f"port/{port}")
                    snippet = payload[:80].decode(errors="replace").replace("\n"," ")
                    return self._alert("CRITICAL","Plaintext Credentials Transmitted",f"'{kw}' in cleartext over {svc}. Payload: '{snippet}'",src,dst,"TCP",port,pkt_num,raw_hex=payload[:32].hex(),mitre="Plaintext Credentials")
        except Exception: pass
        return None

    def _alert(self, severity, category, description, src, dst, proto, port, pkt_num, raw_hex=None, mitre=None):
        return SecurityAlert(timestamp=datetime.utcnow().isoformat()+"Z",severity=severity,category=category,description=description,source_ip=src,destination_ip=dst,protocol=proto,port=port,packet_number=pkt_num,raw_payload_hex=raw_hex,mitre_technique=self.MITRE_MAP.get(mitre))

    def enrich_port(self, port): return self.PORT_SERVICES.get(port, str(port))
