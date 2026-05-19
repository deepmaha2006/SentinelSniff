# SentinelSniff v2.0

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Scapy-2.5+-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Zero_Config-HTML+JSON+CSV-blue?style=for-the-badge" />
</p>

> **Industrial-grade network traffic anomaly detection & forensics engine.**  
> Analyze PCAP files or live interfaces for indicators of compromise — every alert is MITRE ATT&CK annotated.

---

## 🎯 Features

| Detection | Severity | MITRE Technique |
|:---|:---:|:---|
| Plaintext Credential Transmission | **CRITICAL** | T1557.002 |
| SSH Brute Force / Port Scan | **HIGH** | T1046 |
| TCP SYN Flood | **HIGH** | T1498 |
| ICMP Flood / Ping Sweep | **MEDIUM** | T1498.001 |
| DNS Exfiltration Indicator | **MEDIUM** | T1048.003 |
| Insecure Telnet Session | **MEDIUM** | T1040 |
| Oversized ICMP (Covert Channel) | **LOW** | T1001 |

---

## ⚡ Quick Start

```bash
git clone https://github.com/deepmaha2006/SentinelSniff.git
cd SentinelSniff
pip install -e .

# Analyze a PCAP file
sentinelsniff pcap --pcap capture.pcap

# Live capture (requires Administrator/sudo)
sentinelsniff live --interface eth0 --count 1000
```

---

## 📁 Project Structure

```
SentinelSniff/
├── sentinelsniff/
│   ├── __init__.py    # Package metadata
│   ├── engine.py      # ThreatDetectionEngine + SecurityAlert dataclass
│   ├── reporter.py    # HTML dashboard + JSON + CSV generators
│   └── cli.py         # argparse CLI (pcap | live subcommands)
├── __main__.py        # python -m sentinelsniff entry point
├── pyproject.toml     # PEP 517/518 packaging
├── config.json        # Threshold configuration
└── requirements.txt   # scapy>=2.5.0
```

---

## 📊 Reports Generated

| Format | Contents |
|:---|:---|
| `sentinelsniff_TIMESTAMP.html` | Interactive dark dashboard — Chart.js protocol pie + severity bar, scrollable alert table |
| `sentinelsniff_TIMESTAMP.json` | Full structured alert data for SIEM ingestion |
| `sentinelsniff_TIMESTAMP.csv` | Flat incident export for analyst workflows |

---

## ⚙️ Configuration

```json
{
  "thresholds": {
    "port_scan_ports": 20,
    "syn_flood_count": 50,
    "icmp_flood_count": 100,
    "large_icmp_bytes": 1024
  },
  "whitelist_ips": ["127.0.0.1"]
}
```

---

## 👨‍💻 Author

**Deepesh Kumar Mahawar** — B.Tech CSE (Cybersecurity), Poornima College of Engineering

[![LinkedIn](https://img.shields.io/badge/LinkedIn-deepesh--mahawar-0A66C2?style=flat&logo=linkedin)](https://linkedin.com/in/deepesh-mahawar)
[![GitHub](https://img.shields.io/badge/GitHub-deepmaha2006-181717?style=flat&logo=github)](https://github.com/deepmaha2006)
