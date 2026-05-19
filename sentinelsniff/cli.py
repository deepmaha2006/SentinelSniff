"""
SentinelSniff CLI entry point - professional argparse interface with logging setup.
"""
import argparse
import logging
import os
import sys
import time
from datetime import datetime

from .engine import ThreatDetectionEngine, TrafficStats
from .reporter import ReportGenerator
from . import __version__

try:
    from scapy.all import rdpcap, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def setup_logging(level: str, log_file: str = None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        handlers=handlers,
    )


def load_config(path: str) -> dict:
    import json
    defaults = {
        "thresholds": {
            "port_scan_ports": 20,
            "icmp_flood_count": 100,
            "syn_flood_count": 50,
            "large_icmp_bytes": 1024,
        },
        "output": {"dir": "reports", "formats": ["html", "json", "csv"]},
        "whitelist_ips": [],
    }
    if path and os.path.exists(path):
        with open(path) as f:
            import json as _json
            user_cfg = _json.load(f)
            for k, v in user_cfg.items():
                if isinstance(v, dict) and k in defaults:
                    defaults[k].update(v)
                else:
                    defaults[k] = v
    return defaults


def print_banner():
    banner = f"""
+----------------------------------------------------------+
|           SentinelSniff  v{__version__}                        |
|  Network Traffic Anomaly Detection & Forensics Engine    |
|             By Deepesh Kumar Mahawar                     |
+----------------------------------------------------------+
"""
    print(banner)


def run_analysis(packets, engine: ThreatDetectionEngine, config: dict) -> tuple:
    """Process a list of packets and return alerts + stats."""
    stats = TrafficStats(start_time=datetime.utcnow().isoformat() + "Z")
    all_alerts = []
    seen_descriptions = set()
    whitelist = set(config.get("whitelist_ips", []))
    log = logging.getLogger("sentinelsniff.analysis")
    for i, pkt in enumerate(packets, 1):
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            if pkt.haslayer(IP):
                ip = pkt[IP]
                if ip.src in whitelist:
                    continue
                stats.top_talkers[ip.src] = stats.top_talkers.get(ip.src, 0) + 1
                stats.top_destinations[ip.dst] = stats.top_destinations.get(ip.dst, 0) + 1
            if pkt.haslayer(TCP):
                stats.protocols["TCP"] = stats.protocols.get("TCP", 0) + 1
                p = pkt[TCP].dport
                stats.top_ports[p] = stats.top_ports.get(p, 0) + 1
            elif pkt.haslayer(UDP):
                stats.protocols["UDP"] = stats.protocols.get("UDP", 0) + 1
                p = pkt[UDP].dport
                stats.top_ports[p] = stats.top_ports.get(p, 0) + 1
            elif pkt.haslayer(ICMP):
                stats.protocols["ICMP"] = stats.protocols.get("ICMP", 0) + 1
            else:
                stats.protocols["Other"] = stats.protocols.get("Other", 0) + 1
            stats.total_packets += 1
            stats.total_bytes += len(pkt)
            new_alerts = engine.analyze(pkt, i)
            for alert in new_alerts:
                key = f"{alert.category}:{alert.source_ip}"
                if key not in seen_descriptions:
                    seen_descriptions.add(key)
                    all_alerts.append(alert)
                    stats.alerts_by_severity[alert.severity] = \
                        stats.alerts_by_severity.get(alert.severity, 0) + 1
                    log.warning("[%s] %s - %s", alert.severity, alert.category, alert.description)
        except Exception as e:
            log.debug("Packet #%d error: %s", i, e)
    stats.end_time = datetime.utcnow().isoformat() + "Z"
    return all_alerts, stats


def cmd_pcap(args, config):
    """Analyze an offline PCAP file."""
    log = logging.getLogger("sentinelsniff")
    if not os.path.isfile(args.pcap):
        log.error("PCAP file not found: %s", args.pcap)
        sys.exit(1)
    log.info("Loading PCAP: %s", args.pcap)
    t0 = time.time()
    packets = rdpcap(args.pcap)
    log.info("Loaded %d packets in %.2fs", len(packets), time.time() - t0)
    engine = ThreatDetectionEngine(config)
    alerts, stats = run_analysis(packets, engine, config)
    reporter = ReportGenerator(config["output"]["dir"])
    paths = reporter.generate_all(alerts, stats, source=args.pcap)
    log.info("Analysis complete - %d alerts | Reports saved:", len(alerts))
    for fmt, p in paths.items():
        log.info("  [%s] %s", fmt.upper(), p)


def cmd_live(args, config):
    """Capture and analyze live network traffic."""
    log = logging.getLogger("sentinelsniff")
    count = args.count or 500
    iface = args.interface or None
    log.info("Starting live capture on interface: %s (count=%d)", iface or "default", count)
    log.info("Press Ctrl+C to stop early and generate report.")
    engine = ThreatDetectionEngine(config)
    captured = []

    def packet_callback(pkt):
        captured.append(pkt)

    try:
        sniff(iface=iface, prn=packet_callback, count=count, store=True)
    except PermissionError:
        log.error("Permission denied - run with Administrator/sudo for live capture.")
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Capture interrupted by user at %d packets.", len(captured))
    if not captured:
        log.warning("No packets captured. Exiting.")
        return
    alerts, stats = run_analysis(captured, engine, config)
    reporter = ReportGenerator(config["output"]["dir"])
    paths = reporter.generate_all(alerts, stats, source=f"live:{iface or 'default'}")
    log.info("Capture complete - %d packets | %d alerts", stats.total_packets, len(alerts))
    for fmt, p in paths.items():
        log.info("  [%s] %s", fmt.upper(), p)


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        prog="sentinelsniff",
        description="SentinelSniff - Professional Network Traffic Anomaly Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinelsniff pcap --pcap capture.pcap
  sentinelsniff live --interface eth0 --count 1000
  sentinelsniff pcap --pcap capture.pcap --output-dir /var/reports
        """
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", "-c", metavar="FILE", help="Path to JSON config file.")
    parser.add_argument("--output-dir", metavar="DIR", help="Report output directory.")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    parser.add_argument("--log-file", metavar="FILE", help="Write logs to file.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    pcap_p = subparsers.add_parser("pcap", help="Analyze an offline PCAP capture file.")
    pcap_p.add_argument("--pcap", "-p", required=True, metavar="FILE", help="Path to .pcap file.")
    live_p = subparsers.add_parser("live", help="Capture live network interface traffic.")
    live_p.add_argument("--interface", "-i", metavar="IFACE", help="Network interface (e.g., eth0).")
    live_p.add_argument("--count", "-n", type=int, default=500, help="Packet count limit (default: 500).")
    args = parser.parse_args()
    setup_logging(args.log_level, getattr(args, "log_file", None))
    config = load_config(args.config)
    if args.output_dir:
        config["output"]["dir"] = args.output_dir
    if not SCAPY_AVAILABLE:
        logging.error("Scapy is required. Install with: pip install scapy")
        sys.exit(1)
    if args.command == "pcap":
        cmd_pcap(args, config)
    elif args.command == "live":
        cmd_live(args, config)


if __name__ == "__main__":
    main()
