"""
SentinelSniff CLI.
"""
import argparse, json, logging, os, sys
from datetime import datetime
from .engine import ThreatDetectionEngine, TrafficStats
from .reporter import ReportGenerator
from . import __version__

try:
    from scapy.all import rdpcap, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def setup_logging(level, log_file=None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ", handlers=handlers)

def load_config(path):
    defaults = {"thresholds":{"port_scan_ports":20,"icmp_flood_count":100,"syn_flood_count":50,"large_icmp_bytes":1024},"output":{"dir":"reports","formats":["html","json","csv"]},"whitelist_ips":[]}
    if path and os.path.exists(path):
        with open(path) as f:
            for k, v in json.load(f).items():
                if isinstance(v, dict) and k in defaults: defaults[k].update(v)
                else: defaults[k] = v
    return defaults

def run_analysis(packets, engine, config):
    stats = TrafficStats(start_time=datetime.utcnow().isoformat()+"Z")
    all_alerts, seen = [], set()
    whitelist = set(config.get("whitelist_ips", []))
    log = logging.getLogger("sentinelsniff.analysis")
    for i, pkt in enumerate(packets, 1):
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            if pkt.haslayer(IP):
                ip = pkt[IP]
                if ip.src in whitelist: continue
                stats.top_talkers[ip.src] = stats.top_talkers.get(ip.src,0)+1
                stats.top_destinations[ip.dst] = stats.top_destinations.get(ip.dst,0)+1
            if pkt.haslayer(TCP): stats.protocols["TCP"] = stats.protocols.get("TCP",0)+1
            elif pkt.haslayer(UDP): stats.protocols["UDP"] = stats.protocols.get("UDP",0)+1
            elif pkt.haslayer(ICMP): stats.protocols["ICMP"] = stats.protocols.get("ICMP",0)+1
            else: stats.protocols["Other"] = stats.protocols.get("Other",0)+1
            stats.total_packets += 1; stats.total_bytes += len(pkt)
            for alert in engine.analyze(pkt, i):
                key = f"{alert.category}:{alert.source_ip}"
                if key not in seen:
                    seen.add(key); all_alerts.append(alert)
                    stats.alerts_by_severity[alert.severity] = stats.alerts_by_severity.get(alert.severity,0)+1
                    log.warning("[%s] %s", alert.severity, alert.description)
        except Exception as e: log.debug("Packet #%d error: %s", i, e)
    stats.end_time = datetime.utcnow().isoformat()+"Z"
    return all_alerts, stats

def main():
    print(f"\n{'='*60}\n  SentinelSniff v{__version__} | By Deepesh Kumar Mahawar\n{'='*60}\n")
    parser = argparse.ArgumentParser(prog="sentinelsniff")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", "-c", metavar="FILE")
    parser.add_argument("--output-dir", metavar="DIR")
    parser.add_argument("--log-level", choices=["DEBUG","INFO","WARNING","ERROR"], default="INFO")
    parser.add_argument("--log-file", metavar="FILE")
    sub = parser.add_subparsers(dest="command", required=True)
    pcap_p = sub.add_parser("pcap")
    pcap_p.add_argument("--pcap", "-p", required=True, metavar="FILE")
    live_p = sub.add_parser("live")
    live_p.add_argument("--interface", "-i", metavar="IFACE")
    live_p.add_argument("--count", "-n", type=int, default=500)
    args = parser.parse_args()
    setup_logging(args.log_level, getattr(args, "log_file", None))
    config = load_config(args.config)
    if args.output_dir: config["output"]["dir"] = args.output_dir
    if not SCAPY_AVAILABLE:
        logging.error("Scapy required: pip install scapy"); sys.exit(1)
    log = logging.getLogger("sentinelsniff")
    engine = ThreatDetectionEngine(config)
    if args.command == "pcap":
        if not os.path.isfile(args.pcap): log.error("Not found: %s", args.pcap); sys.exit(1)
        packets = rdpcap(args.pcap); alerts, stats = run_analysis(packets, engine, config); source = args.pcap
    else:
        captured = []
        try: sniff(iface=args.interface, prn=captured.append, count=args.count, store=True)
        except PermissionError: log.error("Run as Administrator/sudo."); sys.exit(1)
        except KeyboardInterrupt: pass
        if not captured: log.warning("No packets."); return
        alerts, stats = run_analysis(captured, engine, config); source = f"live:{args.interface or 'default'}"
    reporter = ReportGenerator(config["output"]["dir"])
    paths = reporter.generate_all(alerts, stats, source=source)
    for fmt, p in paths.items(): log.info("  [%s] %s", fmt.upper(), p)

if __name__ == "__main__": main()
