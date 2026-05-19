"""
Report generation — HTML dashboard, JSON, CSV.
"""
import csv, json, os
from datetime import datetime
from typing import List
from .engine import SecurityAlert, TrafficStats

class ReportGenerator:
    SEV_COLORS = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#f0c040","LOW":"#3fb950","INFO":"#58a6ff"}

    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        self.base = f"sentinelsniff_{ts}"

    def generate_all(self, alerts, stats, source):
        return {"json": self._json(alerts, stats, source),
                "csv":  self._csv(alerts),
                "html": self._html(alerts, stats, source)}

    def _json(self, alerts, stats, source):
        path = os.path.join(self.output_dir, f"{self.base}.json")
        data = {
            "meta": {"tool":"SentinelSniff v2.0","author":"Deepesh Kumar Mahawar","generated_at":datetime.utcnow().isoformat()+"Z","source":source},
            "summary": {"total_packets":stats.total_packets,"total_bytes":stats.total_bytes,"alert_count":len(alerts),"alerts_by_severity":stats.alerts_by_severity,"protocols":stats.protocols},
            "alerts": [a.to_dict() for a in alerts],
        }
        with open(path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)
        return path

    def _csv(self, alerts):
        path = os.path.join(self.output_dir, f"{self.base}.csv")
        if not alerts: return path
        fieldnames = list(alerts[0].to_dict().keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames); w.writeheader()
            for a in alerts: w.writerow(a.to_dict())
        return path

    def _html(self, alerts, stats, source):
        path = os.path.join(self.output_dir, f"{self.base}.html")
        sev_badge = lambda s: f'<span class="badge sev-{s.lower()}">{s}</span>'
        rows = ""
        for a in alerts:
            rows += f"<tr><td class='mono text-muted'>{a.timestamp[:19].replace('T',' ')}</td><td>{sev_badge(a.severity)}</td><td class='fw-bold'>{a.category}</td><td>{a.description[:100]}</td><td class='mono'>{a.source_ip}</td><td class='mono'>{a.destination_ip or '\u2014'}</td><td><span class='proto-badge'>{a.protocol}</span></td><td class='mono'>{a.port or '\u2014'}</td><td class='small text-muted'>{a.mitre_technique or '\u2014'}</td></tr>"
        if not rows: rows = "<tr><td colspan='9' class='no-alerts'>\u2705 No security alerts — traffic appears clean.</td></tr>"
        proto_labels = json.dumps(list(stats.protocols.keys()))
        proto_values = json.dumps(list(stats.protocols.values()))
        sev_labels = json.dumps(list(stats.alerts_by_severity.keys()))
        sev_values = json.dumps(list(stats.alerts_by_severity.values()))
        sev_colors = json.dumps([self.SEV_COLORS.get(k,"#aaa") for k in stats.alerts_by_severity.keys()])
        crit = stats.alerts_by_severity.get("CRITICAL",0)
        high = stats.alerts_by_severity.get("HIGH",0)
        med  = stats.alerts_by_severity.get("MEDIUM",0)
        total = len(alerts)
        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>SentinelSniff \u2014 Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--bs:#21262d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--crit:#ff4444;--high:#ff8800;--med:#f0c040;--low:#3fb950}}
body{{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}}
.mono{{font-family:'JetBrains Mono',monospace;font-size:.82em}}.fw-bold{{font-weight:600}}.text-muted{{color:var(--muted)}}.small{{font-size:.8em}}
.topbar{{background:var(--surface);border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between}}
.logo{{display:flex;align-items:center;gap:.75rem}}
.logo-icon{{width:36px;height:36px;background:linear-gradient(135deg,#58a6ff,#3fb950);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.2rem}}
.logo-text{{font-size:1.25rem;font-weight:700}}.logo-text span{{color:var(--accent)}}
.version{{background:rgba(88,166,255,.15);color:var(--accent);border:1px solid var(--accent);border-radius:20px;padding:.2rem .7rem;font-size:.72rem;font-weight:600}}
.meta{{font-size:.8rem;color:var(--muted);text-align:right;line-height:1.7}}
.container{{max-width:1600px;margin:0 auto;padding:2rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:1.25rem;margin-bottom:2rem}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}}
.card:hover{{transform:translateY(-3px);border-color:var(--accent)}}
.card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px}}
.card.c::before{{background:var(--crit)}}.card.h::before{{background:var(--high)}}.card.m::before{{background:var(--med)}}.card.t::before{{background:linear-gradient(90deg,var(--accent),var(--low))}}
.card-val{{font-size:2rem;font-weight:700;color:#fff;line-height:1}}
.card-lbl{{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:.4rem}}
.charts{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2rem}}
@media(max-width:900px){{.charts{{grid-template-columns:1fr}}}}
.chart-box{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem}}
.chart-box h3{{font-size:.95rem;font-weight:600;margin-bottom:1.2rem;display:flex;align-items:center;gap:.5rem}}
.chart-box h3::before{{content:'';width:4px;height:1rem;background:var(--accent);border-radius:2px}}
.tbl-card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:2rem}}
.tbl-hdr{{padding:1.25rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}}
.tbl-hdr h3{{font-size:1rem;font-weight:600}}.tbl-hdr span{{font-size:.8rem;color:var(--muted)}}
.tbl-wrap{{max-height:600px;overflow-y:auto}}
table{{width:100%;border-collapse:collapse;font-size:.87rem}}
th{{padding:.8rem 1rem;color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface);font-weight:500}}
td{{padding:.8rem 1rem;border-bottom:1px solid var(--bs);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(88,166,255,.04)}}
.no-alerts{{text-align:center;padding:3rem;color:var(--muted)}}
.badge{{display:inline-block;padding:.22rem .6rem;border-radius:20px;font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em}}
.sev-critical{{background:rgba(255,68,68,.15);color:var(--crit);border:1px solid var(--crit)}}
.sev-high{{background:rgba(255,136,0,.15);color:var(--high);border:1px solid var(--high)}}
.sev-medium{{background:rgba(240,192,64,.15);color:var(--med);border:1px solid var(--med)}}
.sev-low{{background:rgba(63,185,80,.15);color:var(--low);border:1px solid var(--low)}}
.sev-info{{background:rgba(88,166,255,.15);color:var(--accent);border:1px solid var(--accent)}}
.proto-badge{{background:#21262d;color:var(--muted);border:1px solid var(--border);border-radius:4px;padding:.1rem .5rem;font-size:.72rem;font-family:'JetBrains Mono',monospace}}
.footer{{text-align:center;color:var(--muted);font-size:.8rem;padding:1.5rem;border-top:1px solid var(--border)}}
.footer a{{color:var(--accent);text-decoration:none}}
</style></head><body>
<div class="topbar">
  <div class="logo"><div class="logo-icon">\ud83d\udee1\ufe0f</div><span class="logo-text">Sentinel<span>Sniff</span></span><span class="version">v2.0</span></div>
  <div class="meta">Source: <strong>{source}</strong><br>Generated: <strong>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</strong><br>Packets: <strong>{stats.total_packets:,}</strong> | Bytes: <strong>{stats.total_bytes:,}</strong></div>
</div>
<div class="container">
  <div class="cards">
    <div class="card t"><div class="card-val">{stats.total_packets:,}</div><div class="card-lbl">Packets Analyzed</div></div>
    <div class="card c"><div class="card-val" style="color:var(--crit)">{crit}</div><div class="card-lbl">Critical</div></div>
    <div class="card h"><div class="card-val" style="color:var(--high)">{high}</div><div class="card-lbl">High</div></div>
    <div class="card m"><div class="card-val" style="color:var(--med)">{med}</div><div class="card-lbl">Medium</div></div>
    <div class="card t"><div class="card-val">{total}</div><div class="card-lbl">Total Alerts</div></div>
  </div>
  <div class="charts">
    <div class="chart-box"><h3>Protocol Distribution</h3><canvas id="protoChart" height="230"></canvas></div>
    <div class="chart-box"><h3>Alert Severity Breakdown</h3><canvas id="sevChart" height="230"></canvas></div>
  </div>
  <div class="tbl-card">
    <div class="tbl-hdr"><h3>\ud83d\udd0d Security Incidents</h3><span>{total} alert(s)</span></div>
    <div class="tbl-wrap"><table><thead><tr><th>Timestamp</th><th>Severity</th><th>Category</th><th>Description</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>Port</th><th>MITRE ATT&amp;CK</th></tr></thead><tbody>{rows}</tbody></table></div>
  </div>
</div>
<div class="footer">SentinelSniff v2.0 &nbsp;|&nbsp; <a href="https://github.com/deepmaha2006/SentinelSniff">github.com/deepmaha2006/SentinelSniff</a></div>
<script>
const g='#21262d',t='#8b949e';
new Chart(document.getElementById('protoChart'),{{type:'doughnut',data:{{labels:{proto_labels},datasets:[{{data:{proto_values},backgroundColor:['#58a6ff','#3fb950','#f0c040','#ff8800','#ff4444','#bc8cff'],borderWidth:0,hoverOffset:8}}]}},options:{{plugins:{{legend:{{labels:{{color:t}}}}}},cutout:'62%'}}}});
new Chart(document.getElementById('sevChart'),{{type:'bar',data:{{labels:{sev_labels},datasets:[{{label:'Alerts',data:{sev_values},backgroundColor:{sev_colors},borderRadius:6,borderWidth:0}}]}},options:{{plugins:{{legend:{{display:false}}}},scales:{{x:{{ticks:{{color:t}},grid:{{color:g}}}},y:{{ticks:{{color:t}},grid:{{color:g}},beginAtZero:true}}}}}}}});
</script></body></html>"""
        with open(path, "w", encoding="utf-8") as f: f.write(html)
        return path
