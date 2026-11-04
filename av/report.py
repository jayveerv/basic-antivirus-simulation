"""Reports (HTML + JSON) and the scan history log."""

import html
import json
import os
import time

from . import __version__
from .scanner import summarise

COLORS = {"Malicious": "#f0506e", "Suspicious": "#f5b83d", "Clean": "#34d399", "Error": "#94a3b8"}


def write_json(results, path, title="Scan report"):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    doc = {"tool": "Basic Antivirus Simulation", "version": __version__, "title": title,
           "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "summary": summarise(results), "results": results}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, default=str)
    return path


def render_html(results, title="Scan report"):
    e = html.escape
    s = summarise(results)
    rows = []
    for r in results:
        col = COLORS.get(r["verdict"], "#94a3b8")
        reasons = "".join(f"<li><b>+{x['points']}</b> {e(x['source'])}: {e(x['detail'])}</li>" for x in r.get("reasons", [])) or "<li>No findings</li>"
        mitre = ", ".join(e(m) for m in r.get("mitre", [])) or "-"
        rows.append(f"""
<div class="card"><div class="head"><span class="name">{e(r['file'])}</span>
<span class="badge" style="background:{col}22;color:{col};border-color:{col}">{e(r['verdict'])} &middot; {r.get('score', 0)}/100</span></div>
<div class="meta">Mode: {e(r.get('mode',''))} &middot; Size: {r.get('size',0):,} bytes &middot; Type: {e(r.get('file_type','-'))} &middot; Entropy: {r.get('entropy','-')}</div>
<div class="meta mono">SHA-256: {e(r.get('hashes',{}).get('sha256','-'))}<br>MD5: {e(r.get('hashes',{}).get('md5','-'))}</div>
<div class="meta">MITRE ATT&amp;CK: {mitre}</div><ul>{reasons}</ul></div>""")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#0b1622;color:#d6e2ee;margin:0;padding:24px}}
h1{{margin:0 0 4px;font-size:22px}} .sub{{color:#7f93a8;font-size:13px;margin-bottom:18px}}
.stats{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}} .stat{{background:#101e2c;border:1px solid #1e3347;border-radius:10px;padding:10px 16px}}
.stat b{{font-size:22px;display:block}} .card{{background:#101e2c;border:1px solid #1e3347;border-radius:10px;padding:14px 16px;margin-bottom:12px}}
.head{{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}} .name{{font-weight:600;word-break:break-all}}
.badge{{border:1px solid;border-radius:6px;padding:2px 8px;font-size:13px;white-space:nowrap}} .meta{{color:#9fb3c6;font-size:12.5px;margin-top:6px}}
.mono{{font-family:Consolas,monospace;word-break:break-all}} ul{{margin:8px 0 0;padding-left:18px;font-size:13.5px}} li{{margin:3px 0}}
footer{{color:#7f93a8;font-size:12px;margin-top:18px}}
</style></head><body><h1>{e(title)}</h1><div class="sub">Basic Antivirus Simulation v{__version__} &middot; {time.strftime('%Y-%m-%d %H:%M:%S')}</div>
<div class="stats"><div class="stat"><b>{s['files']}</b>Files</div><div class="stat" style="color:#34d399"><b>{s['Clean']}</b>Clean</div>
<div class="stat" style="color:#f5b83d"><b>{s['Suspicious']}</b>Suspicious</div><div class="stat" style="color:#f0506e"><b>{s['Malicious']}</b>Malicious</div></div>
{''.join(rows)}<footer>Educational simulation. Files are only read, never executed.</footer></body></html>"""


def write_html(results, path, title="Scan report"):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(results, title))
    return path


class History:
    """Append-only scan history (one JSON object per line)."""

    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def add(self, result, source="scan"):
        entry = {"id": result["id"], "time": result["time"], "file": result["file"], "verdict": result["verdict"],
                 "score": result.get("score", 0), "mode": result.get("mode"), "source": source,
                 "rules": [r["rule"] for r in result.get("rules", [])],
                 "signature": (result.get("signature") or {}).get("name"),
                 "mitre": result.get("mitre", []), "sha256": result.get("hashes", {}).get("sha256")}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    def read(self, limit=None):
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as fh:
            items = [json.loads(line) for line in fh if line.strip()]
        items.reverse()
        return items[:limit] if limit else items
