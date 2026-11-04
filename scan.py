"""Basic Antivirus Simulation - command-line scanner.

Examples:
    python scan.py samples demo_files            create safe test files
    python scan.py scan demo_files               full scan of a folder
    python scan.py scan demo_files --quick       quick scan (signatures + rules only)
    python scan.py scan file.txt --report both --quarantine
    python scan.py watch watched                 real-time monitoring of a folder
    python scan.py quarantine list | restore ID | delete ID
    python scan.py history
"""

import argparse
import os
import sys
import time

from av import __version__
from av.monitor import FolderMonitor
from av.quarantine import Quarantine
from av.report import History, write_html, write_json
from av.samples import SAMPLES, create_samples
from av.scanner import Scanner, summarise

HOME = os.path.dirname(os.path.abspath(__file__))
STATE = os.environ.get("AV_STATE_DIR", os.path.join(HOME, "av_state"))
if os.name == "nt":
    os.system("")  # turns on colour support in the Windows console

COL = {"Malicious": "\033[91m", "Suspicious": "\033[93m", "Clean": "\033[92m", "Error": "\033[90m"}
END = "\033[0m"


def color(text, verdict):
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return COL.get(verdict, "") + text + END


def print_result(r, verbose=False):
    v = r["verdict"]
    print("  " + color(f"{v:<10}", v) + f" {r.get('score', 0):>3}/100  {r['file']}")
    if verbose or r["verdict"] != "Clean":
        for x in r.get("reasons", []):
            print(f"      +{x['points']:<3} {x['source']}: {x['detail']}")


def cmd_scan(a):
    sc, hist = Scanner(), History(os.path.join(STATE, "history.jsonl"))
    q = Quarantine(os.path.join(STATE, "quarantine")) if a.quarantine else None
    mode = "quick" if a.quick else "full"
    if not os.path.exists(a.target):
        print(f"error: {a.target} not found"); return 2
    print(f"Basic Antivirus Simulation v{__version__} | {mode} scan | {len(sc.signatures)} signatures, {len(sc.rules)} rules\n")
    t0 = time.time()
    results = sc.scan_folder(a.target, mode, skip=[STATE]) if os.path.isdir(a.target) else [sc.scan_file(a.target, mode)]
    for r in results:
        print_result(r, a.verbose)
        hist.add(r, "cli")
        if q and r["verdict"] == "Malicious":
            item = q.add(r["path"], r, r["file"])
            print(f"      -> quarantined as {item['id']}")
    s = summarise(results)
    print(f"\n{s['files']} files in {time.time() - t0:.2f}s | Clean {s['Clean']} | Suspicious {s['Suspicious']} | Malicious {s['Malicious']}")
    if a.report:
        stamp = time.strftime("%Y%m%d_%H%M%S")
        base = os.path.join(a.out, f"scan_{stamp}")
        if a.report in ("json", "both"):
            print("JSON report:", write_json(results, base + ".json"))
        if a.report in ("html", "both"):
            print("HTML report:", write_html(results, base + ".html"))
    return 1 if s["Malicious"] else 0


def cmd_watch(a):
    sc, hist = Scanner(), History(os.path.join(STATE, "history.jsonl"))
    q = Quarantine(os.path.join(STATE, "quarantine")) if a.quarantine else None

    def show(ev):
        print(f"[{time.strftime('%H:%M:%S')}] {ev['event']:<7}", end="")
        print_result(ev["result"])
        hist.add(ev["result"], "monitor")
        if ev["quarantined"]:
            print(f"      -> quarantined as {ev['quarantined']}")

    mon = FolderMonitor(a.folder, sc, "quick" if a.quick else "full", q, show, a.interval)
    print(f"Watching {os.path.abspath(a.folder)} every {a.interval}s. Drop files in it. Ctrl+C to stop.")
    mon.run_forever()
    return 0


def cmd_quarantine(a):
    q = Quarantine(os.path.join(STATE, "quarantine"))
    if a.action == "list":
        items = q.list()
        if not items:
            print("Quarantine is empty.")
        for i in items:
            print(f"  {i['id']}  {i['verdict']:<10} {i['quarantined_at']}  {i['name']}  ({', '.join(i['detections']) or '-'})")
    elif a.action == "restore":
        print("Restored to", q.restore(a.id, a.to))
    elif a.action == "delete":
        q.delete(a.id)
        print("Deleted", a.id)
    return 0


def cmd_history(a):
    for h in History(os.path.join(STATE, "history.jsonl")).read(a.limit):
        v = h["verdict"]
        print(f"  {h['time']}  " + color(f"{v:<10}", v) + f" {h['score']:>3}  {h['file']}  [{h['source']}]")
    return 0


def cmd_samples(a):
    for p in create_samples(a.folder):
        print(f"  {p:<45} {SAMPLES[os.path.basename(p)][0]}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Basic Antivirus Simulation (safe, educational)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a file or folder")
    s.add_argument("target")
    s.add_argument("--quick", action="store_true", help="signatures + rules only")
    s.add_argument("--report", choices=["html", "json", "both"])
    s.add_argument("--out", default="reports")
    s.add_argument("--quarantine", action="store_true", help="quarantine malicious files")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_scan)

    w = sub.add_parser("watch", help="monitor a folder in real time")
    w.add_argument("folder")
    w.add_argument("--interval", type=float, default=2.0)
    w.add_argument("--quick", action="store_true")
    w.add_argument("--quarantine", action="store_true")
    w.set_defaults(fn=cmd_watch)

    q = sub.add_parser("quarantine", help="list, restore or delete quarantined files")
    q.add_argument("action", choices=["list", "restore", "delete"])
    q.add_argument("id", nargs="?")
    q.add_argument("--to", help="restore to this path instead of the original")
    q.set_defaults(fn=cmd_quarantine)

    h = sub.add_parser("history", help="show scan history")
    h.add_argument("--limit", type=int, default=30)
    h.set_defaults(fn=cmd_history)

    sm = sub.add_parser("samples", help="create safe test files (EICAR + harmless samples)")
    sm.add_argument("folder", nargs="?", default="demo_files")
    sm.set_defaults(fn=cmd_samples)

    a = p.parse_args(argv)
    if a.cmd == "quarantine" and a.action in ("restore", "delete") and not a.id:
        p.error("quarantine restore/delete needs an ID")
    try:
        return a.fn(a)
    except KeyError as exc:
        print("error:", exc.args[0]); return 2


if __name__ == "__main__":
    sys.exit(main())
