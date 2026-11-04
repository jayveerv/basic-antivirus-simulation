"""Basic Antivirus Simulation - Flask web demo.

Every visitor gets a private workspace (uploads, quarantine, history). On the hosted demo
(PUBLIC_MODE=1) workspaces are deleted after RETENTION_HOURS. Files are never executed.
"""

import os
import secrets
import shutil
import sys
import time

from flask import (Flask, abort, flash, redirect, render_template, request, send_file, session, url_for)
from werkzeug.utils import secure_filename

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from av import __version__  # noqa: E402
from av.monitor import FolderMonitor  # noqa: E402
from av.quarantine import Quarantine  # noqa: E402
from av.report import History, render_html, write_json  # noqa: E402
from av.samples import SAMPLES, create_samples  # noqa: E402
from av.scanner import MALICIOUS_AT, SUSPICIOUS_AT, Scanner  # noqa: E402

DATA = os.environ.get("AV_DATA_DIR", os.path.join(ROOT, "webapp_data"))
PUBLIC_MODE = os.environ.get("PUBLIC_MODE", "0") not in ("", "0", "false", "no")
RETENTION_H = float(os.environ.get("RETENTION_HOURS", "24"))
MAX_MB = int(os.environ.get("MAX_UPLOAD_MB", "10"))

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
                  MAX_CONTENT_LENGTH=MAX_MB * 1024 * 1024)
SCANNER = Scanner()
_last_cleanup = [0.0]


def workspace():
    vid = session.get("vid")
    if not vid or not vid.isalnum():
        vid = session["vid"] = secrets.token_hex(8)
    base = os.path.join(DATA, "visitors", vid)
    for sub in ("files", "results", "watch"):
        os.makedirs(os.path.join(base, sub), exist_ok=True)
    return base


def tools():
    base = workspace()
    return base, Quarantine(os.path.join(base, "quarantine")), History(os.path.join(base, "history.jsonl"))


def save_result(base, result):
    write_json([result], os.path.join(base, "results", result["id"] + ".json"))


def load_result(base, rid):
    import json
    if not rid.isalnum():
        abort(404)
    p = os.path.join(base, "results", rid + ".json")
    if not os.path.exists(p):
        abort(404)
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)["results"][0]


@app.before_request
def cleanup():
    if not PUBLIC_MODE or time.time() - _last_cleanup[0] < 600:
        return
    _last_cleanup[0] = time.time()
    root = os.path.join(DATA, "visitors")
    if os.path.isdir(root):
        for vid in os.listdir(root):
            p = os.path.join(root, vid)
            if time.time() - os.path.getmtime(p) > RETENTION_H * 3600:
                shutil.rmtree(p, ignore_errors=True)


@app.context_processor
def inject():
    return {"version": __version__, "public_mode": PUBLIC_MODE, "retention": int(RETENTION_H), "max_mb": MAX_MB,
            "n_sigs": len(SCANNER.signatures), "n_rules": len(SCANNER.rules),
            "malicious_at": MALICIOUS_AT, "suspicious_at": SUSPICIOUS_AT}


def run_scan(path, display, mode, auto_q):
    base, q, hist = tools()
    result = SCANNER.scan_file(path, mode, display)
    result["path"] = display
    result["quarantined"] = None
    if auto_q and result["verdict"] == "Malicious":
        result["quarantined"] = q.add(path, result, display)["id"]
    hist.add(result, "web")
    save_result(base, result)
    return result


@app.get("/")
def index():
    base, q, hist = tools()
    items = hist.read()
    stats = {v: sum(1 for h in items if h["verdict"] == v) for v in ("Clean", "Suspicious", "Malicious")}
    return render_template("index.html", samples=SAMPLES, recent=items[:5], stats=stats, total=len(items),
                           quarantined=len(q.list()))


@app.post("/scan")
def scan_upload():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Choose a file first.", "error")
        return redirect(url_for("index"))
    base = workspace()
    name = secure_filename(f.filename) or "upload.bin"
    path = os.path.join(base, "files", secrets.token_hex(4) + "_" + name)
    f.save(path)
    r = run_scan(path, name, request.form.get("mode", "full"), request.form.get("quarantine") == "on")
    return redirect(url_for("result", rid=r["id"]))


@app.post("/scan-sample/<name>")
def scan_sample(name):
    if name not in SAMPLES:
        abort(404)
    base = workspace()
    folder = os.path.join(base, "files", secrets.token_hex(4))
    path = create_samples(folder, [name])[0]
    r = run_scan(path, name, request.form.get("mode", "full"), request.form.get("quarantine", "on") == "on")
    return redirect(url_for("result", rid=r["id"]))


@app.get("/result/<rid>")
def result(rid):
    base = workspace()
    return render_template("result.html", r=load_result(base, rid))


@app.get("/report/<rid>.<fmt>")
def report(rid, fmt):
    base = workspace()
    r = load_result(base, rid)
    if fmt == "json":
        return send_file(os.path.join(base, "results", rid + ".json"), as_attachment=True,
                         download_name=f"scan_{rid}.json")
    if fmt == "html":
        return render_html([r], f"Scan report: {r['file']}")
    abort(404)


@app.get("/quarantine")
def quarantine():
    _, q, _ = tools()
    return render_template("quarantine.html", items=q.list())


@app.post("/quarantine/<qid>/<action>")
def quarantine_action(qid, action):
    base, q, _ = tools()
    try:
        if action == "restore":
            q.restore(qid, os.path.join(base, "files", "restored", q.get(qid)["name"] if q.get(qid) else qid))
            flash("File restored to your workspace. It will be detected again if you rescan it.", "ok")
        elif action == "delete":
            q.delete(qid)
            flash("File permanently deleted.", "ok")
        else:
            abort(404)
    except KeyError:
        flash("That item is no longer in quarantine.", "error")
    return redirect(url_for("quarantine"))


@app.get("/history")
def history():
    _, _, hist = tools()
    items = hist.read()
    stats = {v: sum(1 for h in items if h["verdict"] == v) for v in ("Clean", "Suspicious", "Malicious")}
    rules = {}
    mitre = {}
    for h in items:
        for r in h["rules"]:
            rules[r] = rules.get(r, 0) + 1
        for m in h["mitre"]:
            mitre[m] = mitre.get(m, 0) + 1
    top_rules = sorted(rules.items(), key=lambda x: -x[1])[:8]
    top_mitre = sorted(mitre.items(), key=lambda x: -x[1])[:8]
    return render_template("history.html", items=items, stats=stats, total=len(items),
                           top_rules=top_rules, top_mitre=top_mitre)


@app.route("/monitor", methods=["GET", "POST"])
def monitor():
    base, q, hist = tools()
    watch = os.path.join(base, "watch")
    log = session.get("monitor_log", [])
    if request.method == "POST":
        mon = FolderMonitor(watch, SCANNER, "full", q if request.form.get("quarantine", "on") == "on" else None)
        name = request.form.get("sample")
        if name in SAMPLES:
            create_samples(watch, [name])
        elif request.form.get("change"):
            files = sorted(os.listdir(watch))
            if files:
                with open(os.path.join(watch, files[0]), "ab") as fh:
                    fh.write(b"\nfiles have been encrypted - pay in bitcoin to decrypt\n")
        for ev in mon.check_once():
            r = ev["result"]
            r["path"] = r["file"]
            r["quarantined"] = ev["quarantined"]
            hist.add(r, "monitor")
            save_result(base, r)
            log.insert(0, {"time": time.strftime("%H:%M:%S"), "event": ev["event"], "file": r["file"], "verdict": r["verdict"],
                           "score": r["score"], "id": r["id"], "quarantined": ev["quarantined"]})
        session["monitor_log"] = log[:20]
        return redirect(url_for("monitor"))
    files = sorted(os.listdir(watch))
    return render_template("monitor.html", samples=SAMPLES, log=log, files=files)


@app.get("/about")
def about():
    return render_template("about.html", rules=SCANNER.rules.rules)


@app.errorhandler(413)
def too_large(_):
    flash(f"File too large. The limit is {MAX_MB} MB.", "error")
    return redirect(url_for("index"))


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": __version__}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"\n  Basic Antivirus Simulation v{__version__}\n  Open http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}/\n")
    try:
        from waitress import serve
        serve(app, host=host, port=port)
    except ImportError:
        app.run(host=host, port=port)
