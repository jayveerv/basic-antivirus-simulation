import json
import os
import subprocess
import sys

import pytest

from av.monitor import FolderMonitor
from av.quarantine import Quarantine, xor
from av.report import History, write_html, write_json
from av.samples import create_samples

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------- quarantine ----------------

def test_xor_round_trip():
    data = os.urandom(1000)
    assert xor(xor(data)) == data and xor(data) != data


def test_quarantine_add_restore_delete(tmp_path, scanner, samples):
    q = Quarantine(str(tmp_path / "q"))
    path = samples / "eicar_test_file.com"
    original = path.read_bytes()
    r = scanner.scan_file(str(path))
    item = q.add(str(path), r)
    assert not path.exists()
    stored = (tmp_path / "q" / (item["id"] + ".qbin")).read_bytes()
    assert stored != original and b"EICAR" not in stored
    assert "EICAR-Test-File" in item["detections"]
    restored = q.restore(item["id"])
    assert open(restored, "rb").read() == original and q.list() == []
    item2 = q.add(restored, r)
    q.delete(item2["id"])
    assert q.list() == [] and not os.path.exists(restored)
    with pytest.raises(KeyError):
        q.delete("missing")


def test_restore_does_not_overwrite(tmp_path):
    q = Quarantine(str(tmp_path / "q"))
    p = tmp_path / "a.txt"
    p.write_text("first")
    item = q.add(str(p))
    p.write_text("new file with same name")
    out = q.restore(item["id"])
    assert out != str(p) and open(out).read() == "first" and p.read_text() == "new file with same name"


# ---------------- monitor ----------------

def test_monitor_detects_new_and_changed(tmp_path, scanner):
    watch = tmp_path / "watch"
    watch.mkdir()
    (watch / "old.txt").write_text("existing")
    mon = FolderMonitor(str(watch), scanner)
    assert mon.check_once() == []
    create_samples(str(watch), ["clean_notes.txt"])
    ev = mon.check_once()
    assert [(e["event"], e["result"]["file"]) for e in ev] == [("new", "clean_notes.txt")]
    with open(watch / "old.txt", "a") as fh:
        fh.write("\nfiles have been encrypted, pay bitcoin")
    ev = mon.check_once()
    assert ev[0]["event"] == "changed" and ev[0]["result"]["verdict"] == "Suspicious"


def test_monitor_auto_quarantine(tmp_path, scanner):
    watch = tmp_path / "watch"
    q = Quarantine(str(tmp_path / "q"))
    seen = []
    mon = FolderMonitor(str(watch), scanner, quarantine=q, on_result=seen.append)
    create_samples(str(watch), ["eicar_test_file.com"])
    ev = mon.check_once()
    assert ev[0]["quarantined"] and not (watch / "eicar_test_file.com").exists()
    assert len(q.list()) == 1 and len(seen) == 1


def test_monitor_thread_start_stop(tmp_path, scanner):
    mon = FolderMonitor(str(tmp_path / "w"), scanner, interval=0.05)
    mon.start()
    mon.stop()
    assert not mon._thread.is_alive()


# ---------------- reports ----------------

def test_reports_and_history(tmp_path, scanner, samples):
    results = scanner.scan_folder(str(samples))
    j = write_json(results, str(tmp_path / "r" / "scan.json"))
    doc = json.load(open(j))
    assert doc["summary"]["files"] == len(results) and doc["results"][0]["hashes"]
    h = write_html(results, str(tmp_path / "r" / "scan.html"))
    html = open(h, encoding="utf-8").read()
    assert "<!DOCTYPE html>" in html and "eicar_test_file.com" in html and "Malicious" in html
    hist = History(str(tmp_path / "h" / "history.jsonl"))
    for r in results:
        hist.add(r)
    items = hist.read()
    assert len(items) == len(results) and items[0]["file"] == results[-1]["file"]
    assert len(hist.read(3)) == 3


def test_html_report_escapes_names(tmp_path, scanner):
    p = tmp_path / "a.txt"
    p.write_text("x")
    r = scanner.scan_file(str(p))
    r["file"] = "<script>.txt"  # such names are illegal on Windows, so set it directly
    html = open(write_html([r], str(tmp_path / "r.html")), encoding="utf-8").read()
    assert "<script>.txt" not in html and "&lt;script&gt;.txt" in html


# ---------------- CLI ----------------

def run_cli(args, cwd, state):
    env = dict(os.environ, AV_STATE_DIR=str(state), NO_COLOR="1")
    return subprocess.run([sys.executable, os.path.join(ROOT, "scan.py")] + args, cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=60)


def test_cli_end_to_end(tmp_path):
    state = tmp_path / "state"
    assert run_cli(["samples", "files"], tmp_path, state).returncode == 0
    out = run_cli(["scan", "files", "--report", "both", "--out", "rep", "--quarantine"], tmp_path, state)
    assert out.returncode == 1  # malicious files found
    assert "Malicious" in out.stdout and "quarantined as" in out.stdout
    assert any(f.endswith(".html") for f in os.listdir(tmp_path / "rep"))
    lst = run_cli(["quarantine", "list"], tmp_path, state).stdout
    qid = lst.split()[0]
    assert run_cli(["quarantine", "restore", qid], tmp_path, state).returncode == 0
    assert "Malicious" in run_cli(["history"], tmp_path, state).stdout
    clean = run_cli(["scan", "files/clean_notes.txt", "--quick"], tmp_path, state)
    assert clean.returncode == 0 and "Clean" in clean.stdout
    bad = run_cli(["quarantine", "delete", "doesnotexist"], tmp_path, state)
    assert bad.returncode == 2
