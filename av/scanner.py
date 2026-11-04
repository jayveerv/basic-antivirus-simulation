"""The scan engine: combines signatures, rules and heuristics into one explainable risk score."""

import os
import time
import uuid

from .heuristics import analyse, file_type, entropy
from .rules import RuleSet
from .signatures import SignatureDB, file_hashes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SIGNATURES = os.path.join(ROOT, "data", "signatures.json")
DEFAULT_RULES = os.path.join(ROOT, "rules", "default.yar")

RULE_POINTS = {"high": 40, "medium": 25, "low": 10}
MALICIOUS_AT = 70
SUSPICIOUS_AT = 30
MAX_READ = 50 * 1024 * 1024  # files above 50 MB are hashed but only the first 50 MB are inspected


def verdict_for(score):
    if score >= MALICIOUS_AT:
        return "Malicious"
    if score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Clean"


class Scanner:
    def __init__(self, signatures=DEFAULT_SIGNATURES, rules=DEFAULT_RULES):
        self.signatures = SignatureDB(signatures)
        self.rules = RuleSet.from_file(rules)

    def scan_file(self, path, mode="full", display_name=None):
        """Scan one file. mode = 'quick' (signatures + rules) or 'full' (+ heuristics)."""
        if mode not in ("quick", "full"):
            raise ValueError("mode must be 'quick' or 'full'")
        started = time.time()
        name = display_name or os.path.basename(path)
        result = {"id": uuid.uuid4().hex[:12], "file": name, "path": os.path.abspath(path), "mode": mode,
                  "time": time.strftime("%Y-%m-%d %H:%M:%S"), "reasons": [], "signature": None,
                  "rules": [], "heuristics": [], "error": None}
        try:
            size = os.path.getsize(path)
            hashes = file_hashes(path)
            with open(path, "rb") as fh:
                data = fh.read(MAX_READ)
        except OSError as exc:
            result.update(score=0, verdict="Error", error=str(exc), size=0, hashes={})
            return result
        result.update(size=size, hashes=hashes, file_type=file_type(data), entropy=round(entropy(data), 2))
        score = 0

        sig = self.signatures.match(hashes)
        if sig:
            result["signature"] = sig
            score = 100
            result["reasons"].append({"source": "Signature", "detail": f"{sig['name']} (matched {sig['matched_on'].upper()})", "points": 100})

        for hit in self.rules.scan(data):
            pts = RULE_POINTS[hit["severity"]]
            result["rules"].append(hit)
            score += pts
            result["reasons"].append({"source": "Rule", "detail": f"{hit['rule']} [{hit['mitre'] or 'no ATT&CK id'}]", "points": pts})

        if mode == "full":
            findings, details = analyse(data, name)
            result["heuristics"] = findings
            result["details"] = details
            for f in findings:
                score += f["points"]
                result["reasons"].append({"source": "Heuristic", "detail": f"{f['check']}: {f['detail']}", "points": f["points"]})

        result["score"] = min(score, 100)
        result["verdict"] = verdict_for(result["score"])
        result["mitre"] = sorted({h["mitre"] for h in result["rules"] if h["mitre"]} |
                                 ({sig["mitre"]} if sig and sig.get("mitre") else set()))
        result["duration_ms"] = round((time.time() - started) * 1000, 1)
        return result

    def scan_folder(self, folder, mode="full", skip=()):
        """Scan every file under a folder (recursive). Returns a list of results."""
        skip = {os.path.abspath(s) for s in skip}
        results = []
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if os.path.abspath(os.path.join(root, d)) not in skip and not d.startswith(".")]
            for f in sorted(files):
                p = os.path.join(root, f)
                if os.path.isfile(p):
                    r = self.scan_file(p, mode)
                    r["file"] = os.path.relpath(p, folder)
                    results.append(r)
        return results


def summarise(results):
    counts = {"Clean": 0, "Suspicious": 0, "Malicious": 0, "Error": 0}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"files": len(results), **counts}
