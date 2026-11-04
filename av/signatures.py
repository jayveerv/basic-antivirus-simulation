"""Signature-based detection: SHA-256 / MD5 hash matching against a JSON database."""

import hashlib
import json
import os

CHUNK = 1 << 20


def file_hashes(path):
    """Return MD5 and SHA-256 of a file, read in chunks so large files are fine."""
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            md5.update(block)
            sha256.update(block)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def bytes_hashes(data):
    return {"md5": hashlib.md5(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest()}


class SignatureDB:
    """A small JSON signature database.

    Format::

        {"version": "...", "signatures": [
            {"name": "...", "sha256": "...", "md5": "...", "severity": "high",
             "mitre": "T....", "description": "..."}]}
    """

    def __init__(self, path):
        self.path = path
        with open(path, encoding="utf-8") as fh:
            self.data = json.load(fh)
        self._index()

    def _index(self):
        self.by_sha256, self.by_md5 = {}, {}
        for sig in self.data.get("signatures", []):
            if sig.get("sha256"):
                self.by_sha256[sig["sha256"].lower()] = sig
            if sig.get("md5"):
                self.by_md5[sig["md5"].lower()] = sig

    def __len__(self):
        return len(self.data.get("signatures", []))

    @property
    def version(self):
        return self.data.get("version", "unknown")

    def match(self, hashes):
        """Return the signature that matches these hashes, or None."""
        sig = self.by_sha256.get(hashes.get("sha256", "").lower())
        if sig:
            return dict(sig, matched_on="sha256")
        sig = self.by_md5.get(hashes.get("md5", "").lower())
        if sig:
            return dict(sig, matched_on="md5")
        return None

    def add(self, name, sha256=None, md5=None, severity="high", mitre="", description="", save=True):
        if not (sha256 or md5):
            raise ValueError("a signature needs a sha256 or md5 hash")
        sig = {"name": name, "sha256": (sha256 or "").lower(), "md5": (md5 or "").lower(),
               "severity": severity, "mitre": mitre, "description": description}
        self.data.setdefault("signatures", []).append(sig)
        self._index()
        if save:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2)
            os.replace(tmp, self.path)
        return sig
