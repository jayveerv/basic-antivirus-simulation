"""Quarantine: move detected files away and XOR-obfuscate them so they cannot be opened or run by accident.

Note: XOR is obfuscation, not encryption. It stops a quarantined file from being run or
re-detected by mistake; it does not protect it from someone who knows the key.
"""

import json
import os
import shutil
import time
import uuid

from .signatures import bytes_hashes

KEY = b"AVSIM-QUARANTINE-2026"


def xor(data, key=KEY):
    k = len(key)
    return bytes(b ^ key[i % k] for i, b in enumerate(data))


class Quarantine:
    def __init__(self, folder):
        self.folder = folder
        os.makedirs(folder, exist_ok=True)
        self.index_path = os.path.join(folder, "index.json")

    def _load(self):
        if not os.path.exists(self.index_path):
            return []
        with open(self.index_path, encoding="utf-8") as fh:
            return json.load(fh)

    def _save(self, items):
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items, fh, indent=2)
        os.replace(tmp, self.index_path)

    def list(self):
        return self._load()

    def get(self, qid):
        return next((i for i in self._load() if i["id"] == qid), None)

    def add(self, path, result=None, display_name=None):
        """Move a file into quarantine. The original is removed."""
        with open(path, "rb") as fh:
            data = fh.read()
        qid = uuid.uuid4().hex[:12]
        with open(os.path.join(self.folder, qid + ".qbin"), "wb") as fh:
            fh.write(xor(data))
        os.remove(path)
        item = {"id": qid, "name": display_name or os.path.basename(path), "original_path": os.path.abspath(path),
                "sha256": bytes_hashes(data)["sha256"], "size": len(data),
                "verdict": (result or {}).get("verdict", "Unknown"), "score": (result or {}).get("score"),
                "detections": [r["rule"] for r in (result or {}).get("rules", [])] +
                              ([result["signature"]["name"]] if result and result.get("signature") else []),
                "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        items = self._load()
        items.append(item)
        self._save(items)
        return item

    def restore(self, qid, dest=None):
        """Decode the file and put it back (at its original path, or `dest`). Returns the new path."""
        items = self._load()
        item = next((i for i in items if i["id"] == qid), None)
        if not item:
            raise KeyError(f"no quarantined file with id {qid}")
        with open(os.path.join(self.folder, qid + ".qbin"), "rb") as fh:
            data = xor(fh.read())
        target = dest or item["original_path"]
        os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
        base, ext = os.path.splitext(target)
        n = 1
        while os.path.exists(target):
            target = f"{base}.restored{n}{ext}"
            n += 1
        with open(target, "wb") as fh:
            fh.write(data)
        os.remove(os.path.join(self.folder, qid + ".qbin"))
        self._save([i for i in items if i["id"] != qid])
        return target

    def delete(self, qid):
        items = self._load()
        if not any(i["id"] == qid for i in items):
            raise KeyError(f"no quarantined file with id {qid}")
        p = os.path.join(self.folder, qid + ".qbin")
        if os.path.exists(p):
            os.remove(p)
        self._save([i for i in items if i["id"] != qid])

    def clear(self):
        shutil.rmtree(self.folder, ignore_errors=True)
        os.makedirs(self.folder, exist_ok=True)
