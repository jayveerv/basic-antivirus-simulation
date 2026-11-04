"""Real-time folder monitoring by polling: detects new or changed files and scans them.

Polling works the same on Windows, Linux and macOS and needs no extra packages.
"""

import os
import threading
import time


class FolderMonitor:
    def __init__(self, folder, scanner, mode="full", quarantine=None, on_result=None, interval=2.0):
        self.folder = folder
        self.scanner = scanner
        self.mode = mode
        self.quarantine = quarantine
        self.on_result = on_result
        self.interval = interval
        os.makedirs(folder, exist_ok=True)
        self._seen = self._snapshot()
        self._stop = threading.Event()
        self._thread = None

    def _snapshot(self):
        snap = {}
        for root, _, files in os.walk(self.folder):
            for f in files:
                p = os.path.join(root, f)
                try:
                    st = os.stat(p)
                    snap[p] = (st.st_mtime_ns, st.st_size)
                except OSError:
                    pass
        return snap

    def check_once(self):
        """Look for new or changed files once, scan them and return the events."""
        now = self._snapshot()
        events = []
        for path, stamp in sorted(now.items()):
            old = self._seen.get(path)
            if old == stamp:
                continue
            kind = "new" if old is None else "changed"
            result = self.scanner.scan_file(path, self.mode)
            result["file"] = os.path.relpath(path, self.folder)
            event = {"event": kind, "path": path, "result": result, "quarantined": None}
            if self.quarantine and result["verdict"] == "Malicious":
                event["quarantined"] = self.quarantine.add(path, result, result["file"])["id"]
            events.append(event)
            if self.on_result:
                self.on_result(event)
        self._seen = self._snapshot()
        return events

    def _run(self):
        while not self._stop.is_set():
            self.check_once()
            self._stop.wait(self.interval)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def run_forever(self):
        try:
            self._run()
        except KeyboardInterrupt:
            pass
