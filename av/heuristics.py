"""Heuristic analysis: entropy, strings, suspicious API names, PE structure and packing hints.

Each finding carries the number of risk points it adds, so the final score is explainable.
"""

import math
import re
import struct
from collections import Counter

SUSPICIOUS_APIS = {
    "VirtualAlloc": "Allocates memory, often for unpacked or injected code",
    "VirtualAllocEx": "Allocates memory inside another process (injection)",
    "WriteProcessMemory": "Writes into another process (injection)",
    "CreateRemoteThread": "Starts code inside another process (injection)",
    "NtUnmapViewOfSection": "Used in process hollowing",
    "LoadLibraryA": "Loads libraries at run time (hides imports)",
    "GetProcAddress": "Resolves functions at run time (hides imports)",
    "URLDownloadToFileA": "Downloads a file from the internet",
    "InternetOpenUrlA": "Opens a URL",
    "WinExec": "Runs a program",
    "ShellExecuteA": "Runs a program or opens a file",
    "GetAsyncKeyState": "Reads key presses (keylogging)",
    "SetWindowsHookExA": "Installs a system-wide hook (keylogging)",
    "IsDebuggerPresent": "Checks for a debugger (anti-analysis)",
    "CryptEncrypt": "Encrypts data (ransomware behaviour)",
    "RegSetValueExA": "Writes to the registry (persistence)",
    "AdjustTokenPrivileges": "Raises privileges",
}

SUSPICIOUS_STRINGS = [
    (r"https?://[^\s\"'<>]{4,}", "URL"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP address"),
    (r"cmd\.exe", "Windows command shell"),
    (r"powershell", "PowerShell"),
    (r"/bin/(?:ba)?sh", "Unix shell"),
    (r"\bwget\s|\bcurl\s", "Download command"),
    (r"\.onion\b", "Tor hidden service"),
    (r"bitcoin|monero|\bwallet\b", "Cryptocurrency"),
    (r"[A-Za-z0-9+/]{120,}={0,2}", "Long base64 blob"),
    (r"CurrentVersion\\Run", "Registry run key"),
]

PACKER_SECTIONS = {b"UPX0", b"UPX1", b"UPX2", b".aspack", b".adata", b".petite", b"MPRESS1", b"MPRESS2", b".nsp0", b".themida"}

COMPRESSED_TYPES = {"ZIP / Office document", "PNG image", "JPEG image", "GZIP archive", "PDF document", "7-Zip archive", "RAR archive"}

MAGIC = [
    (b"MZ", "Windows executable (PE)"),
    (b"\x7fELF", "Linux executable (ELF)"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP / Office document"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"7z\xbc\xaf", "7-Zip archive"),
    (b"Rar!", "RAR archive"),
    (b"#!", "Script with shebang"),
]

EXECUTABLE_EXT = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".hta"}
DOCUMENT_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".jpeg", ".png", ".mp3", ".mp4", ".zip"}


def entropy(data):
    """Shannon entropy in bits per byte (0 = uniform, 8 = random)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def file_type(data):
    for magic, name in MAGIC:
        if data.startswith(magic):
            return name
    sample = data[:4096]
    if sample and all(b in b"\t\n\r" or 32 <= b < 127 or b >= 128 for b in sample):
        return "Text"
    return "Binary data"


def extract_strings(data, min_len=5, limit=5000):
    ascii_ = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    wide = [w.replace(b"\x00", b"") for w in re.findall(rb"(?<![\x20-\x7e])(?:[\x20-\x7e]\x00){%d,}" % min_len, data)]
    out = [s.decode("ascii") for s in ascii_ + wide]
    return out[:limit]


def parse_pe(data):
    """Very small PE parser: returns the section table, or None if not a PE file."""
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return {"valid": False, "sections": []}
    n_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    table = pe_off + 24 + opt_size
    sections = []
    for i in range(min(n_sections, 32)):
        off = table + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00")
        raw_size, raw_ptr = struct.unpack_from("<II", data, off + 16)
        body = data[raw_ptr:raw_ptr + raw_size]
        sections.append({"name": name.decode("latin-1"), "raw_size": raw_size,
                         "entropy": round(entropy(body), 2), "_raw_name": name})
    return {"valid": True, "sections": sections}


def analyse(data, filename=""):
    """Run every heuristic and return (findings, details).

    findings: list of {"check", "detail", "points"}
    """
    findings = []
    ftype = file_type(data)
    ent = entropy(data)
    details = {"file_type": ftype, "entropy": round(ent, 2), "size": len(data)}

    if ent > 7.5 and ftype not in COMPRESSED_TYPES and len(data) > 1024:
        findings.append({"check": "High entropy", "detail": f"{ent:.2f} bits/byte: content looks encrypted or packed", "points": 15})

    strings = extract_strings(data)
    joined = "\n".join(strings)
    apis = sorted(a for a in SUSPICIOUS_APIS if a in joined)
    details["suspicious_apis"] = apis
    if apis:
        findings.append({"check": "Suspicious API names", "detail": ", ".join(apis),
                         "points": min(5 * len(apis), 25)})

    found_strings = []
    for pattern, label in SUSPICIOUS_STRINGS:
        m = re.search(pattern, joined, re.I)
        if m:
            found_strings.append(f"{label}: {m.group(0)[:60]}")
    details["suspicious_strings"] = found_strings
    if found_strings:
        findings.append({"check": "Suspicious strings", "detail": "; ".join(found_strings),
                         "points": min(3 * len(found_strings), 15)})

    pe = parse_pe(data)
    if pe is not None:
        details["pe_sections"] = [{k: v for k, v in s.items() if not k.startswith("_")} for s in pe["sections"]]
        packers = [s["name"] for s in pe["sections"] if s["_raw_name"] in PACKER_SECTIONS]
        if packers:
            findings.append({"check": "Packer section names", "detail": ", ".join(packers), "points": 20})
        hot = [s["name"] for s in pe["sections"] if s["entropy"] > 7.2 and s["raw_size"] > 512]
        if hot:
            findings.append({"check": "High-entropy PE sections", "detail": ", ".join(hot) + " look packed or encrypted", "points": 10})
        if not pe["valid"]:
            findings.append({"check": "Malformed PE header", "detail": "MZ header without a valid PE signature", "points": 5})

    name = filename.lower()
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if ftype.startswith("Windows executable") and ext and ext not in EXECUTABLE_EXT:
        findings.append({"check": "Extension mismatch", "detail": f"{ext} file is really a Windows executable", "points": 30})
    parts = name.split(".")
    if len(parts) >= 3 and "." + parts[-2] in DOCUMENT_EXT and "." + parts[-1] in EXECUTABLE_EXT:
        findings.append({"check": "Double extension", "detail": f"looks like .{parts[-2]} but is .{parts[-1]}", "points": 30})
    return findings, details
