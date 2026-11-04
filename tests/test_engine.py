import json
import os

import pytest

from av.heuristics import analyse, entropy, extract_strings, file_type, parse_pe
from av.rules import RuleError, RuleSet, parse_rules
from av.samples import eicar_bytes
from av.scanner import summarise, verdict_for
from av.signatures import SignatureDB, bytes_hashes, file_hashes


# ---------------- signatures ----------------

def test_eicar_hashes_are_the_published_values():
    h = bytes_hashes(eicar_bytes())
    assert h["sha256"] == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert h["md5"] == "44d88612fea8a8f36de82e1278abb02f"


def test_file_hashes_match_bytes_hashes(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello" * 1000)
    assert file_hashes(str(p)) == bytes_hashes(b"hello" * 1000)


def test_signature_db_match_by_sha256_and_md5(tmp_path):
    db_path = tmp_path / "db.json"
    db_path.write_text(json.dumps({"signatures": [{"name": "A", "sha256": "AB", "md5": "cd"}]}))
    db = SignatureDB(str(db_path))
    assert db.match({"sha256": "ab", "md5": "x"})["matched_on"] == "sha256"
    assert db.match({"sha256": "zz", "md5": "CD"})["matched_on"] == "md5"
    assert db.match({"sha256": "zz", "md5": "zz"}) is None


def test_signature_db_add_persists(tmp_path):
    db_path = tmp_path / "db.json"
    db_path.write_text(json.dumps({"signatures": []}))
    db = SignatureDB(str(db_path))
    db.add("New", sha256="FF" * 32)
    assert len(SignatureDB(str(db_path))) == 1
    with pytest.raises(ValueError):
        db.add("NoHash")


# ---------------- rules ----------------

RULES = r'''
rule TextNocase {
    meta:
        severity = "high"
        mitre = "T1"
    strings:
        $a = "hello" nocase
    condition:
        $a
}
rule HexAt0 {
    meta:
        severity = "low"
    strings:
        $mz = { 4D 5A ?? 00 }
    condition:
        $mz at 0
}
rule TwoOf {
    strings:
        $a = "alpha"
        $b = "beta"
        $c = "gamma"
    condition:
        2 of them
}
rule Logic {
    strings:
        $a = "one"
        $b = "two"
        $c = "three"
    condition:
        $a and ($b or not $c)
}
rule Wide {
    strings:
        $w = "secret" wide
    condition:
        any of them
}
rule Regex {
    strings:
        $r = /id=[0-9]{4}/
    condition:
        #r >= 2 and filesize < 1000
}
'''


@pytest.fixture(scope="module")
def ruleset():
    return RuleSet(parse_rules(RULES))


def names(rs, data):
    return {h["rule"] for h in rs.scan(data)}


def test_text_nocase(ruleset):
    assert "TextNocase" in names(ruleset, b"xx HeLLo xx")


def test_hex_with_wildcard_at_offset(ruleset):
    assert "HexAt0" in names(ruleset, b"MZ\x90\x00rest")
    assert "HexAt0" not in names(ruleset, b"xxMZ\x90\x00")


def test_n_of_them(ruleset):
    assert "TwoOf" in names(ruleset, b"alpha gamma")
    assert "TwoOf" not in names(ruleset, b"alpha only")


def test_boolean_logic(ruleset):
    assert "Logic" in names(ruleset, b"one two three")
    assert "Logic" in names(ruleset, b"one")
    assert "Logic" not in names(ruleset, b"one three")


def test_wide_strings(ruleset):
    assert "Wide" in names(ruleset, "secret".encode("utf-16-le"))
    assert "Wide" not in names(ruleset, b"secret")


def test_regex_count_and_filesize(ruleset):
    assert "Regex" in names(ruleset, b"id=1234 id=5678")
    assert "Regex" not in names(ruleset, b"id=1234")
    assert "Regex" not in names(ruleset, b"id=1234 id=5678" + b"x" * 2000)


def test_match_details(ruleset):
    hit = next(h for h in ruleset.scan(b"..hello..") if h["rule"] == "TextNocase")
    assert hit["severity"] == "high" and hit["mitre"] == "T1"
    assert hit["matched"][0]["offset"] == 2


@pytest.mark.parametrize("bad", [
    'rule X { condition:\n $a\n}',
    'rule X { strings:\n $a = "x"\n condition:\n $a and import os\n}',
    'rule X { meta:\n severity = "huge"\n strings:\n $a = "x"\n condition:\n $a\n}',
    'rule X { strings:\n $a = { ZZ }\n condition:\n $a\n}',
    'nothing here',
])
def test_bad_rules_raise(bad):
    with pytest.raises(RuleError):
        parse_rules(bad)


def test_default_rules_load_and_have_mitre(scanner):
    assert len(scanner.rules) >= 10
    for r in scanner.rules.rules:
        assert r.mitre, r.name


# ---------------- heuristics ----------------

def test_entropy_bounds():
    assert entropy(b"") == 0
    assert entropy(b"aaaa") == 0
    assert 7.9 < entropy(bytes(range(256)) * 16) <= 8.0


def test_file_type_magic():
    assert file_type(b"MZ\x90\x00") == "Windows executable (PE)"
    assert file_type(b"%PDF-1.7") == "PDF document"
    assert file_type(b"plain text\n") == "Text"


def test_extract_ascii_and_wide_strings():
    data = b"\x00\x01VirtualAllocEx\x00" + "CreateRemoteThread".encode("utf-16-le")
    s = extract_strings(data)
    assert "VirtualAllocEx" in s and "CreateRemoteThread" in s


def test_pe_parser_on_fake_packed(samples):
    pe = parse_pe((samples / "fake_packed_program.bin").read_bytes())
    assert pe["valid"]
    assert [s["name"] for s in pe["sections"]] == ["UPX0", "UPX1"]
    assert pe["sections"][0]["entropy"] > 7.2


def test_double_extension_and_mismatch():
    f, _ = analyse(b"text", "invoice.pdf.exe")
    assert any(x["check"] == "Double extension" for x in f)
    f, _ = analyse(b"MZ" + b"\x00" * 100, "photo.jpg")
    assert any(x["check"] == "Extension mismatch" for x in f)


def test_compressed_files_not_flagged_for_entropy(samples):
    f, _ = analyse(b"PK\x03\x04" + os.urandom(5000), "archive.zip")
    assert not any(x["check"] == "High entropy" for x in f)


# ---------------- scanner ----------------

EXPECTED = {
    "eicar_test_file.com": "Malicious",
    "clean_notes.txt": "Clean",
    "logo.png": "Clean",
    "suspicious_script.txt": "Suspicious",
    "ransom_note_sample.txt": "Suspicious",
    "fake_packed_program.bin": "Malicious",
    "random_data.bin": "Clean",
    "invoice.pdf.exe": "Suspicious",
}


@pytest.mark.parametrize("name,verdict", EXPECTED.items())
def test_samples_get_expected_verdict(scanner, samples, name, verdict):
    r = scanner.scan_file(str(samples / name), "full")
    assert r["verdict"] == verdict, r["reasons"]
    assert sum(x["points"] for x in r["reasons"]) >= r["score"]


def test_eicar_signature_and_mitre(scanner, samples):
    r = scanner.scan_file(str(samples / "eicar_test_file.com"))
    assert r["score"] == 100 and r["signature"]["name"] == "EICAR-Test-File"
    assert "EICAR_Test_String" in [h["rule"] for h in r["rules"]]


def test_quick_scan_skips_heuristics(scanner, samples):
    q = scanner.scan_file(str(samples / "invoice.pdf.exe"), "quick")
    f = scanner.scan_file(str(samples / "invoice.pdf.exe"), "full")
    assert q["heuristics"] == [] and q["verdict"] == "Clean"
    assert f["verdict"] == "Suspicious"


def test_scan_folder_and_summary(scanner, samples):
    results = scanner.scan_folder(str(samples))
    s = summarise(results)
    assert s["files"] == len(EXPECTED)
    assert s["Malicious"] == 2 and s["Suspicious"] == 3 and s["Clean"] == 3


def test_missing_file_reports_error(scanner, tmp_path):
    r = scanner.scan_file(str(tmp_path / "nope.txt"))
    assert r["verdict"] == "Error" and r["error"]


def test_bad_mode(scanner, samples):
    with pytest.raises(ValueError):
        scanner.scan_file(str(samples / "logo.png"), "deep")


def test_verdict_thresholds():
    assert verdict_for(0) == "Clean" and verdict_for(29) == "Clean"
    assert verdict_for(30) == "Suspicious" and verdict_for(69) == "Suspicious"
    assert verdict_for(70) == "Malicious" and verdict_for(100) == "Malicious"
