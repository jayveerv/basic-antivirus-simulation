import io
import os
import re

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AV_DATA_DIR", str(tmp_path / "data"))
    import importlib
    import webapp.app as appmod
    appmod = importlib.reload(appmod)
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()


def rid_from(resp):
    return resp.headers["Location"].rsplit("/", 1)[-1]


def test_pages_load(client):
    for url in ["/", "/quarantine", "/history", "/monitor", "/about", "/healthz"]:
        assert client.get(url).status_code == 200, url


def test_sample_scan_and_quarantine_flow(client):
    r = client.post("/scan-sample/eicar_test_file.com", data={"mode": "full", "quarantine": "on"})
    assert r.status_code == 302
    page = client.get(f"/result/{rid_from(r)}").get_data(as_text=True)
    assert "Malicious" in page and "EICAR-Test-File" in page and "Moved to quarantine" in page
    q = client.get("/quarantine").get_data(as_text=True)
    qid = re.search(r"/quarantine/([0-9a-f]{12})/restore", q).group(1)
    assert client.post(f"/quarantine/{qid}/restore").status_code == 302
    assert "Quarantine is empty" in client.get("/quarantine").get_data(as_text=True)


def test_upload_clean_file(client):
    r = client.post("/scan", data={"file": (io.BytesIO(b"just some notes"), "notes.txt"), "mode": "quick"},
                    content_type="multipart/form-data")
    page = client.get(f"/result/{rid_from(r)}").get_data(as_text=True)
    assert "Clean" in page and "notes.txt" in page


def test_upload_without_file(client):
    r = client.post("/scan", data={}, content_type="multipart/form-data", follow_redirects=True)
    assert "Choose a file first" in r.get_data(as_text=True)


def test_reports_download(client):
    rid = rid_from(client.post("/scan-sample/suspicious_script.txt"))
    assert client.get(f"/report/{rid}.json").status_code == 200
    html = client.get(f"/report/{rid}.html").get_data(as_text=True)
    assert "PowerShell_Download_Cradle" in html
    assert client.get(f"/report/{rid}.exe").status_code == 404


def test_history_and_monitor(client):
    client.post("/scan-sample/clean_notes.txt")
    client.post("/monitor", data={"sample": "eicar_test_file.com", "quarantine": "on"})
    page = client.get("/monitor").get_data(as_text=True)
    assert "auto-quarantined" in page
    client.post("/monitor", data={"sample": "clean_notes.txt"})
    client.post("/monitor", data={"change": "1"})
    assert "changed" in client.get("/monitor").get_data(as_text=True)
    hist = client.get("/history").get_data(as_text=True)
    assert "monitor" in hist and "clean_notes.txt" in hist


def test_visitors_are_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("AV_DATA_DIR", str(tmp_path / "data"))
    import importlib
    import webapp.app as appmod
    appmod = importlib.reload(appmod)
    a, b = appmod.app.test_client(), appmod.app.test_client()
    rid = rid_from(a.post("/scan-sample/clean_notes.txt"))
    assert a.get(f"/result/{rid}").status_code == 200
    assert b.get(f"/result/{rid}").status_code == 404
    assert "clean_notes.txt" not in b.get("/history").get_data(as_text=True)


def test_upload_limit(client, monkeypatch):
    import webapp.app as appmod
    appmod.app.config["MAX_CONTENT_LENGTH"] = 1000
    r = client.post("/scan", data={"file": (io.BytesIO(b"x" * 5000), "big.bin")}, content_type="multipart/form-data")
    assert r.status_code in (302, 413)


def test_unknown_sample_and_result(client):
    assert client.post("/scan-sample/real_malware.exe").status_code == 404
    assert client.get("/result/doesnotexist").status_code == 404
    assert client.get("/result/..%2f..%2fetc").status_code == 404
