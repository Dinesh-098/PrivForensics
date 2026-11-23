from io import BytesIO
import hashlib

import numpy as np
import pandas as pd
import pytest

from modules.analysis_models import synthetic_features
from modules.evidence import Registry
from modules.privacy import assess, linkage_benchmark, protect, protect_lanl, text_privacy


def test_upload_deduplication_and_integrity_log(tmp_path):
    registry = Registry(tmp_path)
    case = registry.case("Example")
    evidence_id = registry.upload(case, "../input.csv", BytesIO(b"x,y\n1,2\n"))
    assert registry.upload(case, "copy.csv", BytesIO(b"x,y\n1,2\n")) == evidence_id
    item = registry.list("evidence", case)[0]
    assert item["name"] == "input.csv"
    assert item["sha256"] == hashlib.sha256(b"x,y\n1,2\n").hexdigest()
    assert registry.verify(evidence_id)
    assert registry.checked_audit()
    with registry.session() as db:
        db.execute("UPDATE audit SET details='corrupted' WHERE seq=2")
    assert not registry.checked_audit()


def test_reference_detects_tampering_and_does_not_copy(tmp_path):
    registry = Registry(tmp_path / "state")
    case = registry.case("Example")
    source = tmp_path / "source.txt"
    source.write_bytes(b"original")
    with pytest.raises(ValueError, match="fingerprint"):
        registry.register_reference(case, source, expected="0" * 64)
    identifier = registry.register_reference(case, source)
    assert registry.verify(identifier)
    source.write_bytes(b"changed")
    assert not registry.verify(identifier)
    assert [item["storage"] for item in registry.list("evidence")] == ["reference"]
    assert not list(registry.vault.iterdir())


def fixture_frame():
    return pd.DataFrame({
        "User_ID": ["U1", "U1"], "Email": ["alice@example.com", "second@example.com"],
        "IP_Address": ["192.0.2.1", "192.0.2.2"], "Login_Hour": [4, 12],
        "Failed_Attempts": [1, 2], "Location": ["India", "USA"], "Access_Type": ["Web", "VPN"],
        "Device_Type": ["Laptop", "Mobile"], "Status": [1, 0],
    })


def test_structured_masking_hmac_and_model_projection():
    frame = fixture_frame()
    key = bytes(range(32))
    masked = protect(frame, "mask")
    pseudonyms = protect(frame, "hmac", key)
    assert "@example.com" not in masked.to_csv()
    assert pseudonyms.User_ID.nunique() == 1
    assert pseudonyms.Email.nunique() == 2
    assert protect(frame, "hmac", key).equals(pseudonyms)
    assert assess(frame)["quasi_identifier_singletons"] == 2
    assert np.array_equal(synthetic_features(frame), synthetic_features(pseudonyms))


def test_presidio_runs_locally():
    findings, masked = text_privacy("Send this to alice@example.com")
    assert any(item["type"] == "EMAIL_ADDRESS" for item in findings)
    assert "alice@example.com" not in masked


def test_linkage_benchmark_demonstrates_quasi_identifier_risk():
    rows = linkage_benchmark(42)
    assert rows[0]["recall"] == 1
    assert rows[1]["correct_links"] == rows[2]["correct_links"]
    assert rows[3]["correct_links"] < rows[2]["correct_links"]

def test_lanl_pseudonyms_join_across_roles_and_feeds():
    auth = pd.DataFrame({"source_account": ["U1@DOM"], "destination_computer": ["C1"]})
    process = pd.DataFrame({"account": ["U1@DOM"], "computer": ["C1"], "process": ["P1"]})
    red_team = pd.DataFrame({"account": ["U1@DOM"], "source_computer": ["C1"]})
    key = bytes(range(32))
    a, p, r = [protect_lanl(frame, "hmac", key).iloc[0] for frame in (auth, process, red_team)]
    assert a.source_account == p.account == r.account
    assert a.destination_computer == p.computer == r.source_computer
    assert a.source_account != p.computer
