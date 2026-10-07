"""Phase 4 tests: dataset, training, metrics, and predictions."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import model
from data.build_dataset import LABELS, build_dataset


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    """Build a fresh dataset, train a model, and return its paths and metrics."""
    tmp = tmp_path_factory.mktemp("risk")
    csv, mdl, met = tmp / "d.csv", tmp / "m.joblib", tmp / "metrics.json"
    build_dataset().to_csv(csv, index=False)
    metrics = model.train(csv, mdl, met)
    return {"model": model.joblib.load(mdl), "metrics": metrics, "metrics_path": met}


def test_dataset_size_and_labels():
    df = build_dataset()
    assert len(df) >= 2000
    assert set(df["risk"]) == set(LABELS)


def test_dataset_is_repeatable():
    assert build_dataset(seed=1).equals(build_dataset(seed=1))


def test_metrics_file_has_required_fields(trained):
    saved = json.loads(trained["metrics_path"].read_text())
    assert 0.7 < saved["accuracy"] <= 1.0
    assert 0.7 < saved["macro_f1"] <= 1.0
    assert saved["confusion_matrix"]["labels"] == LABELS
    assert len(saved["confusion_matrix"]["matrix"]) == 3


def test_risky_and_safe_services(trained):
    ports = [
        {"port": 23, "protocol": "tcp", "service": "telnet", "version": "", "encrypted": "no"},
        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 9.9", "encrypted": "yes"},
    ]
    result = model.predict_ports(ports, model=trained["model"])
    by_port = {r["port"]: r for r in result}
    assert by_port[23]["risk"] == "high"
    assert by_port[22]["risk"] == "low"
    assert result[0]["port"] == 23                      # sorted riskiest first
    assert {"risk", "risk_score", "confidence"} <= set(result[0])


def test_unknown_service_does_not_crash(trained):
    ports = [{"port": 9999, "protocol": "tcp", "service": "weird-thing", "version": "", "encrypted": "no"}]
    assert model.predict_ports(ports, model=trained["model"])[0]["risk"] in LABELS


def test_empty_port_list(trained):
    assert model.predict_ports([], model=trained["model"]) == []


def test_version_lag_estimate():
    assert model.version_lag("OpenSSH 9.9") == 0
    assert model.version_lag("nginx 1.14") == 13
    assert model.version_lag("") == 0
    assert model.version_lag("SomethingElse 2.0") == 0
