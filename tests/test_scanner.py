"""Phase 2 tests: allowlist and result parsing. Nmap itself is mocked."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
import scanner


class FakeHost(dict):
    def all_protocols(self):
        return list(self.keys())


class FakeScanner:
    """Stands in for nmap.PortScanner so tests need no real scan."""
    last_call = {}

    def scan(self, hosts, arguments, timeout):
        FakeScanner.last_call = {"hosts": hosts, "arguments": arguments, "timeout": timeout}

    def all_hosts(self):
        return ["127.0.0.1"]

    def __getitem__(self, host):
        return FakeHost({
            "tcp": {
                443: {"state": "open", "name": "https", "product": "nginx", "version": "1.24"},
                22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "9.6"},
                23: {"state": "open", "name": "telnet", "product": "", "version": ""},
                8080: {"state": "closed", "name": "http", "product": "", "version": ""},
            }
        })


def test_non_allowlisted_target_is_rejected():
    with pytest.raises(scanner.TargetNotAllowed):
        scanner.scan("8.8.8.8")


def test_rejected_target_never_reaches_nmap(monkeypatch):
    def boom():
        raise AssertionError("Nmap must not be called for blocked targets")
    monkeypatch.setattr(scanner.nmap, "PortScanner", boom)
    with pytest.raises(scanner.TargetNotAllowed):
        scanner.scan("192.168.1.50")


@pytest.mark.parametrize("bad", ["", "127.0.0.1; rm -rf /", "10.0.0.0/24", "google.com", "127.0.0.2"])
def test_tricky_targets_are_rejected(bad):
    with pytest.raises(scanner.TargetNotAllowed):
        scanner.validate_target(bad)


def test_builtin_targets_are_allowed():
    assert scanner.validate_target("127.0.0.1") == "127.0.0.1"
    assert scanner.validate_target(" LocalHost ") == "localhost"


def test_config_allowlist_works(monkeypatch):
    monkeypatch.setattr(config, "ALLOWED_TARGETS", ["192.168.1.10"])
    assert scanner.validate_target("192.168.1.10") == "192.168.1.10"


def test_scan_output_and_safe_options(monkeypatch):
    monkeypatch.setattr(scanner.nmap, "PortScanner", FakeScanner)
    ports = scanner.scan("localhost")
    # Closed ports are skipped, output is sorted by port.
    assert [p["port"] for p in ports] == [22, 23, 443]
    assert ports[0] == {"port": 22, "protocol": "tcp", "service": "ssh",
                        "version": "OpenSSH 9.6", "encrypted": "yes"}
    assert ports[1]["encrypted"] == "no"
    # Safe options only, and the timeout is passed on.
    args = FakeScanner.last_call["arguments"]
    assert "-sV" in args and "--top-ports 1000" in args
    assert "--script" not in args and "-A" not in args
    assert FakeScanner.last_call["timeout"] == config.SCAN_TIMEOUT_SECONDS
