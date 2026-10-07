"""Phase 3 tests: intent parser with messy spoken sentences."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from intent import parse_command

CASES = [
    # (sentence, expected intent, expected target)
    ("scan localhost and tell me the riskiest port", "scan", "localhost"),
    ("Scan local host", "scan", "localhost"),
    ("scam localhost please", "scan", "localhost"),                       # speech slip
    ("check local post", "scan", "localhost"),                            # speech slip
    ("um scan one two seven dot zero dot zero dot one", "scan", "127.0.0.1"),
    ("check 127.0.0.1", "scan", "127.0.0.1"),
    ("scan 192 dot 168 dot 1 dot 10 now", "scan", "192.168.1.10"),
    ("scan 8.8.8.8", "scan", "8.8.8.8"),                                  # parsed here, blocked by scanner
    ("scan google dot com", "scan", "google.com"),
    ("Hey Wispr, could you uh scan my computer?", "scan", "localhost"),
    ("SCAN LOCALHOST!!!", "scan", "localhost"),
    ("scan the loopback", "scan", "localhost"),
    ("scan localhost. Then explain the results.", "scan", "localhost"),
    ("explain the riskiest port", "explain", "localhost"),
    ("why is port 23 dangerous", "explain", "localhost"),
    ("what does that mean", "explain", "localhost"),
    ("explane the last result", "explain", "localhost"),                  # typo
    ("compare with the last scan", "compare_last", "localhost"),
    ("what changed since last time", "compare_last", "localhost"),
    ("compair this with the previous scan", "compare_last", "localhost"), # typo
    ("show me the scan history", "history", "localhost"),
    ("list my past scans", "history", "localhost"),
    ("show previous scans", "history", "localhost"),
    ("localhost", "scan", "localhost"),                                   # bare target stays default
    ("tell me a joke", "unknown", "localhost"),
    ("", "unknown", "localhost"),
]


@pytest.mark.parametrize("sentence,intent,target", CASES)
def test_parse_command(sentence, intent, target):
    result = parse_command(sentence)
    assert result == {"intent": intent, "target": target}


def test_at_least_15_sentences():
    assert len(CASES) >= 15


def test_none_input_is_safe():
    assert parse_command(None)["intent"] == "unknown"
