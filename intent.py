"""Intent parser: turns a spoken or typed command into an intent and a target.

Uses simple keyword rules. It also copes with messy speech-to-text,
such as "local host", "scam" for "scan", or "127 dot 0 dot 0 dot 1".
It only extracts the target. The scanner decides if the target is allowed.
"""
import re
from difflib import get_close_matches

DEFAULT_TARGET = "localhost"

# Keyword lists for each intent. Common speech-to-text slips are included.
SCAN_WORDS = ["scan", "scans", "scanned", "scanning", "scanner", "check", "probe",
              "test", "inspect", "audit", "analyze", "analyse", "nmap",
              "scam", "skan", "scann", "sgan"]
COMPARE_WORDS = ["compare", "compared", "comparison", "change", "changes", "changed",
                 "difference", "differences", "different", "diff", "versus", "vs",
                 "since", "against"]
HISTORY_WORDS = ["history", "histories", "past", "previous", "earlier", "recent",
                 "old", "log", "logs", "list", "archive"]
EXPLAIN_WORDS = ["explain", "why", "what", "which", "how", "meaning", "mean", "means",
                 "describe", "detail", "details", "danger", "dangerous",
                 "risky", "riskier", "riskiest"]

# Spoken digits, used only when looking for an IP address.
NUMBER_WORDS = {"zero": "0", "nought": "0", "one": "1", "two": "2", "three": "3",
                "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8",
                "nine": "9"}

# Ways people (and speech-to-text) say "this machine".
LOCALHOST_PATTERN = re.compile(
    r"\b(?:local\s?(?:host|hosts|post|most|hose)|loop\s?back"
    r"|(?:this|my)\s(?:machine|computer|pc|laptop|system))\b"
)
IP_PATTERN = re.compile(
    r"(?<![\d.])(\d(?:\s?\d){0,2})\.(\d(?:\s?\d){0,2})\.(\d(?:\s?\d){0,2})\.(\d(?:\s?\d){0,2})(?!\d)"
)
HOST_PATTERN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b")


def _first_index(tokens, words):
    """Index of the first token that matches a keyword (exact or close), else None."""
    for i, tok in enumerate(tokens):
        if tok in words:
            return i
        # Close match catches typos like "compair" or "histroy". Short words must match exactly.
        if len(tok) >= 4 and get_close_matches(tok, words, n=1, cutoff=0.8):
            return i
    return None


def extract_target(text):
    """Find the target in the sentence. Returns None if none is found."""
    t = text.lower()
    t = re.sub(r"[-_]", " ", t)
    t = re.sub(r"\s*\b(?:dot|point)\b\s*", ".", t)          # "127 dot 0" -> "127.0"
    t = re.sub(r"\b(" + "|".join(NUMBER_WORDS) + r")\b",
               lambda m: NUMBER_WORDS[m.group(1)], t)        # "one two seven" -> "1 2 7"
    t = re.sub(r"\.(?=\s|$)", "", t)                         # drop sentence-ending periods

    found = []  # (position, target)
    for m in LOCALHOST_PATTERN.finditer(t):
        found.append((m.start(), "localhost"))
    for m in IP_PATTERN.finditer(t):
        octets = [re.sub(r"\s", "", g) for g in m.groups()]
        if all(int(o) <= 255 for o in octets):
            found.append((m.start(), ".".join(str(int(o)) for o in octets)))
    for m in HOST_PATTERN.finditer(t):
        if not IP_PATTERN.fullmatch(m.group(0)):
            found.append((m.start(), m.group(0)))

    if found:
        return min(found)[1]  # earliest one in the sentence wins
    return None


def parse_command(text):
    """Return {"intent": ..., "target": ...}. Intent is one of:
    scan, explain, compare_last, history, or unknown."""
    text = text or ""
    tokens = re.findall(r"[a-z0-9]+", text.lower())

    # Order matters: compare and history beat scan because they also say "scan".
    if _first_index(tokens, COMPARE_WORDS) is not None:
        intent = "compare_last"
    elif _first_index(tokens, HISTORY_WORDS) is not None:
        intent = "history"
    else:
        scan_pos = _first_index(tokens, SCAN_WORDS)
        explain_pos = _first_index(tokens, EXPLAIN_WORDS)
        if scan_pos is not None and (explain_pos is None or scan_pos < explain_pos):
            intent = "scan"          # "scan localhost and tell me the riskiest port"
        elif explain_pos is not None:
            intent = "explain"
        else:
            intent = "unknown"

    found = extract_target(text)
    # A bare target with no verb, like "localhost", is treated as a scan.
    if intent == "unknown" and found is not None:
        intent = "scan"

    return {"intent": intent, "target": found or DEFAULT_TARGET}
