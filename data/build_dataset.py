"""Build the labeled port-risk dataset from a documented rule table.

HONEST NOTE: These labels are NOT from real incident data. Each service has a
base severity score (0 to 10) set by hand from public CVSS knowledge and well
known weaknesses (for example BlueKeep for RDP, EternalBlue for SMB, cleartext
telnet). Rows are then generated with random variation and noise, and a label
is assigned from the final score. The model learns this rule table. It does
not learn real-world attacker behavior.

Scoring rule for each generated row:
  score = base score of the service
          - 1.0  if the connection is encrypted (and the service is not always encrypted)
          + 0.1 per step the software version is behind the latest (max +2.0)
          + 0.5  if the version is unknown (cannot be checked)
          + random noise (normal, sd 0.5) to mimic analyst disagreement

Labels follow CVSS v3 severity bands, with Critical merged into High:
  low:    score < 4.0
  medium: 4.0 to 6.9
  high:   7.0 and above

Run:  python data/build_dataset.py
"""
from pathlib import Path

import numpy as np
import pandas as pd

# service name (as Nmap reports it): (base score, chance the port is encrypted, why)
RULES = {
    "telnet":        (9.8, 0.00, "Cleartext remote shell, weak default logins, many critical CVEs"),
    "ftp":           (7.5, 0.10, "Cleartext logins, anonymous access, old daemon bugs"),
    "tftp":          (7.5, 0.00, "No authentication at all"),
    "microsoft-ds":  (9.0, 0.30, "SMB: EternalBlue class remote code execution (CVE-2017-0144)"),
    "netbios-ssn":   (7.5, 0.00, "NetBIOS session: information leaks and relay attacks"),
    "ms-wbt-server": (8.8, 0.90, "RDP: BlueKeep class remote code execution (CVE-2019-0708)"),
    "vnc":           (8.5, 0.10, "Remote desktop, weak or missing passwords"),
    "redis":         (8.5, 0.05, "Often open without a password, can lead to code execution"),
    "mongodb":       (8.0, 0.10, "Often exposed without authentication, data theft"),
    "x11":           (7.5, 0.00, "Remote screen and keyboard access if open"),
    "nfs":           (7.5, 0.00, "File shares exposed, weak host based access control"),
    "snmp":          (7.5, 0.00, "Default community strings leak system details"),
    "rpcbind":       (7.0, 0.00, "Service discovery used for amplification and recon"),
    "ms-sql-s":      (7.0, 0.30, "Database exposed, brute force and privilege escalation"),
    "msrpc":         (7.0, 0.20, "Windows RPC, long history of remote code execution bugs"),
    "mysql":         (6.5, 0.30, "Database exposed to the network, brute force risk"),
    "postgresql":    (6.0, 0.40, "Database exposed to the network, brute force risk"),
    "ldap":          (6.0, 0.20, "Directory data leaks and anonymous binds"),
    "http-proxy":    (5.5, 0.10, "Open proxy abuse"),
    "pop3":          (5.5, 0.20, "Cleartext mail logins"),
    "smtp":          (5.0, 0.30, "Mail relay abuse, user enumeration"),
    "imap":          (5.0, 0.30, "Cleartext mail logins"),
    "domain":        (5.3, 0.00, "DNS: amplification and zone transfer leaks"),
    "http":          (5.3, 0.00, "Unencrypted web traffic, web app flaws"),
    "http-alt":      (5.3, 0.00, "Unencrypted web traffic on an alternate port"),
    "ipp":           (4.5, 0.20, "Printing service (CUPS), moderate historical bugs"),
    "sip":           (5.0, 0.10, "VoIP signaling, toll fraud and enumeration"),
    "rtsp":          (5.0, 0.00, "Camera streams, often weak or no authentication"),
    "ssh":           (3.5, 1.00, "Encrypted, key based logins are common, low exposure"),
    "https":         (3.7, 1.00, "Encrypted web traffic, mostly app level issues"),
    "https-alt":     (3.7, 1.00, "Encrypted web traffic on an alternate port"),
    "other":         (5.0, 0.20, "Unknown service, treated as medium by default"),
}

# Common services appear more often than rare ones.
WEIGHTS = {"ssh": 6, "https": 6, "https-alt": 2, "http": 3, "mysql": 2, "ftp": 2, "microsoft-ds": 2,
           "smtp": 2, "domain": 2, "other": 2}

LABELS = ["low", "medium", "high"]


def score_to_label(score):
    """Map a score to a CVSS style band (Critical merged into high)."""
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    return "high"


def build_dataset(rows=3000, seed=42):
    """Create the labeled dataset as a DataFrame."""
    rng = np.random.default_rng(seed)
    services = list(RULES)
    probs = np.array([WEIGHTS.get(s, 1) for s in services], dtype=float)
    probs /= probs.sum()

    data = []
    for service in rng.choice(services, size=rows, p=probs):
        base, p_enc, _ = RULES[service]
        encrypted = int(rng.random() < p_enc)

        # Version variation: most versions are known, many are behind the latest.
        version_known = int(rng.random() < 0.85)
        if version_known and rng.random() < 0.6:
            version_lag = int(min(20, rng.exponential(6)) + 1)   # 1 to 20 steps behind
        else:
            version_lag = 0

        score = base
        if encrypted and p_enc < 1.0:
            score -= 1.0
        score += 0.1 * version_lag
        if not version_known:
            score += 0.5
        score += rng.normal(0, 0.5)                              # realistic noise
        score = float(np.clip(score, 0, 10))

        data.append({
            "service": service,
            "encrypted": encrypted,
            "version_known": version_known,
            "version_lag": version_lag,
            "score": round(score, 2),
            "risk": score_to_label(score),
        })
    return pd.DataFrame(data)


if __name__ == "__main__":
    out = Path(__file__).parent / "ports_dataset.csv"
    df = build_dataset()
    df.to_csv(out, index=False)
    print(f"Wrote {len(df)} rows to {out}")
    print(df["risk"].value_counts().to_string())
