"""Safe Nmap scanner. Only allowlisted targets can be scanned."""
import nmap

import config

# Always allowed. Extra IPs come from config.ALLOWED_TARGETS.
BUILTIN_TARGETS = {"127.0.0.1", "localhost"}

# Safe Nmap options only: service detection on the top 1000 ports.
# No scripts, no OS detection, no aggressive mode.
SAFE_ARGUMENTS = "-sV --top-ports 1000 -T4"

# Services that are encrypted even if Nmap does not report a tunnel.
ENCRYPTED_SERVICES = {
    "https", "ssh", "ftps", "imaps", "pop3s", "smtps", "ldaps",
    "ms-wbt-server", "https-alt", "sftp", "mysqlx",
}


class TargetNotAllowed(ValueError):
    """Raised when a scan target is not on the allowlist."""


def allowed_targets():
    """Return the full set of allowed targets."""
    extra = {str(t).strip().lower() for t in config.ALLOWED_TARGETS}
    return BUILTIN_TARGETS | extra


def validate_target(target):
    """Return the cleaned target, or raise TargetNotAllowed."""
    cleaned = str(target).strip().lower()
    if cleaned not in allowed_targets():
        raise TargetNotAllowed(
            f"Target '{target}' is not allowed. "
            "Only 127.0.0.1, localhost, and IPs in ALLOWED_TARGETS can be scanned."
        )
    return cleaned


def _is_encrypted(info):
    """Decide if a port is encrypted: Nmap tunnel flag or known service name."""
    if info.get("tunnel") == "ssl":
        return True
    return info.get("name", "").lower() in ENCRYPTED_SERVICES


def parse_results(scanner, host):
    """Turn python-nmap output into a clean list of open ports."""
    results = []
    if host not in scanner.all_hosts():
        return results
    for protocol in scanner[host].all_protocols():
        for port, info in scanner[host][protocol].items():
            if info.get("state") != "open":
                continue
            version = " ".join(
                part for part in (info.get("product", ""), info.get("version", ""))
                if part
            )
            results.append({
                "port": int(port),
                "protocol": protocol,
                "service": info.get("name", "unknown") or "unknown",
                "version": version,
                "encrypted": "yes" if _is_encrypted(info) else "no",
            })
    return sorted(results, key=lambda r: r["port"])


def scan(target):
    """Scan one allowlisted target and return a list of open ports."""
    host = validate_target(target)  # raises before any Nmap call
    scanner = nmap.PortScanner()
    scanner.scan(
        hosts=host,
        arguments=SAFE_ARGUMENTS,
        timeout=config.SCAN_TIMEOUT_SECONDS,
    )
    return parse_results(scanner, host if host != "localhost" else "127.0.0.1")
