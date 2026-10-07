"""Settings for VoiceSOC."""

# Extra IPs you own and are allowed to scan (127.0.0.1 and localhost are always allowed).
ALLOWED_TARGETS = []

# Flask settings
HOST = "127.0.0.1"
PORT = 5000
DEBUG = True

# Scanner settings
SCAN_TIMEOUT_SECONDS = 120   # hard limit for one scan
