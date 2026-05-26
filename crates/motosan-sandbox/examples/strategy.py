"""Untrusted 'strategy' run inside the motosan sandbox. Stdlib only.

Prints PASS/FAIL for each enforced control and exits non-zero if any
DETERMINISTIC control failed open (a leak). Check 7 (reach the allowlisted
host) is best-effort and never affects the exit code.
"""
import json
import os
import socket
import sys
import urllib.request

results = []  # (ok: bool, name: str)


def check(name, action, expect_block):
    """expect_block=True → the action SHOULD be denied (PASS if it raises)."""
    try:
        action()
        ok = not expect_block
        detail = "succeeded"
    except Exception as exc:  # noqa: BLE001 - any denial counts
        ok = expect_block
        detail = type(exc).__name__
    results.append((ok, name))
    print(f"{'PASS' if ok else 'FAIL'} {name} ({detail})", flush=True)


# 1. workspace write — allowed
check("workspace-write",
      lambda: open("result.json", "w").write(json.dumps({"ok": 1})),
      expect_block=False)

# 2. write outside the workspace — denied
check("write-confinement",
      lambda: open("/tmp/motosan_escape", "w").write("x"),
      expect_block=True)

# 3. read a normal input file — allowed
check("read-input", lambda: open("input.csv").read(), expect_block=False)

# 4. read the secret — denied by deny_read
check("secret-deny-read", lambda: open(".env").read(), expect_block=True)

# 5. reach a NON-allowlisted host THROUGH the proxy — denied (proxy refuses
#    CONNECT locally; deterministic, no internet needed).
check("net-allowlist-deny",
      lambda: urllib.request.urlopen("https://example.com", timeout=3),
      expect_block=True)

# 6. raw socket to a non-loopback address (bypasses the proxy) — the egress
#    wall blocks it (Seatbelt kernel deny / netns ENETUNREACH). 203.0.113.0/24
#    is TEST-NET-3 (RFC 5737), never routable.
check("direct-egress-wall",
      lambda: socket.create_connection(("203.0.113.1", 80), 2).close(),
      expect_block=True)

# 7. reach the ALLOWLISTED host — best-effort (needs internet), never fatal.
try:
    urllib.request.urlopen("https://api.binance.com/api/v3/ping", timeout=3)
    print("INFO net-allow reached api.binance.com (online)", flush=True)
except Exception as exc:  # noqa: BLE001
    print(f"INFO net-allow best-effort: {type(exc).__name__} "
          "(offline or proxy-gated)", flush=True)

leaked = [name for ok, name in results if not ok]
print(f"--- {len(results) - len(leaked)}/{len(results)} controls held ---",
      flush=True)
sys.exit(1 if leaked else 0)
