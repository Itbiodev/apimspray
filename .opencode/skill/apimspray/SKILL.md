---
name: apimspray
description: >-
  Operate apimspray.py — the Entra ID auth-assessment CLI that routes ROPC
  password spraying, 1:1 credential validation, user enumeration, and client-app
  iteration through rotating Azure APIM gateways. Use whenever the task involves
  running apimspray.py, spraying or validating Entra ID (Azure AD / Microsoft
  365) credentials, enumerating which UPNs exist, or interpreting an apimspray
  results/ directory. Covers mode selection, lockout-safe pacing, and reading
  results.jsonl / tokens.jsonl.
---

# apimspray

`apimspray.py` tests Entra ID (Azure AD / M365) authentication through a pool of
Azure APIM gateways used as rotating egress IPs. This skill teaches how to drive
it safely and read its output. It does **not** cover deploying or tearing down
the gateways — you are given a URLs file and target lists as inputs.

## Authorization gate (do this first)

This is offensive security tooling. Before running anything that sends
credentials (`spray` / `validate` / `validate-clients`), confirm the user has an
authorized engagement and the target tenant/domain is in scope. If scope is
unclear, ask — do not spray. User enumeration (`validate-users`) is
unauthenticated but is still recon against a real tenant; treat it the same way.

## Inputs you need

- **`--urls <file>`**: APIM gateway URLs, one per line — a required prerequisite
  you are handed. Enumeration (`validate-users`) needs gateways that expose the
  `GetCredentialType` operation, which are a **separate** list from the spray
  gateways (commonly `urls_enum.txt` vs `urls.txt`). Using a spray-gateway list
  for `validate-users` will 404.
- **`--users <file>`**: UPNs, one per line (`user@domain.com`). Use `--domain
  corp.com` to append a domain to bare usernames.
- **`--passwords <file>`**: passwords, one per line (spray), or a 1:1 list
  aligned to `--users` (validate / validate-clients, equal length).

Invoke as `apimspray ...` if installed, else `python3 apimspray.py ...` from the
repo directory. Output goes to `./results` relative to the **current working
directory** — `cd` to where you want results, or pass `--output <dir>`.

## Modes — pick the right one

| Mode | What it does | Lockout risk | Requires |
|------|--------------|--------------|----------|
| `validate-users` | Enumerate which UPNs exist via GetCredentialType. No password sent. | **None** | enum-gateway `--urls`, `--users` |
| `spray` | Each password against all users (1:N), chunked with lockout waits. | Yes — managed by pace | `--users`, `--passwords` |
| `validate` | 1:1 `user:password` pair testing (equal-length lists). | Yes | `--users`, `--passwords` (equal len) |
| `validate-clients` | 1:1 pairs, each tried against every client ID. Finds an app not blocked by Conditional Access. | Yes | `--users`, `--passwords`, `--client-ids` |

`--mode` is **required**.

## Recommended workflow

1. **Enumerate first** (`validate-users`) against the enum gateways to learn
   which UPNs exist. Zero lockout cost; prune the user list — spraying
   nonexistent accounts wastes attempts and muddies results. Feed the existing
   UPNs into the next step.
2. **Spray or validate** the pruned users at a conservative pace (start `low` or
   `stealth`). Use `--safe-threshold` as a circuit breaker.
3. **Review** `results.jsonl` / `valid.txt` / `tokens.jsonl` (see below).
4. If a valid-looking cred is **Conditional-Access blocked** (`AADSTS53003`),
   retry it with `validate-clients` across several client IDs — a different app
   may return a token.

## Pacing & lockout safety (the important part)

`--pace` sets workers, per-request delay, passwords-per-chunk, the lockout-reset
wait between chunks, jitter, and a default safe threshold:

| Profile | Workers | Delay | Pass/chunk | Lockout wait | Safe threshold | Jitter |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| `high` | 15 | 0.1s | 10 | 5m | 20 | 0% |
| `medium` (`mid`) | 5 | 1.0s | 5 | 10m | 10 | 10% |
| `low` (default) | 2 | 5.0s | 2 | 15m | 5 | 20% |
| `stealth` | 1 | 30s | 1 | 20m | 1 | 40% |
| `stealth-multi` | 5 | 30s | 1 | 20m | 1 | 40% |

- **Default to `low` or `stealth`** on production tenants. `high` is loud and
  locks accounts fast.
- **`--safe-threshold N`** aborts the run once N accounts hit Smart Lockout
  (`AADSTS50053`). Set it low to fail safe.
- **`--auto-throttle`** slows the global delay automatically when lockouts appear.
- **`--continue-on-success`** keeps going after the first valid cred (default is
  to stop).
- **`--user-batch-size` / `--user-batch-delay`** (spray only) pause between user
  batches; `--user-batch-delay` accepts a range like `2-5` minutes (min ≤ max).

## Client-app selection

Each attempt randomly picks one of four built-in first-party client apps.
- `--client-id <GUID>` pins one app (known GUID reuses its resource/scope;
  unknown defaults to Graph). `--resource` / `--scope` override.
- `validate-clients` uses `--client-ids <csv-or-file>` to iterate every client
  per credential pair — the tool that surfaces a Conditional-Access bypass.

## Reading results

Each run writes `results/<date>_<time>_<mode>/` (plus a `latest` symlink):
- **`results.jsonl`** — source of truth, one JSON object per attempt: `ts, mode,
  username, password, classification, aadsts, client_id, resource, gateway,
  http_status, has_token`.
- **`valid.txt`** — quick-glance hits (`user:pass | classification`, or existing
  UPNs for `validate-users`).
- **`tokens.jsonl`** — OAuth tokens obtained (`access_token`, `refresh_token`,
  `id_token`, metadata). **This is loot** — handle carefully, clean up after.
- **`manifest.json`** — run metadata (args, counts, start/finish).

```bash
# all valid credentials
jq -r 'select(.classification|startswith("VALID")) | "\(.username):\(.password)"' results.jsonl
# everything that happened to one user
jq 'select(.username=="bob@corp.com")' results.jsonl
# CA-blocked hits worth retrying with validate-clients
jq -r 'select(.aadsts=="AADSTS53003") | .username' results.jsonl
```

### Classification meanings
- `VALID (Token)` — password correct, token captured (check `tokens.jsonl`).
- `VALID (MFA Required)` / `VALID (Conditional Access)` — password correct, MFA/CA
  gate. Still a valid credential.
- `VALID (Conditional Access Blocked)` (`AADSTS53003`) — correct password, CA
  blocked this app → candidate for `validate-clients`.
- `LOCKED (Smart Lockout)` (`AADSTS50053`) — back off; watch the safe threshold.
- `BLOCKED (Account Disabled)` — valid-but-disabled account.
- `FAILED (Invalid Creds / User Not Found)` — wrong password or nonexistent user.
- `UNKNOWN (...)` / `ERROR (Request Failed)` — non-standard response, HTTP error,
  or network failure. **The summary's Failed count does NOT include these** — if
  a run looks empty, grep `results.jsonl` for `UNKNOWN`/`ERROR` to see whether the
  gateways or routing were actually broken.

## Known gotchas (avoid these footguns)

- **Do not use `--shuffle-users` with `validate` or `validate-clients`.** It
  reorders users but not passwords, silently misaligning the 1:1 pairing so every
  credential is tested against the wrong password. `--shuffle-users` is only safe
  in `spray` mode.
- **Leave `--tenant` at its default (`common`)** unless you know the gateways
  route a specific tenant path. A non-`common` tenant produces
  `/{tenant}/oauth2/token`, which the gateways 404 — surfaced as `UNKNOWN (HTTP
  404)`, which the summary does not count, so the run looks clean while finding
  nothing.
- **`--resume <run-dir>`** skips users already in that run's `results.jsonl`;
  intended for `spray`. In `validate`/`validate-clients` it can shorten the user
  list and trip the equal-length check.
- Results go to the CWD's `./results`; the tool is callable from anywhere, so be
  deliberate about where you run it.
