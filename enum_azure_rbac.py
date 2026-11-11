#!/usr/bin/env python3
"""
enum_azure_rbac.py - mint an Azure Resource Manager (ARM) token and dump the
signed-in user's RBAC role assignments across subscriptions, INCLUDING ones
inherited through group membership.

Why: ARM authorization is RBAC, not granular OAuth scopes - the token only
carries `user_impersonation`, and what you can do is whatever roles the user
holds. roadrecon sees the directory but NOT Azure RBAC, so the nested-group ->
Azure RBAC path (a group you can join being a member of a group that holds an
Azure role) is invisible to it. This closes that blind spot: the ARM
`$filter=assignedTo('{oid}')` query returns assignments that apply to the user
directly OR via (transitive) group membership.

Read-only (ARM GET). Takes a FOCI refresh token (redeemed to the ARM audience -
note REDEEM_SCOPE below differs from the Graph helpers) or an ARM access token.
The auth FUNCTIONS are byte-identical to the other helpers (CI-enforced); only
the REDEEM_SCOPE constant differs, which is intentional and not CI-checked.

    python3 enum_azure_rbac.py --refresh-token "$RT"
    python3 enum_azure_rbac.py --token "$ARM_AT" --all --json
"""

import argparse
import base64
import json
import re
import sys
import urllib.parse

import requests

ARM = "https://management.azure.com"
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
REDEEM_SCOPE = "https://management.azure.com/.default offline_access"


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


# --- ARM RBAC enumeration ---

def jwt_claims(token):
    """Decode (do not verify) a JWT's payload claims."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def arm_get(session, url):
    r = session.get(url, timeout=30)
    if r.status_code == 401:
        sys.exit("[!] 401 - token is not an ARM token (audience must be https://management.azure.com/).\n"
                 "    Use --refresh-token (redeemed to ARM here) or pass an ARM access token.")
    if r.status_code == 403:
        return None  # no access at this scope; caller handles
    r.raise_for_status()
    return r.json()


def arm_pages(session, url):
    out = []
    while url:
        data = arm_get(session, url)
        if data is None:
            break
        out.extend(data.get("value", []))
        url = data.get("nextLink")
    return out


def main():
    ap = argparse.ArgumentParser(description="Dump the user's Azure RBAC role assignments (incl. via groups) across subscriptions.")
    ap.add_argument("--token", help="ARM access token string, or '-' for stdin.")
    ap.add_argument("--token-file", help="File with the ARM access token (or a tokens.jsonl line).")
    ap.add_argument("--refresh-token", help="Refresh token to redeem to ARM (FOCI), or '-' for stdin. Overrides --token.")
    ap.add_argument("--refresh-token-file", help="File with a refresh token (or a tokens.jsonl line).")
    ap.add_argument("--client-id", default=DEFAULT_FOCI_CLIENT, help="FOCI public client to try FIRST (default: Azure CLI).")
    ap.add_argument("--tenant", default="organizations", help="Tenant for redemption (default: organizations).")
    ap.add_argument("--no-fallback", action="store_true", help="Only try --client-id, no FOCI fallback.")
    ap.add_argument("--all", action="store_true", help="List ALL role assignments in each subscription, not just the user's.")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a report.")
    args = ap.parse_args()

    token = read_token(args)
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})

    claims = jwt_claims(token)
    oid = claims.get("oid")
    who = claims.get("upn") or claims.get("unique_name") or claims.get("appid") or oid or "?"
    if claims.get("aud") and "management" not in str(claims.get("aud")):
        print(f"[!] warning: token audience is {claims.get('aud')!r}, not ARM; calls will likely 401.", file=sys.stderr)
    print(f"[*] identity: {who}  (oid {oid})", file=sys.stderr)

    subs = arm_pages(session, f"{ARM}/subscriptions?api-version=2022-12-01")
    if not subs:
        print("[!] no subscriptions visible to this token (or no ARM access).")
        if args.json:
            json.dump({"identity": who, "oid": oid, "subscriptions": []}, sys.stdout, indent=2)
        return

    roledef_cache = {}

    def role_name(rdid):
        if rdid not in roledef_cache:
            d = arm_get(session, f"{ARM}{rdid}?api-version=2022-04-01")
            roledef_cache[rdid] = (d or {}).get("properties", {}).get("roleName", rdid.rsplit("/", 1)[-1])
        return roledef_cache[rdid]

    out = {"identity": who, "oid": oid, "subscriptions": []}
    for s in subs:
        sub_id = s.get("subscriptionId")
        sub_name = s.get("displayName")
        base = f"{ARM}/subscriptions/{sub_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        if args.all:
            url = base
        elif oid:
            url = base + "&$filter=" + urllib.parse.quote(f"assignedTo('{oid}')", safe="")
        else:
            url = base + "&$filter=" + urllib.parse.quote("atScope()", safe="")
        ras = arm_pages(session, url)
        rows = []
        for ra in ras:
            p = ra.get("properties", {})
            rows.append({
                "role": role_name(p.get("roleDefinitionId", "")),
                "scope": p.get("scope"),
                "principalId": p.get("principalId"),
                "principalType": p.get("principalType"),
            })
        out["subscriptions"].append({"id": sub_id, "name": sub_name, "assignments": rows})

    if args.json:
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    scope = "ALL assignments" if args.all else f"assignments effective for {who} (direct + via groups)"
    print(f"\n[*] {len(subs)} subscription(s); {scope}:\n")
    for sub in out["subscriptions"]:
        print(f"=== {sub['name']}  ({sub['id']}) ===")
        if not sub["assignments"]:
            print("    (none)")
        for a in sub["assignments"]:
            via = "" if a["principalId"] == oid else f"   (via {a['principalType']} {a['principalId']})"
            print(f"    {a['role']:28} @ {a['scope']}{via}")
        print()
    if not args.all:
        print("  Rows where principalId != your oid are inherited via a group you belong to")
        print("  (or could be reached by joining a non-role-assignable group nested into it).")


if __name__ == "__main__":
    main()
