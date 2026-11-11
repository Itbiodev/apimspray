#!/usr/bin/env python3
"""
enum_cert_profiles.py - enumerate Intune SCEP/PKCS certificate profiles via
Microsoft Graph and flag the ones abusable as a cloud -> on-prem AD CS path.

Closes the verification gap roadrecon can't see (see roadrecon_privesc.py's
CERT SURFACE section and dirkjanm.io/extending-ad-cs-attack-surface-intune-certs,
2025-07-30): roadrecon shows the NDES connector SP and the groups scoped to it,
but NOT the profile config that decides exploitability - spoofable subject/SAN,
EnrolleeSuppliesSubject-equivalent, and a client-authentication EKU.

Read-only (Graph GET). Needs a token with DeviceManagementConfiguration.Read.All
(an Intune-admin-capable token); a plain low-priv ROPC token will 403.

Accepts a Graph access token or a FOCI refresh token (same auth as the other
helpers). The auth block is byte-identical across helpers; CI enforces that.

    python3 enum_cert_profiles.py --refresh-token "$RT"
    python3 enum_cert_profiles.py --token "$AT" --json
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


# --- cert-profile enumeration ---

SCEP_TYPES = ("scepcertificateprofile", "scepcertificate")
PKCS_TYPES = ("pkcscertificateprofile", "pkcscertificate")
CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"
# Subject-alternative-name types that can carry an identity usable for PKINIT
# (UPN) or DC impersonation (DNS), and custom attributes an attacker may steer.
RISKY_SAN = ("userprincipalname", "domainnamesystem", "domainnameservice",
             "customazureadattribute", "custom")


def graph_pages(session, url):
    out = []
    while url:
        r = session.get(url, timeout=30)
        if r.status_code == 401:
            sys.exit("[!] 401 Unauthorized - token expired, wrong audience, or revoked.")
        if r.status_code == 403:
            sys.exit("[!] 403 Forbidden - token lacks DeviceManagementConfiguration.Read.All.\n"
                     "    This needs an Intune-admin-capable token; a low-priv ROPC token won't have it.")
        r.raise_for_status()
        data = r.json()
        out.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return out


def classify(p):
    otype = (p.get("@odata.type") or "").lower()
    kind = "SCEP" if any(t in otype for t in SCEP_TYPES) else ("PKCS" if any(t in otype for t in PKCS_TYPES) else None)
    if not kind:
        return None

    ekus = p.get("extendedKeyUsages") or []
    eku_oids = [e.get("objectIdentifier") for e in ekus]
    has_client_auth = CLIENT_AUTH_EKU in eku_oids

    san_type = (p.get("subjectAlternativeNameType") or "").lower()
    custom_sans = p.get("customSubjectAlternativeNames") or []
    san_risky = any(r in san_type for r in RISKY_SAN) or bool(custom_sans)

    subject_fmt = p.get("subjectNameFormat") or p.get("subjectNameFormatString") or ""
    subj_custom = "custom" in subject_fmt.lower() or "{{" in (p.get("subjectNameFormatString") or "")

    # SCEP is the sharper edge: the device builds the CSR and can carry an
    # arbitrary security extension if SANs match policy (dirkjanm). PKCS is
    # server-built, so it can't inject a SID, but a client-auth cert still matters.
    abusable = kind == "SCEP" and has_client_auth and (san_risky or subj_custom)

    return {
        "name": p.get("displayName"),
        "id": p.get("id"),
        "kind": kind,
        "odata_type": p.get("@odata.type"),
        "scep_urls": p.get("scepServerUrls") or [],
        "subject_name_format": subject_fmt,
        "san_type": p.get("subjectAlternativeNameType"),
        "custom_sans": custom_sans,
        "ekus": eku_oids,
        "client_auth_eku": has_client_auth,
        "san_risky": san_risky,
        "subject_custom": subj_custom,
        "abusable": abusable,
    }


def main():
    ap = argparse.ArgumentParser(description="Enumerate Intune SCEP/PKCS certificate profiles and flag abusable ones.")
    ap.add_argument("--token", help="Graph access token string, or '-' for stdin.")
    ap.add_argument("--token-file", help="File with the access token (or a tokens.jsonl line).")
    ap.add_argument("--refresh-token", help="Refresh token to redeem (FOCI), or '-' for stdin. Overrides --token.")
    ap.add_argument("--refresh-token-file", help="File with a refresh token (or a tokens.jsonl line).")
    ap.add_argument("--client-id", default=DEFAULT_FOCI_CLIENT, help="FOCI public client to try FIRST (default: Azure CLI).")
    ap.add_argument("--tenant", default="organizations", help="Tenant for redemption (default: organizations).")
    ap.add_argument("--no-fallback", action="store_true", help="Only try --client-id, no FOCI fallback.")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a report.")
    args = ap.parse_args()

    token = read_token(args)
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})

    raw = graph_pages(session, f"{GRAPH}/deviceManagement/deviceConfigurations?$top=100")
    profiles = [c for c in (classify(p) for p in raw) if c]

    if args.json:
        json.dump(profiles, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    print(f"[*] {len(raw)} device configurations; {len(profiles)} certificate profile(s).\n")
    if not profiles:
        print("    (no SCEP/PKCS certificate profiles found)")
        return
    for c in sorted(profiles, key=lambda x: (not x["abusable"], x["kind"], x["name"] or "")):
        flag = "  <<< ABUSABLE (SCEP + client-auth EKU + spoofable subject/SAN)" if c["abusable"] else ""
        print(f"[{c['kind']}] {c['name']}  ({c['id']}){flag}")
        if c["scep_urls"]:
            print(f"      NDES/SCEP URL(s): {', '.join(c['scep_urls'])}")
        print(f"      subject format : {c['subject_name_format'] or '(default)'}"
              + ("  [spoofable]" if c["subject_custom"] else ""))
        print(f"      SAN type       : {c['san_type'] or '(none)'}"
              + (f" + custom {c['custom_sans']}" if c["custom_sans"] else "")
              + ("  [risky]" if c["san_risky"] else ""))
        print(f"      client-auth EKU: {'YES' if c['client_auth_eku'] else 'no'}  (EKUs: {', '.join(c['ekus']) or 'none'})")
    print("\n  Next (dirkjanm): for an ABUSABLE SCEP profile, enroll an in-scope device and")
    print("  scepreq against the NDES URL with a spoofed subject/SAN -> client-auth cert -> TGT.")
    print("  Verify CA strong-mapping (KB5014754) enforcement before relying on it.")


if __name__ == "__main__":
    main()
