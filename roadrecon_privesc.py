#!/usr/bin/env python3
"""
roadrecon_privesc.py - Privilege-escalation triage over a roadrecon database.

Reads a roadrecon SQLite dump (default: roadrecon.db) and surfaces the two
ingredients of an app-based escalation path in an Entra ID tenant:

  1. Tenant-wide delegated grants (consentType == 'AllPrincipals') that carry
     high-value Microsoft Graph / AAD Graph scopes. These apply to *every*
     user, so any credential you validate inherits them. Clients that are
     public (allow public-client flows) are reachable by ROPC password grant
     - i.e. directly abusable with apimspray's --client-id.

  2. Service principals holding high-value *application* permissions
     (app roles). These are the pivot targets: an Application.ReadWrite.All
     foothold can mint credentials onto one of these SPs and inherit its role.

It then correlates the two into concrete chains (ROPC-capable client with
Application.ReadWrite.All  ->  privileged SP to pivot onto).

Read-only. Does not authenticate or touch the network.

Usage:
    python3 roadrecon_privesc.py [roadrecon.db] [--json] [--all-scopes]
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

# Delegated scopes (OAuth2PermissionGrants.scope) that enable escalation or
# broad tenant impact when pre-consented for all users.
HIGH_VALUE_SCOPES = {
    "RoleManagement.ReadWrite.Directory": "assign directory roles (-> Global Admin)",
    "Application.ReadWrite.All": "add creds to any app/SP -> pivot to its perms",
    "Application.ReadWrite.OwnedBy": "add creds to owned apps/SPs",
    "AppRoleAssignment.ReadWrite.All": "grant app roles (-> consent-grant abuse)",
    "Directory.ReadWrite.All": "broad directory write",
    "Directory.AccessAsUser.All": "act as the user across the directory (AAD Graph)",
    "Group.ReadWrite.All": "add self to privileged/role-assignable groups",
    "GroupMember.ReadWrite.All": "add self to privileged groups",
    "User.ReadWrite.All": "reset non-admin passwords / modify users",
    "PrivilegedAccess.ReadWrite.AzureAD": "manage PIM role assignments",
    "PrivilegedAccess.ReadWrite.AzureADGroup": "manage PIM group assignments",
    "Policy.ReadWrite.ConditionalAccess": "weaken/disable CA policies",
    "RoleManagement.ReadWrite.Exchange": "Exchange role management",
    "DelegatedPermissionGrant.ReadWrite.All": "grant delegated permissions",
    "EntitlementManagement.ReadWrite.All": "access-package / entitlement abuse",
    "RoleEligibilitySchedule.ReadWrite.Directory": "PIM eligibility write",
    "RoleAssignmentSchedule.ReadWrite.Directory": "PIM assignment write",
}

# Application permissions (app roles) that make an SP worth pivoting onto.
HIGH_VALUE_APP_ROLES = {
    "RoleManagement.ReadWrite.Directory": "assign directory roles (-> Global Admin)",
    "Application.ReadWrite.All": "add creds to any app/SP",
    "AppRoleAssignment.ReadWrite.All": "grant any app role to any principal",
    "Directory.ReadWrite.All": "broad directory write",
    "Group.ReadWrite.All": "write any group",
    "GroupMember.ReadWrite.All": "write any group membership",
    "User.ReadWrite.All": "write any user / reset passwords",
    "PrivilegedAccess.ReadWrite.AzureAD": "manage PIM role assignments",
    "Policy.ReadWrite.ConditionalAccess": "weaken/disable CA policies",
    "RoleManagement.ReadWrite.Exchange": "Exchange role management",
}

# Well-known Microsoft first-party *public* clients that accept ROPC. The SP's
# microsoftFirstParty flag is often null in a dump, so these would otherwise be
# mis-reported as "unknown" even though they are prime ROPC targets.
KNOWN_PUBLIC_CLIENTS = {
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
    "1b730954-1685-4b74-9bfd-dac224a7b894": "Azure Active Directory PowerShell",
    "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Microsoft Graph PowerShell",
    "d1ddf0e4-d672-4dae-b554-9d5bdfd93547": "Microsoft Intune PowerShell",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
    "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
    "29d9ed98-a469-4536-ade2-f981bc1d605e": "Microsoft Authentication Broker",
    "0ec893e0-5785-4de6-99da-4ed124e5296c": "Office UWP PWA",
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1": "Visual Studio",
    "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive SyncEngine",
}

# Delegated scopes that let a signed-in user add themselves to a group.
GROUP_WRITE_SCOPES = {"Group.ReadWrite.All", "GroupMember.ReadWrite.All", "Directory.ReadWrite.All"}


def _ropc_reachable(ropc_str):
    """True when the ROPC verdict means password-grant is worth attempting."""
    return ropc_str.startswith("YES") or ropc_str.startswith("likely")


def _match(scope_token, catalog):
    """Case-insensitive membership against a scope/role catalog."""
    for key, why in catalog.items():
        if scope_token.lower() == key.lower():
            return key, why
    return None, None


def load(db_path):
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def build_sp_index(con):
    sps = {}
    for r in con.execute(
        "SELECT objectId, displayName, appId, microsoftFirstParty, accountEnabled, "
        "appRoleAssignmentRequired, appRoles, servicePrincipalType FROM ServicePrincipals"
    ):
        sps[r["objectId"]] = dict(r)
    # appRole GUID -> value, harvested from every resource SP that publishes roles.
    role_id_to_value = {}
    for r in sps.values():
        try:
            for ar in json.loads(r["appRoles"] or "[]"):
                if ar.get("id"):
                    role_id_to_value[ar["id"]] = ar.get("value") or ar.get("displayName") or ar["id"]
        except (ValueError, TypeError):
            pass
    return sps, role_id_to_value


def app_public_client_map(con):
    """appId -> True/False/None (None = no local app registration)."""
    out = {}
    for r in con.execute("SELECT appId, publicClient FROM Applications"):
        out[r["appId"]] = bool(r["publicClient"])
    return out


def find_tenantwide_grants(con, sps, pub_map, all_scopes=False):
    results = []
    for g in con.execute(
        "SELECT clientId, resourceId, consentType, scope FROM OAuth2PermissionGrants "
        "WHERE consentType = 'AllPrincipals'"
    ):
        tokens = (g["scope"] or "").split()
        hits = []
        for t in tokens:
            key, why = _match(t, HIGH_VALUE_SCOPES)
            if key:
                hits.append((key, why))
        if not hits and not all_scopes:
            continue
        client = sps.get(g["clientId"], {})
        resource = sps.get(g["resourceId"], {})
        appid = client.get("appId")
        # ROPC reachability: known MS public client wins; else local app-reg
        # publicClient flag; else infer from the first-party marker.
        pub = pub_map.get(appid)
        if appid in KNOWN_PUBLIC_CLIENTS:
            ropc = "YES (known public client)"
        elif pub is None:
            ropc = "likely (MS first-party)" if client.get("microsoftFirstParty") else "unknown"
        else:
            ropc = "YES (public client)" if pub else "no (confidential - needs secret)"
        results.append({
            "client": client.get("displayName", "?"),
            "client_appId": appid,
            "client_origin": "MS" if client.get("microsoftFirstParty") else "TENANT",
            "client_enabled": bool(client.get("accountEnabled")),
            "assignment_required": bool(client.get("appRoleAssignmentRequired")),
            "resource": resource.get("displayName", "?"),
            "ropc": ropc,
            "high_value_scopes": [h[0] for h in hits],
            "notes": [h[1] for h in hits],
            "all_scopes": g["scope"] if all_scopes else None,
        })
    return results


def find_privileged_sps(con, sps, role_id_to_value):
    seen = {}
    for a in con.execute(
        "SELECT principalId, principalDisplayName, resourceId, id FROM AppRoleAssignments"
    ):
        role = role_id_to_value.get(a["id"], a["id"])
        key, why = _match(role, HIGH_VALUE_APP_ROLES)
        if not key:
            continue
        prin = sps.get(a["principalId"], {})
        resource = sps.get(a["resourceId"], {})
        entry = seen.setdefault(a["principalId"], {
            "sp": a["principalDisplayName"],
            "appId": prin.get("appId"),
            "enabled": bool(prin.get("accountEnabled")),
            "roles": [],
        })
        entry["roles"].append({"role": key, "on": resource.get("displayName", "?"), "why": why})
    return list(seen.values())


ROLE_MGMT_SCOPE = "RoleManagement.ReadWrite.Directory"


def load_group_roles(con, sps, role_id_to_value):
    """Resolve, per group, the roles it confers. Returns {objectId: {...}} for
    groups that grant at least one role, each with:
      name, roleAssignable (bool), roles -> [{kind, role, scope}]
    kind is directory-active | directory-eligible | directory-legacy | app.

    A group's membership is modifiable with Group.ReadWrite.All ONLY when it is
    NOT role-assignable; role-assignable groups require RoleManagement.ReadWrite.
    """
    groups = {r["objectId"]: dict(r) for r in con.execute(
        "SELECT objectId, displayName, isAssignableToRole, groupTypes, membershipRule FROM Groups")}

    # roleDefinitionId may reference RoleDefinitions.objectId or .templateId.
    roledef = {}
    for r in con.execute("SELECT objectId, templateId, displayName FROM RoleDefinitions"):
        roledef[r["objectId"]] = r["displayName"]
        if r["templateId"]:
            roledef[r["templateId"]] = r["displayName"]

    out = {}

    def add(gid, kind, role, scope):
        if gid not in groups:
            return
        g = groups[gid]
        dynamic = "DynamicMembership" in (g["groupTypes"] or "")
        entry = out.setdefault(gid, {
            "name": g["displayName"],
            "roleAssignable": bool(g["isAssignableToRole"]),
            "dynamic": dynamic,
            "rule": g["membershipRule"] if dynamic else None,
            "roles": [],
        })
        entry["roles"].append({"kind": kind, "role": role, "scope": scope})

    for tbl, kind in (("RoleAssignments", "directory-active"),
                      ("EligibleRoleAssignments", "directory-eligible")):
        try:
            for r in con.execute(f'SELECT principalId, roleDefinitionId, resourceScopes FROM "{tbl}"'):
                if r["principalId"] in groups:
                    add(r["principalId"], kind, roledef.get(r["roleDefinitionId"], r["roleDefinitionId"]), r["resourceScopes"])
        except sqlite3.OperationalError:
            pass

    # Legacy activated directory roles (DirectoryRole <-> Group link table).
    try:
        dirrole = {r["objectId"]: r["displayName"] for r in con.execute("SELECT objectId, displayName FROM DirectoryRoles")}
        for r in con.execute("SELECT DirectoryRole, [Group] AS grp FROM lnk_role_member_group"):
            add(r["grp"], "directory-legacy", dirrole.get(r["DirectoryRole"], r["DirectoryRole"]), "/")
    except sqlite3.OperationalError:
        pass

    # App roles assigned to a group.
    for a in con.execute("SELECT principalId, id, resourceDisplayName FROM AppRoleAssignments WHERE principalType='Group'"):
        add(a["principalId"], "app", f"{role_id_to_value.get(a['id'], a['id'])} on {a['resourceDisplayName']}", None)

    # Group owners: with DELEGATED Group.ReadWrite.All, a non-admin can only
    # modify a group they OWN (or with a Groups Administrator / Directory Writers
    # / User Administrator role). So ownership is the enabling condition for the
    # group-write chain - annotate it.
    users = {}
    try:
        for r in con.execute("SELECT objectId, userPrincipalName, displayName FROM Users"):
            users[r["objectId"]] = r["userPrincipalName"] or r["displayName"] or r["objectId"]
    except sqlite3.OperationalError:
        pass
    owners = {}
    try:
        for r in con.execute('SELECT "Group" AS g, "User" AS u FROM lnk_group_owner_user'):
            owners.setdefault(r["g"], []).append(users.get(r["u"], r["u"]))
    except sqlite3.OperationalError:
        pass
    try:
        for r in con.execute('SELECT "Group" AS g, ServicePrincipal AS sp FROM lnk_group_owner_serviceprincipal'):
            owners.setdefault(r["g"], []).append((sps.get(r["sp"], {}).get("displayName") or r["sp"]) + " [SP]")
    except sqlite3.OperationalError:
        pass
    for gid, entry in out.items():
        entry["owners"] = owners.get(gid, [])

    return out


def _role_tier(roles):
    """0 = admin/role (high), 1 = app access (medium), 2 = plain SSO (low)."""
    best = 2
    for r in roles:
        if r["kind"].startswith("directory"):
            return 0
        v = r["role"].lower()
        if any(k in v for k in (".readwrite", "readwrite", ".write", "admin", "manage", "owner")):
            best = min(best, 0)
        elif "msiam_access" in v:
            best = min(best, 2)
        else:
            best = min(best, 1)
    return best


def _fmt_group_targets(group_roles, want_assignable):
    """One row per matching group: {name, roles, tier, dynamic}. Sorted by tier
    (high first) then name; static/dynamic split is left to the printer."""
    rows = []
    for g in group_roles.values():
        if bool(g["roleAssignable"]) != want_assignable:
            continue
        labels = []
        for r in g["roles"]:
            scope = f" @{r['scope']}" if r["scope"] and r["scope"] != '["/"]' else ""
            labels.append(f"{r['role']}{scope}")
        row = {
            "name": g["name"],
            "roles": "; ".join(labels),
            "tier": _role_tier(g["roles"]),
            "dynamic": g["dynamic"],
            "rule": ((g["rule"] or "").strip()[:70]) if g["dynamic"] else None,
            "owners": g.get("owners", []),
        }
        rows.append(row)
    return sorted(rows, key=lambda x: (x["tier"], x["name"].lower()))


# Markers of an on-prem certificate bridge (Intune SCEP/PKCS -> NDES -> AD CS).
# See dirkjanm.io extending-ad-cs-attack-surface-intune-certs (2025-07-30):
# group membership scopes the SCEP profile, so a Group.ReadWrite.All add can put
# you in cert-issuance scope.
#   - Acronyms are matched CASE-SENSITIVELY so "NDES" hits "IntuneSCEPNDES" but
#     not "Zendesk"; "PKCS" hits a PKCS connector but not a word containing it.
#   - Phrases are cert-specific and matched case-insensitively.
CERT_ACRONYMS = ("SCEP", "NDES", "PKCS")
CERT_PHRASES = ("certificate connector", "certificate registration", "ndes connector")


def _is_cert_marker(name):
    if not name:
        return False
    if any(a in name for a in CERT_ACRONYMS):   # case-sensitive acronym
        return True
    low = name.lower()
    return any(p in low for p in CERT_PHRASES)


def find_cert_surface(con, sps, group_roles):
    """Flag SP connectors that bridge Intune cert profiles to on-prem AD CS, and
    the groups whose membership scopes them."""
    connectors = [s.get("displayName") for s in sps.values() if _is_cert_marker(s.get("displayName"))]
    if not connectors:
        return None
    scoping_groups = []
    for g in group_roles.values():
        for r in g["roles"]:
            if r["kind"] == "app" and _is_cert_marker(r["role"]):
                scoping_groups.append({
                    "group": g["name"], "via": r["role"],
                    "reach": "DYNAMIC (rule-gated)" if g["dynamic"] else "static (addable)",
                })
                break
    return {"connectors": sorted(set(connectors)), "scoping_groups": scoping_groups}


def build_chains(grants, priv_sps, group_roles):
    """Escalation shapes (reachability-correct):
      app_write   - ROPC client w/ delegated Application.ReadWrite.All -> write a
                    credential onto any privileged SP (direct).
      role_write  - ROPC client w/ delegated RoleManagement.ReadWrite.Directory ->
                    assign any directory role directly, and modify role-assignable
                    groups (the only scope that can).
      group_write - ROPC client w/ Group/GroupMember/Directory write -> add self to
                    a NON-role-assignable group that confers a role. (Role-assignable
                    groups are out of reach for this scope by Entra design.)
      secret_then_appwrite - an SP that holds app-only Application.ReadWrite.All
                    becomes a pivot once its secret/cert is obtained.
    """
    pivots = [s for s in priv_sps if s["enabled"]]
    assignable_targets = _fmt_group_targets(group_roles, want_assignable=True)
    plain_targets = _fmt_group_targets(group_roles, want_assignable=False)

    # Collapse ROPC-reachable grants to one entry per client appId, unioning the
    # high-value scopes. The target set for a given scope is identical across
    # clients, so each chain lists its vias once instead of repeating per client.
    reach = {}
    for g in grants:
        if not (g["client_enabled"] and _ropc_reachable(g["ropc"])):
            continue
        e = reach.setdefault(g["client_appId"], {
            "via": g["client"], "appId": g["client_appId"], "ropc": g["ropc"], "scopes": set()})
        e["scopes"].update(g["high_value_scopes"])

    def vias_with(pred):
        return [{"via": e["via"], "appId": e["appId"], "ropc": e["ropc"]}
                for e in sorted(reach.values(), key=lambda x: x["via"].lower()) if pred(e["scopes"])]

    chains = []

    rw_vias = vias_with(lambda s: ROLE_MGMT_SCOPE in s)
    if rw_vias:
        chains.append({
            "type": "role_write", "priority": 0, "vias": rw_vias, "targets": assignable_targets,
            "note": "assign ANY directory role directly; role-assignable groups also modifiable",
        })

    aw_vias = vias_with(lambda s: "Application.ReadWrite.All" in s)
    if aw_vias and pivots:
        chains.append({
            "type": "app_write", "priority": 1, "vias": aw_vias,
            "pivots": [{"sp": p["sp"], "roles": [r["role"] for r in p["roles"]]} for p in pivots],
        })

    gw_vias = vias_with(lambda s: s & GROUP_WRITE_SCOPES)
    if gw_vias and plain_targets:
        gw_scopes = sorted({x for e in reach.values() for x in (e["scopes"] & GROUP_WRITE_SCOPES)})
        chains.append({
            "type": "group_write", "priority": 2, "vias": gw_vias, "scopes": gw_scopes, "targets": plain_targets,
            "note": ("DELEGATED Group.ReadWrite.All only writes a group you OWN or can reach via a role "
                     "(Groups Administrator / Directory Writers / User Administrator) - see per-group owners below. "
                     "Unconstrained group-write is the APPLICATION permission (an SP in the pivot-targets section), "
                     "reachable only with that SP's secret. Role-assignable groups are out of reach for this scope; "
                     "Azure RBAC group grants are invisible to roadrecon (use enum_azure_rbac.py)."),
        })

    for p in priv_sps:
        if any(r["role"] == "Application.ReadWrite.All" for r in p["roles"]):
            chains.append({
                "type": "secret_then_appwrite", "priority": 3, "via": p["sp"], "via_appId": p["appId"],
                "precondition": f"obtain {p['sp']}'s client secret/certificate",
            })

    return sorted(chains, key=lambda c: c["priority"])


def main():
    ap = argparse.ArgumentParser(description="Privilege-escalation triage over a roadrecon database.")
    ap.add_argument("db", nargs="?", default="roadrecon.db", help="Path to roadrecon SQLite db (default: roadrecon.db)")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of a report")
    ap.add_argument("--all-scopes", action="store_true", help="Include every AllPrincipals grant, not just high-value ones")
    ap.add_argument(
        "--emit-client-ids",
        action="store_true",
        help=(
            "Print only the ROPC-testable client appIds (one per line, with a "
            "'# name :: scopes' annotation) for the high-value tenant-wide grants, "
            "suppressing the report. Confidential clients (need a secret) are "
            "excluded. Pipe straight into apimspray --client-ids."
        ),
    )
    args = ap.parse_args()

    if not Path(args.db).exists():
        print(f"[!] database not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    con = load(args.db)
    sps, role_id_to_value = build_sp_index(con)
    pub_map = app_public_client_map(con)

    grants = find_tenantwide_grants(con, sps, pub_map, all_scopes=args.all_scopes)
    priv_sps = find_privileged_sps(con, sps, role_id_to_value)
    group_roles = load_group_roles(con, sps, role_id_to_value)
    chains = build_chains(grants, priv_sps, group_roles)
    cert_surface = find_cert_surface(con, sps, group_roles)

    if args.emit_client_ids:
        # Deduplicate by appId; exclude confidential clients (ROPC needs a secret)
        # and disabled SPs. Annotation is after '#', which --client-ids ignores.
        seen = set()
        for g in sorted(grants, key=lambda x: x["client"]):
            appid = g["client_appId"]
            if not appid or appid in seen:
                continue
            if g["ropc"].startswith("no") or not g["client_enabled"]:
                continue
            seen.add(appid)
            print(f"{appid}  # {g['client']} :: {', '.join(g['high_value_scopes'])}")
        return

    if args.json:
        json.dump({"tenantwide_grants": grants, "privileged_sps": priv_sps, "chains": chains, "cert_surface": cert_surface}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    def rule(t):
        print(f"\n{'='*70}\n{t}\n{'='*70}")

    # Group grants by client so a multi-resource app prints one block, not one
    # per resource. Clients with a high-value scope sort to the top.
    by_client = {}
    for g in grants:
        by_client.setdefault(g["client_appId"], []).append(g)

    def client_rank(rows):
        has_hv = any(r["high_value_scopes"] for r in rows)
        ropc_top = rows[0]["ropc"][0] != "Y"
        return (not has_hv, ropc_top, rows[0]["client"].lower())

    title = "ALL TENANT-WIDE (AllPrincipals) GRANTS" if args.all_scopes else "TENANT-WIDE (AllPrincipals) GRANTS WITH HIGH-VALUE SCOPES"
    rule(f"{title}  [{len(by_client)} apps / {len(grants)} grants]")
    for rows in sorted(by_client.values(), key=client_rank):
        g0 = rows[0]
        flags = []
        if not g0["client_enabled"]:
            flags.append("SP DISABLED")
        if g0["assignment_required"]:
            flags.append("assignment-required")
        fs = f"  <{', '.join(flags)}>" if flags else ""
        print(f"\n[{g0['client_origin']}] {g0['client']}  (appId {g0['client_appId']}){fs}")
        print(f"      ROPC-reachable: {g0['ropc']}")
        # high-value resources first; skip no-high-value lines unless --all-scopes
        for g in sorted(rows, key=lambda x: not x["high_value_scopes"]):
            if not g["high_value_scopes"] and not args.all_scopes:
                continue
            print(f"      -> {g['resource']}: {', '.join(g['high_value_scopes']) or '(no high-value)'}")
            for s, why in zip(g["high_value_scopes"], g["notes"]):
                print(f"           - {s}: {why}")

    rule(f"SERVICE PRINCIPALS WITH HIGH-VALUE APPLICATION PERMISSIONS (pivot targets)  [{len(priv_sps)}]")
    for p in sorted(priv_sps, key=lambda x: x["sp"]):
        dis = "" if p["enabled"] else "  <SP DISABLED>"
        print(f"\n{p['sp']}  (appId {p['appId']}){dis}")
        for r in p["roles"]:
            print(f"      [{r['role']}] on {r['on']}  - {r['why']}")

    if cert_surface:
        rule("CLOUD -> ON-PREM CERTIFICATE SURFACE (Intune SCEP/NDES -> AD CS)")
        print("\n  Connector SP(s) present: " + ", ".join(cert_surface["connectors"]))
        print("  Ref: dirkjanm.io/extending-ad-cs-attack-surface-intune-certs (2025-07-30)")
        if cert_surface["scoping_groups"]:
            print("  Groups whose membership scopes the cert profile (add-self candidates):")
            for sg in cert_surface["scoping_groups"]:
                print(f"      [{sg['reach']}] {sg['group']}  -> {sg['via']}")
        print("  Verify (not in roadrecon): SCEP profile uses spoofable identifiers +")
        print("  EnrolleeSuppliesSubject + client-auth EKU; device enrolled; CA strong-mapping status.")

    rule(f"CORRELATED ESCALATION CHAINS  [{len(chains)}]")
    if not chains:
        print("\n  (none correlated)")

    def print_vias(vias):
        print("      via (any valid user --ROPC-->):")
        for v in vias:
            print(f"          {v['via']} ({v['appId']})  [{v['ropc']}]")

    def print_group_targets(targets):
        tier_name = {0: "ADMIN / ROLE", 1: "APP ACCESS", 2: "SSO (low value)"}
        for dyn, head in ((False, "STATIC (addable directly)"), (True, "DYNAMIC (rule-gated, not directly addable)")):
            rows = [t for t in targets if t["dynamic"] == dyn]
            if not rows:
                continue
            print(f"      {head}:")
            last_tier = None
            for t in rows:
                if t["tier"] != last_tier:
                    print(f"        - {tier_name[t['tier']]}:")
                    last_tier = t["tier"]
                suffix = f"   (rule: {t['rule']}...)" if t["dynamic"] else ""
                print(f"            {t['name']}  ->  {t['roles']}{suffix}")
                if t["owners"]:
                    print(f"                owners (delegated add works if you land one): {', '.join(t['owners'])}")
                else:
                    print(f"                owners: none  (delegated add needs Groups Administrator / Directory Writers / User Administrator)")

    for ch in chains:
        if ch["type"] == "role_write":
            print(f"\n  [role-write]  ->  assign ANY directory role (Global Admin)")
            print_vias(ch["vias"])
            print(f"      RoleManagement.ReadWrite.Directory -> {ch['note']}")
            if ch["targets"]:
                print("      role-assignable groups reachable this way:")
                print_group_targets(ch["targets"])
        elif ch["type"] == "app_write":
            print(f"\n  [app-write]  ->  Application.ReadWrite.All -> cred onto any privileged SP")
            print_vias(ch["vias"])
            print("      pivot targets:")
            for p in ch["pivots"]:
                print(f"          {p['sp']}  (inherit: {', '.join(p['roles'])})")
        elif ch["type"] == "group_write":
            print(f"\n  [group-write]  ->  {', '.join(ch['scopes'])}: add self to a non-role-assignable group")
            print_vias(ch["vias"])
            print_group_targets(ch["targets"])
            print(f"      note: {ch['note']}")
        elif ch["type"] == "secret_then_appwrite":
            print(f"\n  [secret-gated] {ch['via']} ({ch['via_appId']}) holds app-only Application.ReadWrite.All")
            print(f"      precondition: {ch['precondition']}  ->  then cred onto any app/SP -> pivot anywhere")

    print()


if __name__ == "__main__":
    main()
