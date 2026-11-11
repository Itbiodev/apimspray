#!/usr/bin/env python3
"""
check_auth_sync.py - CI guard that the duplicated auth block stays byte-identical
across the standalone Graph helpers.

We deliberately keep check_group_membership.py and add_to_group.py as separate,
copy-pasteable single files (portability on an engagement box beats DRY). The
cost is a shared auth block that could drift. This script is the safety net:
it extracts the shared symbols from each file via AST and fails if they differ,
so CI catches drift instead of a human.

Stdlib only; parses (does not import) the targets, so it needs no third-party
packages installed in CI. Exit 0 = in sync, 1 = drift (prints a diff).

    python3 tools/check_auth_sync.py
"""

import ast
import difflib
import pathlib
import sys

# Files that must share the auth block, relative to the repo root.
SCRIPTS = ["check_group_membership.py", "add_to_group.py",
           "enum_cert_profiles.py", "add_app_credential.py", "enum_azure_rbac.py"]

# Symbols (functions and module constants) that must be identical across them.
SHARED = ["DEFAULT_FOCI_CLIENT", "FOCI_CLIENTS", "_read_source", "_try_redeem",
          "redeem_refresh_token", "read_token"]


def extract(path):
    """Map each shared symbol name -> its exact source text in `path`."""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    found = {}
    for node in tree.body:
        name = None
        if isinstance(node, ast.FunctionDef):
            name = node.name
        elif isinstance(node, ast.Assign):
            tgts = [t.id for t in node.targets if isinstance(t, ast.Name)]
            name = next((t for t in tgts if t in SHARED), None)
        if name in SHARED:
            found[name] = ast.get_source_segment(src, node)
    return found


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    paths = [root / s for s in SCRIPTS]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        print(f"[!] missing file(s): {', '.join(missing)}", file=sys.stderr)
        return 1

    extracted = {p: extract(p) for p in paths}
    ref_path = paths[0]
    ref = extracted[ref_path]

    drift = False
    for sym in SHARED:
        if sym not in ref:
            print(f"[!] {ref_path.name}: shared symbol '{sym}' not found", file=sys.stderr)
            drift = True
            continue
        for other in paths[1:]:
            got = extracted[other].get(sym)
            if got is None:
                print(f"[!] {other.name}: shared symbol '{sym}' not found", file=sys.stderr)
                drift = True
            elif got != ref[sym]:
                drift = True
                print(f"\n[!] DRIFT in '{sym}': {other.name} differs from {ref_path.name}")
                for line in difflib.unified_diff(
                    ref[sym].splitlines(), got.splitlines(),
                    fromfile=f"{ref_path.name}:{sym}", tofile=f"{other.name}:{sym}", lineterm=""):
                    print(line)

    if drift:
        print("\n[!] auth block out of sync. Re-copy the shared block so all helpers match.", file=sys.stderr)
        return 1
    print(f"[+] auth block in sync across {len(paths)} helper(s): {', '.join(SCRIPTS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
