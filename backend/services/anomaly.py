"""
Rule-based anomaly detection engine — production-grade.

Each rule receives the log dict and returns either:
  - None  → not suspicious
  - dict  → { severity, title, message }

All matching rules fire (not just first match).
"""

import re
from datetime import datetime
from typing import Optional


# ── Helpers ────────────────────────────────────────────────────────────────────

def _hour(log: dict) -> Optional[int]:
    ts = log.get("occurred_at") or log.get("received_at")
    if not ts:
        return None
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except ValueError:
            return None
    return ts.hour


def _actor(log: dict) -> str:
    return log.get("actor_email") or log.get("actor_id") or "Unknown user"


def _ip(log: dict) -> str:
    return log.get("ip_address") or "unknown IP"


# ── Existing rules (kept + improved) ──────────────────────────────────────────

def rule_late_night_login(log: dict) -> Optional[dict]:
    """Login between midnight and 5 AM."""
    if log.get("event_type") != "login":
        return None
    hour = _hour(log)
    if hour is None or not (0 <= hour < 5):
        return None
    return {
        "severity": "high",
        "title": "Late-Night Login",
        "message": (
            f"{_actor(log)} logged in at {hour:02d}:00 AM — an unusual hour. "
            "This may indicate account compromise or unauthorized access."
        ),
    }


def rule_bulk_download(log: dict) -> Optional[dict]:
    """More than 20 file downloads in a single event."""
    if log.get("event_type") not in ("download", "file_download", "export"):
        return None
    count = log.get("action_count", 1)
    if count <= 20:
        return None
    return {
        "severity": "high",
        "title": "Bulk File Download",
        "message": (
            f"{_actor(log)} downloaded {count} files in one session. "
            "This volume is unusual and may indicate data exfiltration."
        ),
    }


def rule_privilege_escalation(log: dict) -> Optional[dict]:
    """Privilege escalation flag or role_change to admin."""
    is_escalation = log.get("privilege_escalation", False)
    role_change_to_admin = (
        log.get("event_type") in ("role_change", "permission_change")
        and "admin" in str(log.get("resource", "")).lower()
    )
    if not (is_escalation or role_change_to_admin):
        return None
    return {
        "severity": "critical",
        "title": "Privilege Escalation",
        "message": (
            f"{_actor(log)} was granted elevated or admin privileges. "
            "Immediate review is required — this is a high-risk change."
        ),
    }


def rule_multiple_failed_logins(log: dict) -> Optional[dict]:
    """Explicit brute-force / failed login events."""
    if log.get("event_type") not in ("login_failed", "brute_force", "multiple_failed_logins"):
        return None
    count = log.get("action_count", 1)
    actor = _actor(log)
    return {
        "severity": "high",
        "title": "Multiple Failed Logins",
        "message": (
            f"{count} failed login attempt(s) detected for {actor} from {_ip(log)}. "
            "This pattern suggests a brute-force or credential stuffing attack."
        ),
    }


def rule_server_error(log: dict) -> Optional[dict]:
    """5xx HTTP responses."""
    code = log.get("status_code")
    if code is None or code < 500:
        return None
    endpoint = log.get("endpoint", "unknown endpoint")
    return {
        "severity": "medium",
        "title": "Server Error Detected",
        "message": (
            f"Endpoint '{endpoint}' returned HTTP {code}. "
            "Repeated server errors can indicate an attack or service disruption."
        ),
    }


def rule_off_hours_admin_action(log: dict) -> Optional[dict]:
    """Admin performing any action outside 8 AM–8 PM."""
    if log.get("actor_role", "").lower() != "admin":
        return None
    hour = _hour(log)
    if hour is None or (8 <= hour < 20):
        return None
    return {
        "severity": "medium",
        "title": "Off-Hours Admin Activity",
        "message": (
            f"Admin {_actor(log)} performed '{log.get('event_type')}' outside business hours "
            f"(hour {hour:02d}:00). Verify this action was intentional."
        ),
    }


# ── NEW: Injection attack detection ───────────────────────────────────────────

_SQL_PATTERNS = re.compile(
    r"('|\"|--|;|\/\*|\*\/|xp_|UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO"
    r"|SELECT\s+\*|OR\s+1=1|AND\s+1=1|SLEEP\s*\(|BENCHMARK\s*\()",
    re.IGNORECASE,
)

_XSS_PATTERNS = re.compile(
    r"(<script|javascript:|onerror=|onload=|<iframe|<img[^>]+src=|eval\s*\(|document\.cookie)",
    re.IGNORECASE,
)

_PATH_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", re.IGNORECASE)


def rule_injection_attempt(log: dict) -> Optional[dict]:
    """Detect SQL injection, XSS, and path traversal patterns in endpoint or user_agent."""
    targets = [
        log.get("endpoint", ""),
        log.get("user_agent", ""),
        log.get("resource", ""),
    ]
    combined = " ".join(str(t) for t in targets if t)

    if _SQL_PATTERNS.search(combined):
        return {
            "severity": "critical",
            "title": "SQL Injection Attempt",
            "message": (
                f"{_actor(log)} from {_ip(log)} sent a request containing SQL injection patterns "
                f"targeting '{log.get('endpoint', 'unknown endpoint')}'. Block and investigate immediately."
            ),
        }
    if _XSS_PATTERNS.search(combined):
        return {
            "severity": "high",
            "title": "XSS Attempt Detected",
            "message": (
                f"A cross-site scripting (XSS) payload was detected from {_ip(log)} "
                f"in a request to '{log.get('endpoint', 'unknown endpoint')}'. "
                "This could be an attempt to hijack user sessions."
            ),
        }
    if _PATH_TRAVERSAL.search(combined):
        return {
            "severity": "high",
            "title": "Path Traversal Attempt",
            "message": (
                f"{_actor(log)} from {_ip(log)} attempted directory traversal "
                f"on '{log.get('endpoint', 'unknown path')}'. "
                "They may be trying to access restricted server files."
            ),
        }
    return None


# ── NEW: Account enumeration ───────────────────────────────────────────────────

def rule_account_enumeration(log: dict) -> Optional[dict]:
    """
    Repeated 404s or failed auth from the same IP against different endpoints
    in a single log event. Detects username/email probing.
    """
    if log.get("status_code") not in (404, 401, 403):
        return None
    count = log.get("action_count", 1)
    if count < 10:
        return None
    return {
        "severity": "high",
        "title": "Account Enumeration Detected",
        "message": (
            f"{count} failed requests (HTTP {log.get('status_code')}) from {_ip(log)}. "
            "This pattern suggests automated probing for valid user accounts or endpoints."
        ),
    }


# ── NEW: Impossible travel ─────────────────────────────────────────────────────

# Country-level "impossible travel" using a simple known-pairing list.
# In production, replace with a real GeoIP + velocity check against DB.
_HIGH_RISK_COUNTRY_PAIRS = {
    frozenset(["IN", "US"]),
    frozenset(["IN", "RU"]),
    frozenset(["IN", "CN"]),
    frozenset(["GB", "KP"]),
    frozenset(["US", "KP"]),
    frozenset(["US", "RU"]),
}

def rule_impossible_travel(log: dict) -> Optional[dict]:
    """
    Flag if log metadata contains two_location_countries field set by the ingestion
    pipeline (compare current location with actor's last known location).
    Alternatively, flag any login carrying a 'prev_location' meta field
    that differs drastically from current location.
    """
    metadata_str = log.get("meta_data") or log.get("metadata") or ""
    metadata = {}
    if isinstance(metadata_str, dict):
        metadata = metadata_str
    elif isinstance(metadata_str, str):
        import json
        try:
            metadata = json.loads(metadata_str)
        except (ValueError, TypeError):
            metadata = {}

    prev_country = str(metadata.get("prev_country", "")).upper()
    curr_country = str(metadata.get("curr_country", log.get("location", "")[:2])).upper()

    if not prev_country or not curr_country or prev_country == curr_country:
        return None

    pair = frozenset([prev_country, curr_country])
    if pair in _HIGH_RISK_COUNTRY_PAIRS:
        return {
            "severity": "critical",
            "title": "Impossible Travel Detected",
            "message": (
                f"{_actor(log)}'s account was accessed from {curr_country} shortly after "
                f"a session from {prev_country}. This geographic jump may indicate "
                "a stolen credential or account takeover."
            ),
        }
    return None


# ── NEW: Token / session replay ────────────────────────────────────────────────

def rule_token_reuse_after_logout(log: dict) -> Optional[dict]:
    """
    Detects an authenticated action immediately after a logout event.
    Requires the client to send event_type='action_after_logout' or
    include meta_data.seconds_since_logout < 10.
    """
    if log.get("event_type") == "action_after_logout":
        return {
            "severity": "high",
            "title": "Session Token Reuse",
            "message": (
                f"{_actor(log)} from {_ip(log)} performed an action immediately after logout. "
                "This may indicate a stolen or replayed session token."
            ),
        }

    metadata = {}
    raw = log.get("meta_data") or log.get("metadata") or {}
    if isinstance(raw, str):
        import json
        try:
            metadata = json.loads(raw)
        except (ValueError, TypeError):
            pass
    elif isinstance(raw, dict):
        metadata = raw

    seconds = metadata.get("seconds_since_logout")
    if seconds is not None and int(seconds) < 10:
        return {
            "severity": "high",
            "title": "Session Token Reuse",
            "message": (
                f"{_actor(log)} performed an action just {seconds}s after logout from {_ip(log)}. "
                "The session token may have been captured and replayed."
            ),
        }
    return None


# ── NEW: Slow-drip data exfiltration ──────────────────────────────────────────

def rule_slow_exfiltration(log: dict) -> Optional[dict]:
    """
    Detects gradual data export — small batches but flagged cumulatively
    by the client via action_count and event_type. 
    Triggers on download/export with 5–20 files but marked high severity.
    """
    if log.get("event_type") not in ("download", "file_download", "export"):
        return None
    count = log.get("action_count", 1)
    severity = log.get("severity", "low")

    # Small batch but client already assessed it as high risk
    if 5 <= count <= 20 and severity in ("high", "critical"):
        return {
            "severity": "medium",
            "title": "Possible Slow Data Exfiltration",
            "message": (
                f"{_actor(log)} exported {count} files — a moderate volume "
                "that was pre-flagged as high risk by the source system. "
                "This may be part of a slow, deliberate data leak."
            ),
        }
    return None


# ── NEW: Mass permission change ────────────────────────────────────────────────

def rule_mass_permission_change(log: dict) -> Optional[dict]:
    """Multiple role or permission changes in one event."""
    if log.get("event_type") not in ("role_change", "permission_change", "bulk_permission_change"):
        return None
    count = log.get("action_count", 1)
    if count < 5:
        return None
    return {
        "severity": "critical",
        "title": "Mass Permission Change",
        "message": (
            f"{_actor(log)} changed permissions for {count} users or resources in one action. "
            "Bulk permission changes are extremely high-risk and require immediate review."
        ),
    }


# ── NEW: Suspicious user-agent ────────────────────────────────────────────────

_BOT_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|metasploit"
    r"|curl\/[0-9]|python-requests|scrapy|zgrab|nuclei)",
    re.IGNORECASE,
)

def rule_suspicious_user_agent(log: dict) -> Optional[dict]:
    """Detect known scanner / attack tool user agents."""
    ua = log.get("user_agent", "")
    if not ua or not _BOT_AGENTS.search(ua):
        return None
    return {
        "severity": "high",
        "title": "Attack Tool Detected",
        "message": (
            f"A request from {_ip(log)} used a user-agent matching known attack tools "
            f"('{ua[:60]}'). This strongly suggests automated scanning or exploitation."
        ),
    }


# ── NEW: Severity escalation across multiple alerts ───────────────────────────

def rule_repeated_medium_alerts(log: dict) -> Optional[dict]:
    """
    If the same IP or actor is already marked 'high' in this log event,
    and this is the second+ suspicious indicator, escalate to critical.
    This is a meta-rule — run it last.

    In production, replace this with a DB query counting recent alerts
    for the same actor_id / ip_address within the last 10 minutes.
    """
    # Client-side signal: if they're sending a log already severity=high
    # AND it's a repeated offender flag
    metadata = {}
    raw = log.get("meta_data") or log.get("metadata") or {}
    if isinstance(raw, str):
        import json
        try:
            metadata = json.loads(raw)
        except (ValueError, TypeError):
            pass
    elif isinstance(raw, dict):
        metadata = raw

    prior_alert_count = int(metadata.get("prior_alert_count", 0))
    if prior_alert_count >= 3 and log.get("severity") in ("high", "critical"):
        return {
            "severity": "critical",
            "title": "Repeat Offender — Escalated",
            "message": (
                f"{_actor(log)} from {_ip(log)} has triggered {prior_alert_count} prior alerts "
                "in this session. All activity from this actor should be treated as critical risk."
            ),
        }
    return None


# ── NEW: Improved location rule ────────────────────────────────────────────────

def rule_new_location(log: dict) -> Optional[dict]:
    """
    Flag high/critical events paired with a location not matching
    actor's home country (from metadata.home_country).
    Much more useful than the original version.
    """
    location = log.get("location", "")
    if not location:
        return None

    metadata = {}
    raw = log.get("meta_data") or log.get("metadata") or {}
    if isinstance(raw, str):
        import json
        try:
            metadata = json.loads(raw)
        except (ValueError, TypeError):
            pass
    elif isinstance(raw, dict):
        metadata = raw

    home = metadata.get("home_country", "").lower()
    if home and home not in location.lower():
        severity = log.get("severity", "low")
        if severity in ("high", "critical"):
            return {
                "severity": "medium",
                "title": "Activity from Unusual Location",
                "message": (
                    f"{_actor(log)} triggered a high-severity event from {location}, "
                    f"but their usual location is {home.title()}. "
                    "Verify this was an authorized access."
                ),
            }
    return None


# ── Registry ───────────────────────────────────────────────────────────────────

ALL_RULES = [
    # Existing (improved)
    rule_late_night_login,
    rule_bulk_download,
    rule_privilege_escalation,
    rule_multiple_failed_logins,
    rule_server_error,
    rule_off_hours_admin_action,
    rule_new_location,          # improved version
    # New
    rule_injection_attempt,
    rule_account_enumeration,
    rule_impossible_travel,
    rule_token_reuse_after_logout,
    rule_slow_exfiltration,
    rule_mass_permission_change,
    rule_suspicious_user_agent,
    rule_repeated_medium_alerts,  # meta-rule — keep last
]


def detect(log: dict) -> list[dict]:
    """Run all rules. Returns a (possibly empty) list of alert dicts."""
    alerts = []
    for rule in ALL_RULES:
        result = rule(log)
        if result:
            alerts.append(result)
    return alerts