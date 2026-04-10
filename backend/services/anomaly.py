"""
Rule-based anomaly detection engine.

Each rule is a function that receives the log dict and returns either:
  - None          → not suspicious
  - dict          → { severity, title, message } if suspicious

Rules are evaluated in order; ALL matching rules produce alerts (not just first match).
"""
from datetime import datetime
from typing import Optional


# ── Helper ─────────────────────────────────────────────────────────────────────

def _hour(log: dict) -> Optional[int]:
    """Return hour-of-day from occurred_at or received_at."""
    ts = log.get("occurred_at") or log.get("received_at")
    if not ts:
        return None
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except ValueError:
            return None
    return ts.hour


# ── Rules ──────────────────────────────────────────────────────────────────────

def rule_late_night_login(log: dict) -> Optional[dict]:
    """Login between midnight and 5 AM is suspicious."""
    if log.get("event_type") != "login":
        return None
    hour = _hour(log)
    if hour is None:
        return None
    if 0 <= hour < 5:
        actor = log.get("actor_email", "Unknown user")
        return {
            "severity": "high",
            "title": "Late-Night Login",
            "message": (
                f"⚠️ {actor} logged in at an unusual time "
                f"({hour:02d}:{0:02d} AM). This may indicate account compromise."
            ),
        }
    return None


def rule_bulk_download(log: dict) -> Optional[dict]:
    """More than 20 downloads in a single event is suspicious."""
    if log.get("event_type") not in ("download", "file_download", "export"):
        return None
    count = log.get("action_count", 1)
    if count > 20:
        actor = log.get("actor_email", "Unknown user")
        return {
            "severity": "high",
            "title": "Bulk File Download",
            "message": (
                f"⚠️ {actor} downloaded {count} files in one session. "
                "Possible data exfiltration."
            ),
        }
    return None


def rule_privilege_escalation(log: dict) -> Optional[dict]:
    """Any privilege escalation flag or role_change to admin."""
    is_escalation = log.get("privilege_escalation", False)
    role_change_to_admin = (
        log.get("event_type") in ("role_change", "permission_change")
        and "admin" in str(log.get("resource", "")).lower()
    )
    if not (is_escalation or role_change_to_admin):
        return None
    actor = log.get("actor_email", "Unknown user")
    return {
        "severity": "critical",
        "title": "Privilege Escalation",
        "message": (
            f"🚨 {actor} was granted elevated / admin privileges. "
            "Immediate review required."
        ),
    }


def rule_multiple_failed_logins(log: dict) -> Optional[dict]:
    """Brute-force indicators."""
    if log.get("event_type") not in ("login_failed", "brute_force", "multiple_failed_logins"):
        return None
    count = log.get("action_count", 1)
    actor = log.get("actor_email", log.get("ip_address", "Unknown"))
    return {
        "severity": "high",
        "title": "Multiple Failed Logins",
        "message": (
            f"⚠️ {count} failed login attempt(s) detected for {actor}. "
            "Possible brute-force attack."
        ),
    }


def rule_server_error(log: dict) -> Optional[dict]:
    """5xx HTTP responses are worth flagging."""
    code = log.get("status_code")
    if code is None or code < 500:
        return None
    endpoint = log.get("endpoint", "unknown endpoint")
    return {
        "severity": "medium",
        "title": "Server Error Detected",
        "message": (
            f"⚠️ Endpoint '{endpoint}' returned HTTP {code}. "
            "Possible service disruption."
        ),
    }


def rule_new_location(log: dict) -> Optional[dict]:
    """Flag events from unusual/foreign locations (simple keyword list)."""
    location = log.get("location", "")
    if not location:
        return None
    # In production, compare against the user's known locations in DB.
    # Here we flag any event already marked high/critical with a foreign location hint.
    if log.get("severity") in ("high", "critical") and location:
        actor = log.get("actor_email", "Unknown user")
        return {
            "severity": "medium",
            "title": "High-Severity Event from Remote Location",
            "message": (
                f"ℹ️ {actor} triggered a high-severity event from {location}."
            ),
        }
    return None


def rule_off_hours_admin_action(log: dict) -> Optional[dict]:
    """Admin performing any action outside 8 AM–8 PM."""
    if log.get("actor_role", "").lower() != "admin":
        return None
    hour = _hour(log)
    if hour is None:
        return None
    if hour < 8 or hour >= 20:
        actor = log.get("actor_email", "Admin")
        return {
            "severity": "medium",
            "title": "Off-Hours Admin Activity",
            "message": (
                f"ℹ️ Admin {actor} performed '{log.get('event_type')}' outside business hours."
            ),
        }
    return None


# ── Registry ───────────────────────────────────────────────────────────────────

ALL_RULES = [
    rule_late_night_login,
    rule_bulk_download,
    rule_privilege_escalation,
    rule_multiple_failed_logins,
    rule_server_error,
    rule_new_location,
    rule_off_hours_admin_action,
]


def detect(log: dict) -> list[dict]:
    """
    Run all rules against a log dict.
    Returns a (possibly empty) list of alert dicts.
    """
    alerts = []
    for rule in ALL_RULES:
        result = rule(log)
        if result:
            alerts.append(result)
    return alerts