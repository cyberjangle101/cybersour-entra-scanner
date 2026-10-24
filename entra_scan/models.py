"""Core data types and small helpers used by every check.

Plain-language glossary:
  Finding   one result line in the report (PASS / FAIL / WARN / INFO / SKIPPED / ERROR).
  check     a function that asks Graph some questions and returns a list of Findings.
  SKIPPED   the check could not read its data (missing permission or licence). It is NEVER counted as a pass.
"""
from __future__ import annotations

import math

import datetime as dt
import os
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import quote

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# Report ordering: the things that need attention come first, passes last.
STATUS_ORDER = {"FAIL": 0, "WARN": 1, "ERROR": 2, "SKIPPED": 3, "MANUAL": 4, "SUPPRESSED": 5, "INFO": 6, "PASS": 7}
MAX_EVIDENCE = 5000          # safety cap per finding (the HTML report shows far fewer; JSON/CSV keep everything up to this)
MICROSOFT_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"      # tenant that owns first-party Microsoft apps


# --------------------------------------------------------------------------- exceptions
class GraphError(Exception):
    """Graph answered with an HTTP error (or something we refuse to trust)."""

    def __init__(self, status, code, message, url=""):
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message, self.url = status, code, message, url


class SkipCheck(Exception):
    """Raised by a check that cannot run in this tenant. The reason is shown in the report."""


class ConfigError(Exception):
    """Bad or missing configuration or credentials. The message is written for the person running the tool."""


# --------------------------------------------------------------------------- the finding
@dataclass
class Finding:
    """One result row. status: PASS, FAIL, WARN, INFO, MANUAL, SKIPPED or ERROR."""
    id: str                          # stable identifier, e.g. "CA-002"
    category: str                    # which area of Entra it belongs to (see runner.AREAS)
    title: str                       # what is being checked, phrased as the desired state
    status: str                      # PASS | FAIL | WARN | INFO | MANUAL | SKIPPED | ERROR
    severity: str = "info"
    detail: str = ""                 # what was found
    remediation: str = ""            # how to fix it
    evidence: list = field(default_factory=list)   # affected objects, as "name [id]"
    cis: str = ""                    # CIS benchmark reference (filled in by metadata.py)
    learn: str = ""                  # Microsoft Learn article (filled in by metadata.py)
    setting: str = ""                # the exact Graph object/property the verdict is based on (metadata.py)
    needs: str = ""                  # Graph permission this check reads with (filled in by the runner)
    risk: str = ""                   # severity this control carries when it FAILS (used for scoring PASS rows); set by verdict()
    frameworks: dict = field(default_factory=dict)   # {"nist": [...], "iso": [...]} indicative mappings (metadata.py)
    script: str = ""                 # optional read-only remediation guidance / PowerShell snippet (never run by the scanner)
    suppression: dict = field(default_factory=dict)  # set when an accepted-risk entry applies: reason, owner, expires, original status
    fingerprint: str = ""            # stable hash of id + affected objects, used to compare runs


def PASS(i, c, t, d=""):
    """A control that is satisfied."""
    return Finding(i, c, t, "PASS", "info", d)


def INFO(i, c, t, d="", ev=None):
    """Context that is neither good nor bad."""
    return Finding(i, c, t, "INFO", "info", d, "", list(ev or []))


def MANUAL(i, c, t, d, fix):
    """A CIS recommendation that Microsoft Graph cannot read. Listed so nothing silently falls off the audit."""
    return Finding(i, c, t, "MANUAL", "info", d, fix)


def FAIL(i, c, t, sev, d, fix, ev=None):
    """A control that is not met (severity says how bad)."""
    return Finding(i, c, t, "FAIL", sev, d, fix, list(ev or []))


def WARN(i, c, t, sev, d, fix, ev=None):
    """A weaker or partial failure that deserves a look."""
    return Finding(i, c, t, "WARN", sev, d, fix, list(ev or []))


def verdict(i, c, t, ok, sev, detail, fix, ev=None, warn=False):
    """PASS when ok; otherwise FAIL (or WARN for softer, judgement-call items)."""
    if ok:
        f = PASS(i, c, t)
    else:
        f = (WARN if warn else FAIL)(i, c, t, sev, detail, fix, ev)
    f.risk = sev                                     # remember how serious this control is, even when it passes (for scoring)
    return f


# --------------------------------------------------------------------------- check registry
CHECKS: list[tuple[str, Callable]] = []


def check(category, needs=()):
    """Decorator: register a function as a check in an area.

    The docstring becomes the check's display name.  `needs` lists the Microsoft Graph application permissions
    the check reads with; it feeds `--list-permissions`, the README table and the "SKIPPED" explanations.
    """
    def deco(fn):
        """Register the function and remember which permissions it needs."""
        fn.needs = tuple(needs)
        CHECKS.append((category, fn))
        return fn
    return deco


# --------------------------------------------------------------------------- small helpers
def sample(items, n=MAX_EVIDENCE):
    """The affected objects, in order. Only a very large list is cut (at MAX_EVIDENCE) and the cut is stated.

    Earlier versions cut every list at 25, which lost the full list that auditors and remediation teams need.
    The HTML report still shows only the first few; JSON, CSV, SARIF and JUnit carry everything.
    """
    items = list(items) if isinstance(items, (list, tuple, set)) else []
    out = items[:n]
    if len(items) > n:
        out.append(f"... and {len(items) - n} more (list capped at {n})")
    return out


def ref(label, ident=None):
    """Evidence entry that names an object AND carries its stable identifier: 'name [id]'.
    Names change; IDs do not, and the ID is what you paste into the portal or a script."""
    label = "?" if label in (None, "") else str(label)
    return f"{label} [{ident}]" if ident and str(ident) != label else label


def seg(x):
    """Make an identifier safe to place inside a URL path (values come from the API, so never trust them)."""
    return quote(str(x), safe=",@:'$()=")


def num(x, default=0.0):
    """Tolerant number: API fields that arrive as null or text must not crash a whole check."""
    try:
        v = float(x)
        return v if math.isfinite(v) else default
    except (TypeError, ValueError):
        return default


def parse_time(s):
    """ISO-8601 string -> timezone-aware datetime, or None if it is missing or malformed."""
    if not isinstance(s, str) or not s:
        return None
    try:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def one(data):
    """Some policy endpoints return a single object, others a collection of one. Always give back the object."""
    if isinstance(data, dict) and isinstance(data.get("value"), list):
        return data["value"][0] if data["value"] else {}
    return data


def write_private(path, text):
    """Write a file readable only by the current user (POSIX). On Windows it inherits the folder's ACL."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    try:
        os.chmod(str(path), 0o600)
    except OSError:
        pass
