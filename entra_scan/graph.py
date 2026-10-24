"""Microsoft Graph v1.0 client: GET only, with the safety rules that protect the access token.

Why so careful?  The bearer token can read the whole tenant's configuration, and Graph responses contain
URLs (@odata.nextLink) that we then call.  A hostile or buggy value must never make us send the token to
another host, follow a redirect, or loop forever.

Troubleshooting: pass `--verbose` / `--log-file` to the CLI. Every request is logged as
"GET <path> -> <status> (<ms>, request-id <id>)".  Tokens and headers are never logged.
"""
from __future__ import annotations

import logging
import math
import time
from urllib.parse import quote, urlencode, urlsplit

import requests

from .clouds import CLOUDS, Cloud
from .models import GraphError

log = logging.getLogger("entra_scan.graph")

GRAPH = CLOUDS["commercial"].graph_url                  # kept for callers/tests that import it
GRAPH_HOSTS = {"graph.microsoft.com"}
MAX_PAGES = 5000            # hard stop for paging loops
MAX_ATTEMPTS = 6            # retries for throttling (429) and transient 5xx
DEFAULT_TIMEOUT = 60        # seconds per request


def trusted_url(url, hosts=GRAPH_HOSTS):
    """Refuse to send credentials anywhere except an expected Microsoft host over https."""
    u = urlsplit(str(url))
    if u.scheme != "https" or (u.hostname or "").lower() not in hosts or u.username or u.password:
        raise GraphError(400, "UntrustedUrl", f"Refused to send credentials to {u.scheme}://{u.hostname}", str(url)[:120])
    return url


def retry_after(headers, attempt):
    """Seconds to wait before retrying. Honour Retry-After when it is a sane number, otherwise back off exponentially."""
    try:
        v = float(headers.get("Retry-After"))
        if not math.isnan(v) and v >= 0:
            return min(v, 60.0)
    except (TypeError, ValueError):
        pass
    return float(min(2 ** attempt, 60))


def checked_page(data, url=""):
    """Normalise one Graph answer so the checks can rely on its shape.

    The tenant is untrusted input: a proxy, a bug or an attacker-controlled value could return a list or a string instead of an
    object, or rows that are not objects. A non-object answer becomes a GraphError (the check is then reported as ERROR, not crashed);
    rows inside "value" that are not objects are dropped.
    """
    if not isinstance(data, dict):
        raise GraphError(502, "UnexpectedResponse", f"Graph returned {type(data).__name__} instead of an object", str(url)[:120])
    if "value" in data:
        rows = data["value"]
        data = {**data, "value": [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []}
    return data


class Graph:
    """Tiny read-only client.  `token_provider()` returns a fresh access token each call (MSAL caches them)."""

    def __init__(self, token_provider, cloud: Cloud | None = None, proxy=None, ca_bundle=None, timeout=DEFAULT_TIMEOUT):
        self.cloud = cloud or CLOUDS["commercial"]
        self.hosts = {self.cloud.graph_host}                # the ONLY host that may ever receive the token
        self.token = token_provider
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"https": proxy, "http": proxy}
        if ca_bundle:
            self.session.verify = ca_bundle                 # corporate TLS-inspection CA bundle
        self.timeout = timeout
        self.deadline = None                                # monotonic time after which requests are refused (per-check budget)
        self.calls = 0                                      # how many requests were made (shown in the report footer)

    # -- one request ------------------------------------------------------------------------
    def _request(self, url):
        """GET one URL with retries. Raises GraphError for HTTP errors, redirects and an exhausted time budget."""
        trusted_url(url, self.hosts)
        for attempt in range(MAX_ATTEMPTS):
            if self.deadline is not None and time.monotonic() > self.deadline:
                raise GraphError(408, "TimeBudgetExceeded", "The time budget for this check ran out (see --check-timeout)", url[:120])
            self.calls += 1
            started = time.monotonic()
            r = self.session.get(
                url, timeout=self.timeout, allow_redirects=False,         # never follow redirects with a token attached
                # ConsistencyLevel=eventual enables "advanced queries" ($count, some $filter forms) on directory objects.
                headers={"Authorization": f"Bearer {self.token()}", "ConsistencyLevel": "eventual"})
            rid = (getattr(r, "headers", {}) or {}).get("request-id", "-")
            log.debug("GET %s -> %s (%d ms, request-id %s)", urlsplit(url).path + ("?" + urlsplit(url).query[:80] if urlsplit(url).query else ""),
                      r.status_code, (time.monotonic() - started) * 1000, rid)
            if r.status_code in (429, 500, 502, 503, 504):      # throttled or temporarily unavailable: wait and retry
                time.sleep(retry_after(r.headers, attempt))
                continue
            if 300 <= r.status_code < 400:
                raise GraphError(r.status_code, "UnexpectedRedirect", "Graph redirected; refusing to follow with credentials", url[:120])
            if r.status_code >= 400:
                try:
                    err = r.json().get("error", {})
                except (ValueError, AttributeError):
                    err = {}
                raise GraphError(r.status_code, err.get("code", ""), err.get("message", r.text[:200]), url)
            return r.json()
        raise GraphError(429, "Throttled", "Retries exhausted", url)

    def _url(self, path, params):
        """Build the full URL. A bare path is attached to the cloud's Graph base; an absolute URL is used as given (and then host-checked)."""
        url = path if path.startswith("http") else self.cloud.graph_url + path
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params, quote_via=quote, safe="$,()'")
        return url

    # -- public API -------------------------------------------------------------------------
    def get(self, path, params=None):
        """GET one object (or one page)."""
        return checked_page(self._request(self._url(path, params)), path)

    def get_all(self, path, params=None, limit=0):
        """GET a collection, following @odata.nextLink.  `limit` stops early once enough rows are read (0 = all)."""
        first = self._url(path, params)
        data, rows, seen = checked_page(self._request(first), path), [], {first}
        while True:
            rows.extend(data.get("value", []))
            if limit and len(rows) >= limit:
                return rows[:limit]
            nxt = data.get("@odata.nextLink")
            if not nxt:
                return rows
            if nxt in seen or len(seen) > MAX_PAGES:           # a repeating or endless nextLink must not hang the scan
                raise GraphError(500, "PaginationLoop", "nextLink repeated or exceeded the page limit", str(nxt)[:120])
            seen.add(nxt)
            data = checked_page(self._request(nxt), path)
