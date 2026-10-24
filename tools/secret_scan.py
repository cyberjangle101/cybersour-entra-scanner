"""Dependency-free secrets scanner for this repository (and any zip of it).
High-signal patterns + entropy + risky filenames. Not a replacement for gitleaks/trufflehog (CI runs those too), but it needs no
install and no network.  Usage: python tools/secret_scan.py [path ...]   (default: repo root).  Exit 1 if anything is found."""
import math, os, re, sys, zipfile

PATTERNS = {
    "private key block": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    "Entra/Azure AD client secret value": r"(?<![A-Za-z0-9])[A-Za-z0-9_~.\-]{3}8Q~[A-Za-z0-9_~.\-]{20,}",
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Bearer token literal": r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{30,}=*",
    "Azure storage / SAS": r"(?:AccountKey|SharedAccessSignature|[?&]sig)=[A-Za-z0-9%+/=]{20,}",
    "Azure connection string": r"(?:DefaultEndpointsProtocol|Endpoint=sb://)[^\"'\s]{20,}",
    "AWS access key id": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "GitHub token": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b",
    "Slack token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    "Google API key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "generic credential assignment": r"(?i)\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']",
    "URL with embedded credentials": r"[a-z][a-z0-9+.\-]*://[^/\s:@]{1,64}:[^/\s:@]{3,64}@[^/\s]+",
}
RISKY_NAMES = re.compile(r"(?i)(\.pem|\.key|\.pfx|\.p12|\.jks|\.kdbx|\.env(\..+)?|id_rsa|id_ed25519|secrets?\.(json|ya?ml|txt)|credentials(\.json)?|settings\.json)$")
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", ".venv-build", "dist", "build"}
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|your[_-]|<.*>|xxxx|\.\.\.|dummy|fake|canary|test|sample|\$\{|%\w+%|os\.environ|getenv)")
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def entropy(s):
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def scan_text(name, text):
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if "secret-scan: ignore" in line:      # explicit, reviewable allow-marker for dummy test fixtures
            continue
        for label, rx in PATTERNS.items():
            for m in re.finditer(rx, line):
                if label == "URL with embedded credentials":
                    userinfo = m.group(0).split("://", 1)[1].split("@", 1)[0]       # judge only user:password, not the host
                    if PLACEHOLDER.search(userinfo):
                        continue
                elif PLACEHOLDER.search(line) and label in ("generic credential assignment", "Bearer token literal"):
                    continue
                hits.append((name, lineno, label, m.group(0)[:60]))
        for m in re.finditer(r"[\"']([A-Za-z0-9+/=_\-]{24,})[\"']", line):          # long random-looking literals
            tok = m.group(1)
            if not GUID.match(tok) and entropy(tok) >= 4.3 and not PLACEHOLDER.search(line) and not re.fullmatch(r"[A-Za-z_]+", tok):   # letters-only = identifier, not a secret
                hits.append((name, lineno, f"high-entropy literal ({entropy(tok):.1f} bits/char)", tok[:40]))
    return hits


def scan_path(root):
    findings, files = [], 0
    for dp, dirs, fs in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in fs:
            path = os.path.join(dp, f)
            rel = os.path.relpath(path, root)
            files += 1
            if RISKY_NAMES.search(f):
                findings.append((rel, 0, "risky filename", f))
            if f.lower().endswith(".zip"):
                findings += scan_zip(path)
                continue
            try:
                data = open(path, "rb").read()
            except OSError:
                continue
            if b"\0" in data[:4096]:
                continue
            findings += scan_text(rel, data.decode("utf-8", "replace"))
    return files, findings


def scan_zip(path):
    out = []
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith("/"):
                continue
            if RISKY_NAMES.search(os.path.basename(n)):
                out.append((f"{os.path.basename(path)}!{n}", 0, "risky filename", n))
            data = z.read(n)
            if b"\0" not in data[:4096]:
                out += scan_text(f"{os.path.basename(path)}!{n}", data.decode("utf-8", "replace"))
    return out


if __name__ == "__main__":
    roots = sys.argv[1:] or [os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))]
    total = 0
    for r in roots:
        if r.lower().endswith(".zip"):
            hits, n = scan_zip(r), 1
        elif os.path.isfile(r):
            hits, n = scan_text(os.path.basename(r), open(r, encoding="utf-8", errors="replace").read()), 1
        else:
            n, hits = scan_path(r)
        for h in hits:
            print(f"{h[2]:42} {h[0]}:{h[1]}  {h[3]}")
        print(f"{r}: scanned {n} files, {len(hits)} potential secrets")
        total += len(hits)
    sys.exit(1 if total else 0)
