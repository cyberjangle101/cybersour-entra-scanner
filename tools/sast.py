"""Small AST-based static analyser with rules tuned to this code base (no install needed; CI also runs bandit).
Usage: python tools/sast.py [files...]   Exit 1 if any HIGH/MEDIUM finding remains."""
import ast, os, re, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DANGEROUS = {"eval": "HIGH", "exec": "HIGH", "compile": "MEDIUM", "__import__": "MEDIUM"}
DANGEROUS_ATTR = {("os", "system"): "HIGH", ("os", "popen"): "HIGH", ("pickle", "load"): "HIGH", ("pickle", "loads"): "HIGH",
                  ("marshal", "loads"): "HIGH", ("yaml", "load"): "MEDIUM", ("tempfile", "mktemp"): "MEDIUM",
                  ("subprocess", "Popen"): "MEDIUM", ("subprocess", "run"): "MEDIUM", ("subprocess", "call"): "MEDIUM",
                  ("subprocess", "check_output"): "MEDIUM", ("hashlib", "md5"): "LOW", ("hashlib", "sha1"): "LOW",
                  ("random", "random"): "INFO", ("xml.etree.ElementTree", "parse"): "MEDIUM"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request"}
SECRETISH = re.compile(r"(?i)secret|token|password|passwd|credential|private_key|client_secret")
REDOS = re.compile(r"\((?:[^()]*[+*])\)[+*]|\(\.\*\)[+*]|\(\.\+\)[+*]")


def name_of(n):
    if isinstance(n, ast.Name):
        return n.id
    if isinstance(n, ast.Attribute):
        base = name_of(n.value)
        return f"{base}.{n.attr}" if base else n.attr
    return ""


def analyse(path):
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    rel = os.path.relpath(path, ROOT)
    out = []
    add = lambda sev, rule, node, msg: out.append((sev, rule, f"{rel}:{node.lineno}", msg))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = name_of(node.func)
            if fn in DANGEROUS:
                add(DANGEROUS[fn], "dangerous-call", node, f"{fn}()")
            base, _, attr = fn.rpartition(".")
            if (base, attr) in DANGEROUS_ATTR:
                add(DANGEROUS_ATTR[(base, attr)], "dangerous-call", node, fn + "()")
            kws = {k.arg: k.value for k in node.keywords}
            if attr in HTTP_METHODS and base in ("requests", "self.s", "self.session", "session", "urllib.request"):
                if "timeout" not in kws:
                    add("MEDIUM", "http-no-timeout", node, f"{fn}() without timeout (can hang forever)")
                v = kws.get("verify")
                if isinstance(v, ast.Constant) and v.value is False:
                    add("HIGH", "tls-verify-disabled", node, f"{fn}(verify=False)")
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                add("HIGH", "shell-true", node, "shell=True")
            if fn in ("print", "log", "logging.info", "logging.debug", "logging.warning", "logging.error"):
                for a in node.args:
                    for sub in ast.walk(a):
                        if isinstance(sub, ast.Name) and SECRETISH.search(sub.id) and "secret" in sub.id.lower() + sub.id.lower():
                            add("MEDIUM", "secret-in-log", node, f"{fn}() prints variable '{sub.id}'")
            if fn in ("webbrowser.open", "os.startfile") and node.args and not isinstance(node.args[0], ast.Constant):
                add("INFO", "open-nonliteral", node, f"{fn}() with a computed argument: confirm it is validated")
            if fn == "open" and len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and "w" in str(node.args[1].value):
                add("INFO", "file-write", node, "open(..., 'w'): confirm the path is trusted and permissions are right")
            if fn in ("re.compile", "re.match", "re.search", "re.fullmatch", "re.sub", "re.findall") and node.args:
                a = node.args[0]
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and REDOS.search(a.value):
                    add("MEDIUM", "regex-redos", node, f"possible catastrophic backtracking: {a.value[:50]}")
        if isinstance(node, ast.ExceptHandler):
            broad = node.type is None or name_of(node.type) in ("Exception", "BaseException")
            silent = all(isinstance(b, (ast.Pass, ast.Continue)) for b in node.body)
            if node.type is None:
                add("MEDIUM", "bare-except", node, "bare except")
            elif broad and silent:
                add("INFO", "swallowed-exception", node, "broad except that silently continues")
        if isinstance(node, ast.Assert) and "tests" not in rel:
            add("LOW", "assert-in-prod", node, "assert is stripped under python -O; do not use it for validation")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.args.defaults + [x for x in node.args.kw_defaults if x]:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    add("LOW", "mutable-default", node, f"{node.name}() has a mutable default argument")
        if isinstance(node, ast.Call) and name_of(node.func).endswith((".get", ".get_all", ".post", ".invoke")) and node.args:
            a = node.args[0]
            if isinstance(a, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in a.values):
                add("INFO", "unescaped-path-segment", node, "request path built from a variable (is it URL-quoted / from a trusted API?)")
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and SECRETISH.search(t.id) and isinstance(node.value, ast.Constant) \
                        and isinstance(node.value.value, str) and len(node.value.value) > 7 and not node.value.value.startswith(("http", "/", "AZURE_")):
                    add("HIGH", "hardcoded-secret", node, f"{t.id} assigned a string literal")
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "-v"]
    def walk(d):
        for base, _dirs, names in os.walk(os.path.join(ROOT, d)):
            if "__pycache__" not in base:
                yield from (os.path.join(base, n) for n in names if n.endswith(".py"))
    files = args or [f for d in ("entra_scan", "tools", "tests") for f in walk(d)] + [os.path.join(ROOT, n) for n in ("entra_posture_scan.py", "entra_posture_gui.py")]
    allf = []
    for f in files:
        allf += analyse(f)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    counts = {}
    for sev, rule, loc, msg in sorted(allf, key=lambda x: (order[x[0]], x[1], x[2])):
        counts[(sev, rule)] = counts.get((sev, rule), 0) + 1
        if sev != "INFO" or "-v" in sys.argv:
            print(f"{sev:6} {rule:22} {loc:38} {msg}")
    print("\nsummary:", {f"{s}/{r}": n for (s, r), n in sorted(counts.items(), key=lambda x: order[x[0][0]])})
    sys.exit(1 if any(s in ("HIGH", "MEDIUM") for s, *_ in allf) else 0)
