"""Fuzzing of every input the app accepts.  Run: python tests/fuzz.py [iterations] [seed]

Inputs fuzzed:
  1. Graph API responses  - every endpoint answer is replaced by hostile / wrongly-typed data (the tenant is untrusted input).
  2. Command-line arguments - random flags and values; must exit with a clean code and never a traceback.
  3. GUI form values       - random types and strings into build_args().
  4. Helper functions      - seg/num/parse_time/csv_safe/ref/sample/trusted_url/retry_after/first_line/read_secret_file.
  5. Report writers        - random strings in every finding field -> HTML must stay escaped, CSV must stay formula-safe.
  6. Credential sources    - random stdin / file contents.
  7. User-supplied JSON files (policy, accepted risks, baseline, batch) and the federated / Key Vault inputs.
Pass criteria: no unhandled exception escapes, no ERROR caused by hostile *shape* is left silent (counted and listed), no payload reaches the HTML unescaped.
"""
import contextlib, io, os, random, string, sys, tempfile, time, copy, csv
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from entra_scan import auth, batch, cli, context, export, gui, graph, postprocess, report, runner
from entra_scan.models import ConfigError, Finding, GraphError, num, parse_time, ref, sample, seg
from fake_tenant import Args, FakeGraph, bad_tenant, good_tenant

csv.field_size_limit(10**8)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 300
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
R = random.Random(SEED)
problems, stats = [], {}

PAYLOADS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "'; DROP TABLE x;--", "=cmd|' /C calc'!A0", "@SUM(1+1)", "+1+1", "-2+3",
            "{{7*7}}", "${jndi:ldap://x}", "../../etc/passwd", "\x00\x01\x02", "A" * 100000, "‮⁦evil", "💥" * 50, "%s%n%x", "\r\nSet-Cookie: x=1", "", " ", "null"]


def junk(depth=0):
    c = R.random()
    if depth > 3 or c < 0.35:
        return R.choice([None, True, False, 0, -1, 1.5, float("nan"), float("inf"), 10**30, "", R.choice(PAYLOADS),
                         "".join(R.choice(string.printable) for _ in range(R.randint(0, 40)))])
    if c < 0.6:
        return [junk(depth + 1) for _ in range(R.randint(0, 4))]
    return {R.choice(["id", "value", "state", "displayName", "isEnabled", "userType", "conditions", "grantControls", "rules", "setting", "scope",
                      "appRoleId", "principalId", "clientId", "scope", "signInActivity", "assignedLicenses", "values", "name"] + PAYLOADS[:3]): junk(depth + 1)
            for _ in range(R.randint(0, 5))}


def mutate_value(v):
    """Hostile variant of a plausible response: keep the shape sometimes, corrupt one field, or replace entirely."""
    c = R.random()
    if c < 0.25:
        return junk()
    if c < 0.45:
        return {"value": [junk() for _ in range(R.randint(0, 4))]}
    v = copy.deepcopy(v)
    def walk(x):
        if isinstance(x, dict) and x:
            k = R.choice(list(x))
            x[k] = junk() if R.random() < 0.5 else walk(x[k])
        elif isinstance(x, list) and x:
            i = R.randrange(len(x))
            x[i] = junk() if R.random() < 0.5 else walk(x[i])
            return x
        else:
            return junk()
        return x
    for _ in range(R.randint(1, 3)):
        v = walk(v)
    return v


def fuzz_api():
    errs = {}
    for n in range(N):
        t = (good_tenant if n % 2 else bad_tenant)()
        for p in R.sample([k for k in t if not callable(t[k]) and not isinstance(t[k], Exception)], R.randint(1, 6)):
            t[p] = mutate_value(t[p])
        if R.random() < 0.2:
            t[R.choice(list(t))] = GraphError(R.choice([400, 401, 403, 404, 429, 500]), "x", R.choice(PAYLOADS)[:50], "u")
        try:
            f = runner.run_scan(context.Ctx(FakeGraph(t), Args()), None, log=lambda *_: None)
            runner.scan_coverage(f)
            f, extras = postprocess.finalize(f, runner.AREAS)
            report.render_html({"t": "x"}, f, runner.AREAS, extras["summary"], {"new": [x.id for x in f[:2]], "resolved": [], "changed": [], "not_run_now": []})
            export.sarif_text({"tenant": "x"}, f)
            export.junit_text({}, f, runner.AREAS)
            for x in f:
                if x.status == "ERROR":
                    errs.setdefault(x.id, []).append(x.detail[:110])
        except BaseException as e:           # the scan itself must never raise
            problems.append(f"API fuzz #{n}: scan crashed {type(e).__name__}: {e}")
    stats["api_iterations"] = N
    stats["api_check_errors"] = {k: (len(v), v[0]) for k, v in errs.items()}


def fuzz_cli():
    flags = ["--tenant", "--client-id", "--auth", "--areas", "--max-users", "--output-dir", "--fail-on", "--min-coverage", "--client-secret",
             "--client-secret-file", "--cert-path", "--cert-thumbprint", "--prompt-secret", "--secret-stdin", "--csv", "--list-checks", "--bogus",
             "--list-permissions", "--version", "-h", "--cloud", "--proxy", "--timeout", "--check-timeout", "--max-runtime", "--sarif", "--junit",
             "--verbose", "--federated-audience", "--keyvault-secret"]
    ok = 0
    for n in range(N):
        argv = []
        for _ in range(R.randint(0, 6)):
            argv.append(R.choice(flags))
            if R.random() < 0.7:
                argv.append(R.choice(PAYLOADS + ["ca", "high", "secret", "cert", "5", "-1", "0", "99999999999999999999"])[:300])
        canary = None
        for i, a in enumerate(argv[:-1]):                 # give every --client-secret value a unique marker so an echo is unmistakable
            if a == "--client-secret" and argv[i + 1] not in flags:
                canary = argv[i + 1] = f"CANARY{R.getrandbits(48):x}"
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                os.environ.pop("AZURE_CLIENT_SECRET", None)
                saved = sys.stdin; sys.stdin = io.StringIO(R.choice(PAYLOADS) + "\n")
                try:
                    rc = cli.main(argv)
                finally:
                    sys.stdin = saved
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 2
        except BaseException as e:
            problems.append(f"CLI fuzz {argv[:6]!r}: uncaught {type(e).__name__}: {e}"); continue
        if rc not in (0, 1, 2, 3, 130) or "Traceback" in err.getvalue():
            problems.append(f"CLI fuzz {argv[:6]!r}: rc={rc} {err.getvalue()[-150:]}")
        # a secret value on the command line must be refused and never echoed
        if canary and canary in out.getvalue() + err.getvalue():
            problems.append(f"CLI fuzz echoed a secret-flag value: {argv[:6]!r}")
        ok += 1
    stats["cli_iterations"] = ok


def fuzz_files():
    """Policy, suppression, baseline and batch files are user-supplied: garbage must give ConfigError, never a crash or a hang."""
    d = tempfile.mkdtemp()
    shapes = [lambda: junk(), lambda: {"disable": junk(), "severity": junk()}, lambda: [{"id": junk(), "owner": junk(), "reason": junk(), "expires": junk()}],
              lambda: {"tenants": junk(), "defaults": junk()}, lambda: {"findings": junk()}, lambda: [dict(id="ADM-001", owner="o", reason="r", expires=R.choice(PAYLOADS + ["2030-01-01", "0000-00-00"]))],
              lambda: {"tenants": [{"name": R.choice(PAYLOADS + ["ok"]), "tenant": "t", R.choice(["client_secret", "x", "cert_path"]): junk()}]}]
    import json as _json
    for n in range(N):
        path = os.path.join(d, f"f{n}.json")
        raw = R.choice([lambda: _json.dumps(R.choice(shapes)(), default=str), lambda: "".join(R.choice(string.printable) for _ in range(R.randint(0, 200))), lambda: ""])()
        open(path, "w", encoding="utf-8", errors="replace").write(raw)
        for loader in (postprocess.load_policy, postprocess.load_suppressions, postprocess.load_baseline, batch.load_batch):
            try:
                loader(path)
            except ConfigError:
                pass
            except BaseException as e:
                problems.append(f"file fuzz: {loader.__name__} crashed {type(e).__name__}: {e} on {raw[:80]!r}")
    for p in ("/nonexistent/x.json", d):                                  # missing file and a directory
        for loader in (postprocess.load_policy, postprocess.load_suppressions, postprocess.load_baseline, batch.load_batch):
            try:
                loader(p)
            except ConfigError:
                pass
            except BaseException as e:
                problems.append(f"file fuzz: {loader.__name__} crashed on {p}: {type(e).__name__}")
    # federated / Key Vault inputs
    for n in range(N):
        a = type("A", (), {"federated_token_file": R.choice(PAYLOADS + [None]), "cloud": R.choice(["commercial", "usgov", "bogus"]), "federated_audience": None,
                           "proxy": None, "ca_bundle": None})()
        try:
            auth.read_federated_assertion(a, environ={"ACTIONS_ID_TOKEN_REQUEST_URL": R.choice(PAYLOADS), "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"})
        except ConfigError:
            pass
        except BaseException as e:
            problems.append(f"federated fuzz: {type(e).__name__}: {e}")
        try:
            auth.fetch_keyvault_secret(R.choice(PAYLOADS + ["https://v.vault.azure.net/secrets/" + R.choice(PAYLOADS)]), a, mi_client=object())
        except ConfigError:
            pass
        except BaseException as e:
            problems.append(f"keyvault fuzz: {type(e).__name__}: {e}")
    stats["file_iterations"] = N


def fuzz_gui_form():
    keys = list(runner.AREAS)
    for n in range(N):
        form = {k: junk() for k in ("auth", "tenant", "client_id", "secret", "cert_path", "cert_thumbprint", "output_dir", "max_users", "areas")}
        if R.random() < 0.5:
            form.update(auth=R.choice(["secret", "cert", "device"]), tenant=R.choice(PAYLOADS), client_id=R.choice(PAYLOADS), secret=R.choice(PAYLOADS),
                        areas={R.choice(keys + PAYLOADS[:2]): R.choice([True, False, 1, "x", None]) for _ in range(3)}, max_users=R.choice(["1", "-3", "x", 5, None, 2.5, "9" * 40]))
        try:
            a = gui.build_args(form if R.random() > 0.05 else junk(), keys)
            assert a.areas is None or all(x in keys for x in a.areas)
        except ValueError:
            pass
        except BaseException as e:
            problems.append(f"GUI form fuzz: {type(e).__name__}: {e} for {str(form)[:120]}")
    stats["gui_form_iterations"] = N


def fuzz_helpers():
    for n in range(N * 3):
        v = junk()
        for fn in (seg, num, parse_time, report.csv_safe, lambda x: ref(x, x), lambda x: sample(x if isinstance(x, list) else [x]),
                   lambda x: graph.retry_after({"Retry-After": x}, R.randint(0, 9)), auth.first_line, lambda x: graph.trusted_url(x)):
            try:
                fn(v)
            except (GraphError, ConfigError, ValueError, TypeError, AttributeError) as e:
                # TypeError/AttributeError from helpers are only acceptable where the caller guarantees a string; record for review
                if isinstance(e, (TypeError, AttributeError)) and fn in (seg, num, parse_time, report.csv_safe):
                    problems.append(f"helper {getattr(fn,'__name__','?')} raised {type(e).__name__} for {str(v)[:60]!r}")
            except BaseException as e:
                problems.append(f"helper {getattr(fn,'__name__','?')} raised {type(e).__name__}: {e} for {str(v)[:60]!r}")
    for u in ("http://graph.microsoft.com/v1.0", "https://graph.microsoft.com.evil.com/x", "https://evil.com/graph.microsoft.com", "https://user:pw@graph.microsoft.com/x",
              "https://graph.microsoft.com@evil.com/", "//graph.microsoft.com", "https://GRAPH.MICROSOFT.COM/v1.0", "ftp://graph.microsoft.com"):
        try:
            graph.trusted_url(u); accepted = True
        except GraphError:
            accepted = False
        if accepted != (u == "https://GRAPH.MICROSOFT.COM/v1.0"):
            problems.append(f"trusted_url wrong verdict for {u}")
    stats["helper_iterations"] = N * 3


def fuzz_report():
    for n in range(max(50, N // 3)):
        fs = []
        for _ in range(R.randint(1, 8)):
            P = lambda: R.choice(PAYLOADS)
            fs.append(Finding(P()[:20], R.choice(["ca", "roles", P()[:12]]), P(), R.choice(["FAIL", "WARN", "PASS", "INFO", "MANUAL", "SKIPPED", "ERROR", P()[:5]]),
                              R.choice(["critical", "high", "medium", "low", "info", P()[:5]]), P(), P(), [P(), P()], cis=P(), learn=R.choice([P(), "javascript:1", "https://learn.microsoft.com/a"]),
                              setting=P(), needs=P()))
        try:
            h = report.render_html({P_: R.choice(PAYLOADS) for P_ in ("tenant", "<b>k</b>")}, fs, runner.AREAS)
            body = h.split("<script nonce")[0]
            for bad in ("<script>alert(1)", "<img src=x", "javascript:1", "onerror=alert(1)>"):
                if bad in body.replace("&lt;", "<") and bad in h.replace("&lt;", "\0") and bad in body:
                    problems.append(f"report: unescaped payload {bad!r}")
            if h.count("<script nonce") != 1:
                problems.append("report: extra script tag")
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "f.csv"); report.export_csv(fs, p)
                for row in csv.reader(open(p, encoding="utf-8-sig", newline="")):
                    for c in row:
                        if c[:1] in ("=", "+", "-", "@", "\t", "\r"):
                            problems.append(f"csv formula cell {c[:30]!r}")
        except BaseException as e:
            problems.append(f"report fuzz: {type(e).__name__}: {e}")
    stats["report_iterations"] = max(50, N // 3)


def fuzz_credentials():
    class In:
        def __init__(s, t, tty=False): s.t, s.tty = t, tty
        def readline(s): return s.t.splitlines(True)[0] if s.t else ""
        def isatty(s): return s.tty
    for n in range(N):
        txt = R.choice(PAYLOADS) + R.choice(["", "\n", "\nx\n", "\r\n"])
        a = type("A", (), dict(auth=R.choice(["secret", "cert"]), secret_stdin=R.random() < .5, client_secret_file=None, prompt_secret=False,
                               prompt_passphrase=False, cert_path=None, cert_passphrase=None, client_secret=None))()
        with tempfile.TemporaryDirectory() as d:
            if R.random() < 0.4:
                f = os.path.join(d, "s"); open(f, "w", encoding="utf-8", errors="ignore").write(txt); os.chmod(f, R.choice([0o600, 0o644, 0o000]))
                a.client_secret_file = f
            try:
                auth.resolve_credentials(a, environ={}, stdin=In(txt), prompt=lambda m: txt)
            except ConfigError:
                pass
            except BaseException as e:
                problems.append(f"credential fuzz: {type(e).__name__}: {e}")
    stats["credential_iterations"] = N


if __name__ == "__main__":
    t0 = time.time()
    for fn in (fuzz_helpers, fuzz_credentials, fuzz_files, fuzz_gui_form, fuzz_report, fuzz_cli, fuzz_api):
        fn()
    print(f"seed={SEED} iterations={N} time={time.time()-t0:.1f}s")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"PROBLEMS: {len(problems)}")
    for p in problems[:40]:
        print("  -", p)
    sys.exit(1 if problems else 0)
