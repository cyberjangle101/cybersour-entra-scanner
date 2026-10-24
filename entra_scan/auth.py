"""Sign-in: turns a credential into Microsoft Graph access tokens. Only app-only sign-in is supported (no device code, no interactive).

Methods (--auth):
  secret            client secret               (secret/cert are the classic app-registration credentials)
  cert              certificate private key
  federated         workload identity federation: a short-lived OIDC token from GitHub Actions, Kubernetes, etc. is exchanged for a
                    Graph token. NO long-lived secret exists anywhere. (Recommended for CI.)
  managed-identity  the Azure resource's own identity (VM, Function, Automation, Container Apps). NO credential at all.
Key Vault: --keyvault-secret <secret URL> reads the client secret at run time using the managed identity.

Where secrets can come from (never from a command-line value; argv is visible to other users and shell history):
  AZURE_CLIENT_SECRET env var  |  --prompt-secret (typed hidden)  |  --secret-stdin  |  --client-secret-file
Secrets live in memory only. Nothing in this module writes a credential anywhere.
"""
from __future__ import annotations

import getpass
import os
import re
import sys
from pathlib import Path

import msal
import requests

from .clouds import Cloud, get_cloud
from .models import ConfigError

GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]      # commercial default; other clouds use Cloud.scope
FEDERATED_AUDIENCE = {"commercial": "api://AzureADTokenExchange", "usgov": "api://AzureADTokenExchangeUSGov",
                      "usgovdod": "api://AzureADTokenExchangeUSGov", "china": "api://AzureADTokenExchangeChina"}
GITHUB_OIDC_HOST_SUFFIX = ".actions.githubusercontent.com"
AUTH_METHODS = ("secret", "cert", "federated", "managed-identity")
# A tenant is either a GUID or a domain name. Anything else is rejected before it can reach a URL.
_TENANT_RX = re.compile(r"^([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,63})$")
_CLIENT_RX = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")

HOW_TO_SUPPLY_IT = (
    "Provide it with one of: the AZURE_CLIENT_SECRET environment variable, --prompt-secret (typed hidden), "
    "--secret-stdin, --client-secret-file or --keyvault-secret. (There is deliberately no --client-secret <value> flag: command-line "
    "arguments are visible to other users and stay in shell history.)")


def first_line(text, n=300):
    """First line of an error message, trimmed. MSAL errors can be multi-line and very long."""
    return (str(text or "").strip().splitlines() or ["no detail"])[0][:n]


def read_secret_file(path):
    """First non-empty line of a file. Warns (does not fail) if other users can read the file."""
    try:
        st = os.stat(path)
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"Cannot read the secret file: {type(e).__name__}")
    if os.name == "posix" and st.st_mode & 0o077:
        print(f"warning: {path} is readable by other users; restrict it (chmod 600).", file=sys.stderr)
    line = next((x.strip() for x in text.splitlines() if x.strip()), "")
    if not line:
        raise ConfigError("The secret file is empty.")
    return line


def is_interactive(stream):
    """True if a person can type into `stream`, so a hidden prompt can be answered.

    On Windows, NUL (the stdin of scheduled tasks, services and many CI runners) is a character device, so isatty() is True,
    yet nobody can answer there and getpass, which reads the console directly, would wait forever.  A real console is told
    apart by GetConsoleMode, which fails for NUL.
    """
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):             # missing or closed stream
        return False
    if os.name != "nt":
        return True
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return True                                  # an in-memory stand-in that says it is a terminal (tests)
    import ctypes
    import msvcrt
    try:
        return bool(ctypes.windll.kernel32.GetConsoleMode(msvcrt.get_osfhandle(fd), ctypes.byref(ctypes.c_ulong())))
    except OSError:
        return False


def resolve_credentials(args, environ=None, stdin=None, prompt=None, is_tty=None):
    """CLI only: gather the secret (or key passphrase) from a safe source and store it on `args` (memory only)."""
    environ = os.environ if environ is None else environ
    stdin = sys.stdin if stdin is None else stdin
    prompt = prompt or getpass.getpass
    tty = is_interactive(stdin) if is_tty is None else is_tty

    if args.auth == "secret":
        chosen = [n for n, on in (("--secret-stdin", args.secret_stdin), ("--client-secret-file", bool(args.client_secret_file)),
                                  ("--prompt-secret", args.prompt_secret)) if on]
        if len(chosen) > 1:
            raise ConfigError("Use only one of --secret-stdin, --client-secret-file and --prompt-secret.")
        if args.secret_stdin:
            secret = (stdin.readline() or "").strip()
        elif args.client_secret_file:
            secret = read_secret_file(args.client_secret_file)
        elif args.prompt_secret:
            secret = prompt("Client secret (input hidden): ")
        elif environ.get("AZURE_CLIENT_SECRET") or getattr(args, "keyvault_secret", None):
            return                                   # env var / Key Vault are read later by build_token_provider
        elif tty:
            secret = prompt("Client secret (input hidden): ")        # a person is at the keyboard: just ask
        else:
            return                                   # unattended and nothing supplied: build_token_provider explains
        if not (secret or "").strip():
            raise ConfigError("The client secret is empty.")
        args.client_secret = secret.strip()

    elif args.auth == "cert":
        if args.prompt_passphrase:
            args.cert_passphrase = prompt("Private key passphrase (input hidden): ")
        elif not environ.get("AZURE_CLIENT_CERT_PASSPHRASE") and tty:
            path = args.cert_path or environ.get("AZURE_CLIENT_CERT_PATH")
            try:
                encrypted = bool(path) and "ENCRYPTED PRIVATE KEY" in Path(path).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                encrypted = False
            if encrypted:
                args.cert_passphrase = prompt("Private key passphrase (input hidden): ")


def _certificate_credential(args, opt):
    """Build the MSAL credential dict from a PEM private key file + SHA-1 thumbprint."""
    path, thumb = opt("cert_path", "AZURE_CLIENT_CERT_PATH"), opt("cert_thumbprint", "AZURE_CLIENT_CERT_THUMBPRINT")
    if not path or not thumb:
        raise ConfigError("Certificate auth needs a PEM private key file and the certificate's SHA-1 thumbprint: "
                          "--cert-path and --cert-thumbprint (or AZURE_CLIENT_CERT_PATH / AZURE_CLIENT_CERT_THUMBPRINT).")
    try:
        pem = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError("Cannot read the certificate private key as a PEM text file "
                          f"({type(e).__name__}). A .pfx must be converted first, for example: "
                          "openssl pkcs12 -in cert.pfx -nodes -nocerts -out key.pem")
    if "PRIVATE KEY" not in pem:
        raise ConfigError("The certificate file does not contain a PEM private key (-----BEGIN ... PRIVATE KEY-----).")
    thumb = thumb.replace(":", "").replace(" ", "")
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", thumb):
        raise ConfigError("Use the certificate's SHA-1 thumbprint (40 hex characters, shown in Entra > Certificates & secrets).")
    cred = {"private_key": pem, "thumbprint": thumb}
    if "ENCRYPTED PRIVATE KEY" in pem:
        phrase = opt("cert_passphrase", "AZURE_CLIENT_CERT_PASSPHRASE")
        if not phrase:
            raise ConfigError("The private key is encrypted: use --prompt-passphrase or set AZURE_CLIENT_CERT_PASSPHRASE "
                              "(there is deliberately no passphrase value flag).")
        cred["passphrase"] = phrase
    return cred


def _session(args):
    """requests session honouring --proxy / --ca-bundle (used for token endpoints that are not MSAL's own)."""
    sess = requests.Session()
    if getattr(args, "proxy", None):
        sess.proxies = {"https": args.proxy, "http": args.proxy}
    if getattr(args, "ca_bundle", None):
        sess.verify = args.ca_bundle
    return sess


def read_federated_assertion(args, environ=None, session=None, cloud=None):
    """Fetch the OIDC token to exchange for a Graph token. Called again for every token request, so rotation just works.

    Sources, in order: --federated-token-file / AZURE_FEDERATED_TOKEN_FILE (Kubernetes / Azure workload identity style),
    then GitHub Actions (ACTIONS_ID_TOKEN_REQUEST_URL + ACTIONS_ID_TOKEN_REQUEST_TOKEN, which need `permissions: id-token: write`).
    """
    environ = os.environ if environ is None else environ
    cloud = cloud or get_cloud(getattr(args, "cloud", None))
    path = getattr(args, "federated_token_file", None) or environ.get("AZURE_FEDERATED_TOKEN_FILE")
    if path:
        try:
            token = Path(path).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError, ValueError) as e:        # ValueError: embedded NUL byte in the path
            raise ConfigError(f"Cannot read the federated token file: {type(e).__name__}") from None
        if not token:
            raise ConfigError("The federated token file is empty.")
        return token
    url, bearer = environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if url and bearer:
        host = (re.match(r"^https://([^/:@]+)(?:[:/]|$)", url) or [None, ""])[1].lower()
        if not host.endswith(GITHUB_OIDC_HOST_SUFFIX):                  # never send the runner token to an arbitrary host
            raise ConfigError("ACTIONS_ID_TOKEN_REQUEST_URL is not a GitHub Actions address; refusing to use it.")
        audience = getattr(args, "federated_audience", None) or FEDERATED_AUDIENCE[cloud.name]
        sess = session or _session(args)
        try:
            r = sess.get(url + ("&" if "?" in url else "?") + "audience=" + requests.utils.quote(audience, safe=""),
                         headers={"Authorization": f"Bearer {bearer}"}, timeout=30, allow_redirects=False)
            token = r.json().get("value")
        except (requests.RequestException, ValueError, AttributeError) as e:
            raise ConfigError(f"Could not obtain the GitHub OIDC token: {type(e).__name__}") from None
        if r.status_code != 200 or not token:
            raise ConfigError(f"GitHub did not issue an OIDC token (HTTP {r.status_code}). Does the job have 'permissions: id-token: write'?")
        return token
    raise ConfigError("Federated sign-in needs --federated-token-file (or AZURE_FEDERATED_TOKEN_FILE), or a GitHub Actions job with "
                      "'permissions: id-token: write'.")


def _managed_identity_client(args):
    """MSAL managed-identity client: system-assigned by default, user-assigned when --client-id is given."""
    client_id = getattr(args, "client_id", None) or os.environ.get("AZURE_CLIENT_ID")
    if client_id:
        if not _CLIENT_RX.match(str(client_id).strip()):
            raise ConfigError("--client-id must be the managed identity's client ID (a GUID).")
        ident = msal.UserAssignedManagedIdentity(client_id=str(client_id).strip())
    else:
        ident = msal.SystemAssignedManagedIdentity()
    return msal.ManagedIdentityClient(ident, http_client=_session(args))


def fetch_keyvault_secret(url, args, mi_client=None, session=None):
    """Read one secret's value from Azure Key Vault using the managed identity. The URL must be a vault in the chosen cloud."""
    cloud = get_cloud(getattr(args, "cloud", None))
    m = re.match(r"^https://([a-z0-9-]{3,24})\." + re.escape(cloud.vault_suffix) + r"/secrets/([A-Za-z0-9-]{1,127})(?:/([0-9a-f]{32}))?/?$", str(url))
    if not m:
        raise ConfigError(f"--keyvault-secret must look like https://<vault>.{cloud.vault_suffix}/secrets/<name>.")
    mi = mi_client or _managed_identity_client(args)
    tok = mi.acquire_token_for_client(resource=f"https://{cloud.vault_suffix}")
    if "access_token" not in tok:
        raise ConfigError(f"Managed identity could not get a Key Vault token: {first_line(tok.get('error_description') or tok.get('error'))}. "
                          "Key Vault lookup only works on an Azure resource with a managed identity.")
    sess = session or _session(args)
    try:
        r = sess.get(str(url).rstrip("/") + "?api-version=7.4", headers={"Authorization": f"Bearer {tok['access_token']}"}, timeout=30,
                     allow_redirects=False)
        value = r.json().get("value")
    except (requests.RequestException, ValueError, AttributeError) as e:
        raise ConfigError(f"Key Vault request failed: {type(e).__name__}") from None
    if r.status_code != 200 or not value:
        raise ConfigError(f"Key Vault returned HTTP {r.status_code}. The identity needs 'Key Vault Secrets User' on that secret.")
    return str(value).strip()


def build_token_provider(args):
    """Validate the settings and return `provider()`, a function that yields a fresh Graph access token.

    `args` carries cloud, auth, tenant, client_id and the credential fields for that method (environment variables are the fallback).
    """
    def opt(name, env):
        """Read a setting from the parsed arguments, falling back to its environment variable."""
        return getattr(args, name, None) or os.environ.get(env)

    cloud: Cloud = get_cloud(getattr(args, "cloud", None))
    method = getattr(args, "auth", None) or "secret"
    if method not in AUTH_METHODS:
        raise ConfigError(f"Sign-in method must be one of: {', '.join(AUTH_METHODS)}.")
    net = {"proxies": ({"https": args.proxy, "http": args.proxy} if getattr(args, "proxy", None) else None),
           "verify": getattr(args, "ca_bundle", None) or True, "timeout": getattr(args, "timeout", None) or 60}

    if method == "managed-identity":
        mi = _managed_identity_client(args)

        def mi_provider():
            """Token for Graph from the Azure resource's managed identity."""
            result = mi.acquire_token_for_client(resource=f"https://{cloud.graph_host}")
            if "access_token" not in result:
                raise ConfigError(f"Managed identity token request failed: {first_line(result.get('error_description') or result.get('error'))}. "
                                  "This only works on an Azure resource that has a managed identity with Graph app roles assigned.")
            return result["access_token"]
        return mi_provider

    tenant, client_id = opt("tenant", "AZURE_TENANT_ID"), opt("client_id", "AZURE_CLIENT_ID")
    if not tenant or not client_id:
        raise ConfigError("Tenant and client ID are required (or set AZURE_TENANT_ID / AZURE_CLIENT_ID).")
    if not _TENANT_RX.match(str(tenant)):
        raise ConfigError("Tenant must be the tenant ID (a GUID) or a domain such as contoso.onmicrosoft.com.")
    if not _CLIENT_RX.match(str(client_id).strip()):
        raise ConfigError("Client ID must be the application (client) ID, a GUID.")

    if method == "cert":
        credential = _certificate_credential(args, opt)
    elif method == "federated":
        read_federated_assertion(args, cloud=cloud)               # fail fast with a clear message if no token source exists
        credential = {"client_assertion": lambda: read_federated_assertion(args, cloud=cloud)}
    else:
        credential = opt("client_secret", "AZURE_CLIENT_SECRET")
        if not credential and getattr(args, "keyvault_secret", None):
            credential = fetch_keyvault_secret(args.keyvault_secret, args)
        if not credential:
            raise ConfigError("A client secret is required. " + HOW_TO_SUPPLY_IT)

    app = msal.ConfidentialClientApplication(
        str(client_id).strip(), authority=f"{cloud.authority}/{tenant}", client_credential=credential, **net)

    def provider():
        """Return a valid access token (MSAL serves it from its cache until shortly before expiry)."""
        result = app.acquire_token_for_client(scopes=[cloud.scope])      # MSAL caches the token until it nears expiry
        if "access_token" not in result:
            raise ConfigError(f"Token request failed: {first_line(result.get('error_description') or result.get('error'))}")
        return result["access_token"]

    return provider
