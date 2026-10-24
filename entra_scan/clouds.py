"""Cloud environments. Commercial and GCC (Moderate) use the global endpoints; GCC High, DoD and China have their own.

Everything that differs between clouds lives here, so the Graph client and the sign-in code never hard-code a host.
Microsoft Learn links are the same in every cloud.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import ConfigError


@dataclass(frozen=True)
class Cloud:
    """Endpoints for one Microsoft cloud."""
    name: str
    graph_host: str           # host that serves Microsoft Graph
    login_host: str           # host that issues tokens (Entra ID)
    vault_suffix: str         # DNS suffix of Azure Key Vault in this cloud

    @property
    def graph_url(self):
        """Base URL for Graph v1.0 requests."""
        return f"https://{self.graph_host}/v1.0"

    @property
    def authority(self):
        """Token authority prefix (the tenant is appended)."""
        return f"https://{self.login_host}"

    @property
    def scope(self):
        """The '.default' scope MSAL asks for: all application permissions consented to the app."""
        return f"https://{self.graph_host}/.default"


CLOUDS = {
    "commercial": Cloud("commercial", "graph.microsoft.com", "login.microsoftonline.com", "vault.azure.net"),
    "usgov": Cloud("usgov", "graph.microsoft.us", "login.microsoftonline.us", "vault.usgovcloudapi.net"),            # GCC High
    "usgovdod": Cloud("usgovdod", "dod-graph.microsoft.us", "login.microsoftonline.us", "vault.usgovcloudapi.net"),  # DoD
    "china": Cloud("china", "microsoftgraph.chinacloudapi.cn", "login.chinacloudapi.cn", "vault.azure.cn"),         # 21Vianet
}


def get_cloud(name):
    """Look a cloud up by name. Unknown names are a configuration error, never a silent fallback to commercial."""
    try:
        return CLOUDS[str(name or "commercial").lower()]
    except KeyError:
        raise ConfigError(f"Unknown cloud {name!r}. Choose one of: {', '.join(CLOUDS)}.") from None
