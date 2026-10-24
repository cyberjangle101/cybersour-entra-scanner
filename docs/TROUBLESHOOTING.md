# Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `Settings problem: Tenant and client ID are required` | Missing `--tenant` / `--client-id` | Pass them or set `AZURE_TENANT_ID` / `AZURE_CLIENT_ID`. |
| `AADSTS7000215 invalid client secret` | Wrong secret value (you copied the secret *ID*) or expired secret | Create a new secret and copy its **Value**. |
| `AADSTS700016 application not found` | Wrong client ID or tenant | Check both on the app registration's Overview page. |
| Check shows **SKIPPED**, "403 Authorization_RequestDenied" | Permission missing or admin consent not granted | The finding names the permission (`Needs permission:`). Add it, click *Grant admin consent*. |
| Conditional Access / sign-in checks SKIPPED, message mentions *premium* or *licence* | Tenant has no Entra ID P1 / P2 | Expected; those controls cannot be read without the licence. Not a pass. |
| `ERROR` finding "UnexpectedResponse" | Graph (or a proxy) returned something that is not a JSON object | Re-run; if it persists check proxy/TLS inspection. |
| `ERROR` finding with a Python exception name | A check met data in a shape it did not expect | The scan continues. Report the finding ID and the message; the JSON report holds the details. |
| Scan is slow on a big tenant | Throttling (HTTP 429) - the client waits as Graph asks | Use `--max-users 20000` or `--areas` to scan part of the tenant. |
| Coverage below 100% | Some checks were skipped or errored | See the *Skipped / errors* filter in the report. |
| `A .pfx must be converted` | Only PEM private keys are supported | `openssl pkcs12 -in cert.pfx -nodes -nocerts -out key.pem` |
