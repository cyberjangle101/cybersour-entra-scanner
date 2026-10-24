# Security notes
* Read-only: HTTP GET only; no write permission is requested.
* Credentials: never accepted as a command-line value; held in memory; GUI never saves them; no secrets in reports or logs.
* Network: the Graph client refuses any host other than graph.microsoft.com, does not follow redirects, and caps pagination.
* Output: HTML is escaped and CSP-protected; CSV neutralises formula injection; files are created owner-only (0600).
* Report vulnerabilities privately to the repository owner.
