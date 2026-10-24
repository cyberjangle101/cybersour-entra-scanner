"""Entra ID Posture Scanner: a read-only security-posture scan of a Microsoft Entra ID tenant.

Everything the scanner does is an HTTP GET against Microsoft Graph v1.0. Nothing in the tenant is ever changed.
Layout (read in this order if you are new to the code):

  models.py       what a finding is, plus small helpers shared by every check
  graph.py        the Microsoft Graph HTTP client (paging, retries, safety rules)
  auth.py         turns a client secret or certificate into access tokens
  permissions.py  the Graph permissions the app needs, and which check uses which
  checks/         one file per area of Entra (Conditional Access, roles, users, ...)
  metadata.py     per-finding extras: Microsoft Learn link, "setting checked", CIS reference
  report.py       HTML / JSON / CSV output
  runner.py       runs every check in isolation and works out coverage
  cli.py / gui.py the two front ends
"""
__version__ = "1.1.0"
