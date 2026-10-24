"""All checks. Importing this package registers every check with models.CHECKS (via the @check decorator)."""
from . import (apps, authn, conditional_access, devices, extended, governance, groups,  # noqa: F401
               identity_protection, manual, privileged, tenant, users)
