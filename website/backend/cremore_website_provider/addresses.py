"""Website address-policy compatibility path; decisions remain in fetch.py.

The pure address classifier is also used for credential-free provider export
redirects. Importing it performs no DNS resolution or network access.
"""

from cremore.network_addresses import INTERNAL, PUBLIC, allowed, classify

__all__ = ["INTERNAL", "PUBLIC", "allowed", "classify"]
