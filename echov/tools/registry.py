"""Registry of READ-ONLY detection/recon tools. Each module exposes NAME,
CATEGORY, BINARIES, run(target, workdir) -> normalized dict, and optionally
OPT_IN=True (noisy/active tools that only run when explicitly requested).
Nothing here sends attack traffic."""
from __future__ import annotations
from echov.tools import whatweb, wafw00f, testssl, headers, dnsrecon, nikto

_ALL = (whatweb, wafw00f, testssl, headers, dnsrecon, nikto)
TOOLS = {m.NAME: m for m in _ALL}
# tools that run by default (opt-in ones excluded unless named explicitly)
DEFAULT_TOOLS = [m.NAME for m in _ALL if not getattr(m, "OPT_IN", False)]
OPT_IN_TOOLS = [m.NAME for m in _ALL if getattr(m, "OPT_IN", False)]
