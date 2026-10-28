# echov/severity.py
"""Single source of truth for CVSS-based severity classification.

Scanners, triage, Oracle, the dashboard, and reports all import from here so
labels, ordering, colors, and CVSS banding stay in lockstep. Bands follow the
official CVSS v3.1 qualitative severity rating scale (FIRST.org spec, sec. 5).
"""
from __future__ import annotations

# (label, inclusive_low, inclusive_high) per the CVSS v3.1 rating scale.
CVSS_BANDS = [
    ("none",     0.0, 0.0),
    ("low",      0.1, 3.9),
    ("medium",   4.0, 6.9),
    ("high",     7.0, 8.9),
    ("critical", 9.0, 10.0),
]

# Canonical order, least to most severe. "info" is our alias for CVSS "none".
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

# Display colors. Critical is a deep crimson: hotter than high, and
# deliberately NOT Oracle purple (which marks reasoning / OWASP classes).
SEVERITY_COLOR = {
    "critical": "#c01030",  # deep crimson
    "high":     "#f2606a",  # red
    "medium":   "#f2b24c",  # amber
    "low":      "#fdd835",  # yellow
    "info":     "#6b7280",  # gray
}

# Relative weights for scoring / donut math.
SEVERITY_WEIGHT = {"critical": 40, "high": 10, "medium": 3, "low": 1, "info": 0}

_ALIASES = {"none": "info", "informational": "info", "unknown": "info", "": "info"}


def normalize_severity(label):
    """Coerce any label to one of SEVERITY_ORDER."""
    if label is None:
        return "info"
    key = _ALIASES.get(str(label).strip().lower(), str(label).strip().lower())
    return key if key in SEVERITY_RANK else "info"


def severity_from_cvss(score):
    """Map a CVSS base score to a band, or None if not scorable."""
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s < 0 or s > 10:
        return None
    if s == 0.0:
        return "info"
    for label, lo, hi in CVSS_BANDS:
        if label != "none" and lo <= s <= hi:
            return label
    return None


def classify(cvss_score=None, label=None):
    """Prefer a CVSS-derived band; fall back to a normalized label."""
    derived = severity_from_cvss(cvss_score)
    return derived if derived is not None else normalize_severity(label)


def max_severity(labels):
    """Most severe label in an iterable, or 'info' if empty."""
    best = "info"
    for lbl in labels:
        n = normalize_severity(lbl)
        if SEVERITY_RANK[n] > SEVERITY_RANK[best]:
            best = n
    return best
