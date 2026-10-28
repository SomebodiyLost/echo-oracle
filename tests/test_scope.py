
import pytest
from echov.scope import ScopeGuard, normalize_host
from echov.models import Verdict


@pytest.fixture
def guard():
    return ScopeGuard(
        allow_domains=["localhost", "mylab.local"],
        allow_wildcards=["*.mylab.local"],
        allow_cidrs=["127.0.0.0/8"],
        deny_rules=["payments.mylab.local", "*.internal.mylab.local"],
        deny_cidrs=["10.0.0.0/8"],
    )
def test_uppercase_is_allowed(guard):
    assert v(guard, "APP.MYLAB.LOCAL") == Verdict.ALLOW

def test_trailing_dot_is_allowed(guard):
    assert v(guard, "app.mylab.local.") == Verdict.ALLOW

def test_ipv6_loopback(guard):
    # what SHOULD this be? ::1 isn't in your IPv4 CIDR...
    print(guard.check("::1").verdict)

def v(guard, host):
    return guard.check(host).verdict


def test_exact_domain_allowed(guard):
    assert v(guard, "localhost") == Verdict.ALLOW

def test_subdomain_of_wildcard_allowed(guard):
    assert v(guard, "app.mylab.local") == Verdict.ALLOW
    assert v(guard, "a.b.mylab.local") == Verdict.ALLOW

def test_ip_in_cidr_allowed(guard):
    assert v(guard, "127.0.0.1") == Verdict.ALLOW

def test_lookalike_domain_is_lead(guard):
    assert v(guard, "notmylab.local") == Verdict.LEAD

def test_suffix_trick_is_lead(guard):
    assert v(guard, "mylab.local.evil.com") == Verdict.LEAD

def test_wildcard_does_not_match_apex():
    g = ScopeGuard(["x"], ["*.example.com"], [], [], [])
    assert g.check("example.com").verdict == Verdict.LEAD
    assert g.check("foo.example.com").verdict == Verdict.ALLOW

def test_ip_outside_cidr_is_lead(guard):
    assert v(guard, "8.8.8.8") == Verdict.LEAD

def test_explicit_deny_beats_allow(guard):
    assert v(guard, "payments.mylab.local") == Verdict.DENY

def test_deny_wildcard_blocks_subdomain_and_apex(guard):
    assert v(guard, "db.internal.mylab.local") == Verdict.DENY
    assert v(guard, "internal.mylab.local") == Verdict.DENY

def test_denied_cidr(guard):
    assert v(guard, "10.1.2.3") == Verdict.DENY

def test_normalization(guard):
    assert normalize_host("http://LOCALHOST:3000/admin") == "localhost"
    assert v(guard, "http://app.mylab.local:8080/login") == Verdict.ALLOW
