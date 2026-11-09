import pytest

from anonid import Issuer, Verifier, TokenStore, TokenError, parse

SCOPE = "event:test"


@pytest.fixture()
def setup():
    issuer = Issuer()
    store = TokenStore()
    return issuer, store, Verifier(issuer.public_key, store, expected_scope=SCOPE)


def test_valid_token_is_accepted(setup):
    issuer, _, gate = setup
    claim = gate.verify(issuer.issue(SCOPE, now=1_000), now=1_100)
    assert claim.scope == SCOPE and claim.right == "entry"


def test_token_contains_no_personal_fields(setup):
    issuer, _, _ = setup
    claim, _, _ = parse(issuer.issue(SCOPE))
    assert set(vars(claim)) == {"scope", "right", "issued_at", "expires_at", "token_id", "version"}


def test_replay_is_rejected(setup):
    issuer, _, gate = setup
    token = issuer.issue(SCOPE, now=1_000)
    gate.verify(token, now=1_001)
    with pytest.raises(TokenError, match="already used"):
        gate.verify(token, now=1_002)


def test_expired_token_is_rejected(setup):
    issuer, _, gate = setup
    token = issuer.issue(SCOPE, ttl_seconds=60, now=1_000)
    with pytest.raises(TokenError, match="expired"):
        gate.verify(token, now=2_000)


def test_tampered_payload_is_rejected(setup):
    issuer, _, gate = setup
    prefix, payload, sig = issuer.issue(SCOPE).split(".")
    other_payload = Issuer().issue(SCOPE).split(".")[1]
    with pytest.raises(TokenError, match="signature"):
        gate.verify(f"{prefix}.{other_payload}.{sig}")


def test_foreign_issuer_is_rejected(setup):
    _, _, gate = setup
    with pytest.raises(TokenError, match="signature"):
        gate.verify(Issuer().issue(SCOPE))


def test_wrong_scope_is_rejected(setup):
    issuer, _, gate = setup
    with pytest.raises(TokenError, match="scope"):
        gate.verify(issuer.issue("event:other"))


def test_revoked_token_is_rejected(setup):
    issuer, store, gate = setup
    token = issuer.issue(SCOPE)
    store.revoke(parse(token)[0].token_id)
    with pytest.raises(TokenError, match="revoked"):
        gate.verify(token)


@pytest.mark.parametrize("bad", ["", "abc", "XYZ.a.b", "AID1.@@@.###"])
def test_malformed_tokens_are_rejected(setup, bad):
    _, _, gate = setup
    with pytest.raises(TokenError):
        gate.verify(bad)
