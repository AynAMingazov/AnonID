"""End-to-end demo: issue a token, verify it at the entrance, try a replay and a forgery."""
from anonid import Issuer, Verifier, TokenStore, TokenError

SCOPE = "event:kfu-it-day-2026"

issuer = Issuer()
store = TokenStore()
gate = Verifier(issuer.public_key, store, expected_scope=SCOPE)

token = issuer.issue(SCOPE, right="entry", ttl_seconds=2 * 3600)
print("Token given to the visitor:\n", token, "\n")

claim = gate.verify(token)
print("Gate: access granted ->", claim.scope, claim.right)

for label, candidate in [
    ("Replay of the same token", token),
    ("Forged token", token[:-4] + "AAAA"),
    ("Token for another event", Issuer().issue("event:other")),
]:
    try:
        gate.verify(candidate)
        print(f"{label}: ACCEPTED (unexpected)")
    except TokenError as err:
        print(f"{label}: rejected ({err})")
