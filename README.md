# AnonID

Access verification without transfer of personal data.
My course project at Kazan Federal University, Institute of Computational Mathematics and IT, 2026. Grade: excellent (86/100).

## Why I chose this topic
To enter a hackathon, a conference or a sports event I usually give my full name, phone, date of birth and sometimes passport data. The organizer needs one fact: I am allowed to enter. Everything else is stored in some table and later appears in leaks. While preparing a presentation about phone fraud for a regional contest, I saw how easy it is to buy such data. AnonID is my attempt to check the right without collecting the person.

## Idea
| Role | What it does | What it knows |
|---|---|---|
| Issuer | Checks the person once (registration, payment, invitation) and signs a token | Who the person is |
| Holder | Keeps the token (QR or string) and shows it at the entrance | Own token |
| Verifier | Checks the token offline with the issuer public key | Only that the right exists |

Token contents: scope (event), right (entry), issue time, expiry, random 128-bit id, version. No name, no phone, no birth date.

Format: `AID1.<payload base64url>.<Ed25519 signature base64url>`

## Why Ed25519
- Short signature (64 bytes) and key (32 bytes), token fits into a QR code
- Fast verification on a weak device at the entrance
- Deterministic signatures, no random number problems like in ECDSA
- Standard: RFC 8032, implemented in the `cryptography` library

## Threat model
| Threat | Control | Test |
|---|---|---|
| Forged or modified token | Signature over the whole payload | `test_tampered_payload_is_rejected`, `test_foreign_issuer_is_rejected` |
| Replay of a copied token | One-time id, atomic insert in SQLite | `test_replay_is_rejected` |
| Token from another event | Scope check | `test_wrong_scope_is_rejected` |
| Old token | Expiry with 30 s clock skew | `test_expired_token_is_rejected` |
| Lost or stolen token | Revocation list | `test_revoked_token_is_rejected` |
| Garbage input | Strict parser | `test_malformed_tokens_are_rejected` |
| Leak of the verifier database | Stores only random ids and timestamps | `test_token_contains_no_personal_fields` |

Not covered: the token is a bearer credential, whoever shows it first gets in. In the paper I describe two fixes: binding the token to a key on the phone (the holder signs a challenge at the gate) and a photo check by staff. Neither is implemented here.

## Related standards
While writing the paper I compared my approach with existing ones:
- **SD-JWT (RFC 9901, 2025)**: the issuer signs hashes of fields and the holder discloses only the needed ones. More flexible than AnonID, where the token has only one fact by design.
- **W3C Verifiable Credentials 2.0** (Recommendation, 2025): common data model for such credentials.
- **BBS signatures**: allow unlinkable proofs, so two verifiers cannot tell that it is the same person. AnonID tokens are one-time, which gives a similar effect in a simpler way.

AnonID is intentionally small: one fact, one signature, offline check. It is easy to explain and to audit.

## Where AI could help
- Anomaly detection on the verifier side: many failed checks from one gate in a short time means someone is guessing tokens.
- Face liveness check (for example MiniFASNet) if the token is bound to a photo. This brings biometric data back into the system, so it is a trade-off I would discuss with the organizer.

## Run
```
pip install -r requirements.txt
python demo.py      # valid token, replay, forgery, wrong event
pytest -q           # 12 tests
```

Python 3.10+, cryptography (Ed25519), SQLite, pytest.

## References
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA): https://www.rfc-editor.org/rfc/rfc8032
- RFC 9901, Selective Disclosure for JSON Web Tokens: https://datatracker.ietf.org/doc/rfc9901/
- W3C Verifiable Credentials Data Model 2.0: https://www.w3.org/TR/vc-data-model-2.0/
- Federal Law 152-FZ "On Personal Data" (principle of data minimization)
