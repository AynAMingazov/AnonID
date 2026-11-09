# AnonID — identity verification without transferring personal data

Course project, Kazan Federal University, Institute of Computational Mathematics and Information Technologies (2025–2026). Grade: **excellent**.

## Problem
Registration for events, online services and access systems usually collects far more personal data than the task requires: full name, phone, date of birth, sometimes passport details. Every such database becomes a leak risk for the people and a liability for the organiser.

## Idea
Check a person's right **once** and give them a short signed token that proves only that right, for example *"entry to event X until 18:00"*. The entrance terminal verifies the token offline with the issuer's public key and never receives the person's data.

```
Person ──(proves right once)──► Issuer ──(signed token, no PII)──► Person
Person ──(shows token / QR)──► Verifier: signature ✓  scope ✓  expiry ✓  not used ✓
```

## Security properties
| Threat | Protection |
|---|---|
| Forged or modified token | Ed25519 signature over the whole payload |
| Re-use of a copied token (replay) | one-time `token_id`, atomic "used" mark in SQLite |
| Token from another event | scope check |
| Old token | expiry with small clock-skew tolerance |
| Lost / stolen token | revocation list |
| Leak of the verifier database | it stores only random ids and timestamps, no personal data |

Limitations: a token is a bearer credential (whoever shows it first gets in); binding to a device key or a photo check at the gate are possible extensions.

## Run
```bash
pip install -r requirements.txt
python demo.py
pytest -q
```

## Structure
```
anonid/tokens.py   claim model, issuer, verifier
anonid/store.py    used / revoked token ids (SQLite)
demo.py            end-to-end scenario: valid, replay, forgery, wrong scope
tests/             unit tests for every rule above
```

## Stack
Python 3.10+, `cryptography` (Ed25519), SQLite, pytest
