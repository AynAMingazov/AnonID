# AnonID

Access verification without transfer of personal data.
Course project, Kazan Federal University, 2026. Grade: excellent.

## Problem
Registration systems collect name, phone, date of birth, passport. The check usually needs one fact: the person has the right to enter.

## Solution
1. Issuer verifies the person once and signs a token.
2. Token contains: scope, right, issue time, expiry, random id. No personal data.
3. Verifier checks signature, scope, expiry and one-time use. Works offline.

Ed25519 signatures. Used tokens are stored as random ids only.

## Threats
| Threat | Control |
|---|---|
| Forged token | Signature |
| Replay | One-time id |
| Wrong event | Scope |
| Old token | Expiry |
| Stolen token | Revocation list |

Not covered: token is a bearer credential. Device binding is described in the paper, not implemented.

## AI extension
Anomaly detection on failed checks per gate. Liveness check if the token is bound to a photo; this brings back biometric data.

## Run
```
pip install -r requirements.txt
python demo.py
pytest -q
```

Python, cryptography, SQLite.
