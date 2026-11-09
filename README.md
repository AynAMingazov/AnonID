# AnonID

My course project at Kazan Federal University (2025-2026), grade excellent.

Idea: verify that a person has a right (for example to enter an event) without giving his personal data to everyone who checks him.

## Why
When you register for some event they ask name, phone, birthday, sometimes passport. And then all this lies in some excel or database, and later it leaks. I think in most cases organizer doesnt need it, he only needs to know "this person can enter".

## How it works
1. Issuer checks the person one time and gives him a signed token (can be QR)
2. Token has only: event, right, time of issue, expire time and random id. No name, no phone
3. Verifier at the entrance checks signature with public key, event, expire time and that token was not used before

Signature is Ed25519. Used tokens are saved in SQLite only as random id, so even if this db leaks there is nothing about people.

## What it protects from
- fake or changed token - signature check
- same token two times (replay) - one time id
- token from other event - scope check
- old token - expire time
- stolen token - revoke list

What is not solved: token works like a ticket, who shows it first goes in. Can be fixed by binding token to phone key, I wrote about it in the paper but didnt implement.

## Where AI can be used here
In the paper I didnt use AI, but I think it fits:
- anomaly detection on the verifier side (many failed tokens from one gate = someone tries to brute force)
- face liveness check (for example MiniFASNet) if token is bound to a photo, but then we again work with biometric data, so it is a trade off

## Run
```
pip install -r requirements.txt
python demo.py
pytest -q
```

Stack: Python, cryptography (Ed25519), SQLite, pytest
