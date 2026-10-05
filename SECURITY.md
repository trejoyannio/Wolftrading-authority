# Security Policy

## Public-only repository

This repository is an untrusted transport for **public signed artifacts**. Private cryptographic material must never be committed.

Allowed:
- public keys
- signed envelopes
- manifests
- protocol JSON
- checksums
- validation reports intended for public verification

Forbidden:
- private keys
- keystores
- passwords
- recovery codes
- authentication tokens
- broker/account secrets

## Fail-closed invariant

A GitHub compromise, stale cache, accidental edit, or malicious content change must not by itself authorize a trade. Android independently verifies the Wolftrading Root trust chain, release hashes, lineage and validation contract.

If verification fails, the required state is:

`NEW TRADES: LOCKED`
