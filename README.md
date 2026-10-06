# Wolftrading Protocol Authority

Public, read-only distribution repository for **cryptographically signed Wolftrading protocol material**.

This repository is intentionally separate from the private Android application source.

## Trust model

Android embeds the Wolftrading Root **public** key and independently verifies:

1. Root signature on the signing-keyset.
2. Monotonic keyset generation.
3. Release signing key authorization and revision window.
4. Release signature.
5. Immutable artifact hashes.
6. Immediate release lineage.
7. ChangeSet, Dependency Registry and Validation Report.
8. Deterministic contract test vectors.
9. Atomic Candidate → Active cutover.

The repository transport is **not** trusted to redefine Wolftrading. Tampered unsigned content must fail closed on Android.

## Bootstrap state

- Root key ID: `wolf-root-01`
- Signing keyset generation: `1`
- Active operational signer: `wolf-sign-01`
- CURRENT release: **not published yet**
- New trades: **LOCKED**

The absence of `current/release-envelope.json` is deliberate until a sufficiently complete Wolftrading protocol release has passed validation.

## Public files

- `wolf-root-public.pem`
- `wolf-sign-01-public.pem`
- `trust/keyset-envelope.json`
- `trust/keysets/1/*`
- `trust/rollback-risk-registry-envelope.json` — required before CURRENT publication; may be absent only during bootstrap
- `status.json`
- `SHA256SUMS`

Android v0.8.2 reads this repository over HTTPS at:

`https://raw.githubusercontent.com/trejoyannio/Wolftrading-authority/main`

## Forbidden material

Never commit:

- Android release keystore
- Wolftrading Root private key
- protocol signing private keys
- passwords
- recovery credentials
- private account or broker credentials

See `SECURITY.md`.


## Rollback risk trust gate

Before CURRENT can be published, Authority must contain a root-signed `trust/rollback-risk-registry-envelope.json`.
The registry is independent of release artifacts and carries per-protocol risk manifests signed by an ACTIVE operational signing key.
The root and signing private keys remain offline and must never be committed.
