#!/usr/bin/env python3
import base64
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(".")
CURRENT = ROOT / "current" / "release-envelope.json"

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def fail(message: str):
    raise SystemExit(message)

if not CURRENT.exists():
    print("BOOTSTRAP PASS: CURRENT is intentionally absent.")
    raise SystemExit(0)

envelope = json.loads(CURRENT.read_text())
if envelope.get("schemaVersion") != 1:
    fail("CURRENT envelope schemaVersion must be 1")

manifest_bytes = base64.b64decode(envelope["manifestBase64"])
signature_b64 = envelope.get("signatureBase64", "").strip()
if not signature_b64:
    fail("CURRENT signature missing")

manifest = json.loads(manifest_bytes)
if manifest.get("schemaVersion") != 4:
    fail("CURRENT manifest schemaVersion 4 required")

revision = int(manifest["revision"])
release_id = manifest["releaseId"]
if release_id != f'{manifest["protocolVersion"]}-r{revision}':
    fail("releaseId mismatch")

release_dir = ROOT / "releases" / str(revision)
if not release_dir.is_dir():
    fail("immutable release directory missing")

assets = {
    "protocol.json": ("protocolPath", "protocolSha256"),
    "selftests.json": ("selfTestsPath", "selfTestsSha256"),
    "changeset.json": ("changeSetPath", "changeSetSha256"),
    "registry.json": ("registryPath", "registrySha256"),
    "validation-report.json": ("validationReportPath", "validationReportSha256"),
    "coverage-attestation.json": ("coverageAttestationPath", "coverageAttestationSha256"),
}

for filename, (path_key, hash_key) in assets.items():
    expected_path = f"/releases/{revision}/{filename}"
    if manifest.get(path_key) != expected_path:
        fail(f"{filename}: immutable path mismatch")
    p = release_dir / filename
    if not p.is_file():
        fail(f"{filename}: missing")
    actual = sha256_bytes(p.read_bytes())
    if actual.lower() != manifest.get(hash_key, "").lower():
        fail(f"{filename}: SHA-256 mismatch")

coverage_path = release_dir / "coverage-attestation.json"
coverage = json.loads(coverage_path.read_text())
if coverage.get("schemaVersion") != 1:
    fail("coverage schemaVersion must be 1")
if coverage.get("status") != "COMPLETE":
    fail("coverage status must be COMPLETE")
if coverage.get("protocolVersion") != manifest["protocolVersion"]:
    fail("coverage protocolVersion mismatch")
if int(coverage.get("revision", -1)) != revision:
    fail("coverage revision mismatch")
if coverage.get("protocolSha256", "").lower() != manifest["protocolSha256"].lower():
    fail("coverage protocol hash mismatch")
if coverage.get("registrySha256", "").lower() != manifest["registrySha256"].lower():
    fail("coverage registry hash mismatch")
if coverage.get("selfTestsSha256", "").lower() != manifest["selfTestsSha256"].lower():
    fail("coverage self-tests hash mismatch")

rm = int(coverage.get("requiredModuleCount", 0))
im = int(coverage.get("implementedModuleCount", -1))
ro = int(coverage.get("requiredDecisionOutputCount", 0))
io = int(coverage.get("implementedDecisionOutputCount", -1))
if rm <= 0 or im != rm:
    fail("module coverage incomplete")
if ro <= 0 or io != ro:
    fail("decision-output coverage incomplete")
if coverage.get("unimplementedModules") != []:
    fail("unimplementedModules must be empty")
if coverage.get("unimplementedDecisionOutputs") != []:
    fail("unimplementedDecisionOutputs must be empty")

# Emit material for the workflow's OpenSSL signature verification.
tmp = pathlib.Path("/tmp")
(tmp / "wolf-current-manifest.json").write_bytes(manifest_bytes)
(tmp / "wolf-current-signature.der").write_bytes(base64.b64decode(signature_b64))

keyset_env = json.loads((ROOT / "trust" / "keyset-envelope.json").read_text())
keyset = json.loads(base64.b64decode(keyset_env["keysetBase64"]))
key_id = manifest["keyId"]
matches = [k for k in keyset["signingKeys"] if k["keyId"] == key_id]
if len(matches) != 1:
    fail("manifest keyId not uniquely authorized by keyset")
key = matches[0]
if key.get("state") != "ACTIVE":
    fail("CURRENT signer is not ACTIVE")
if revision < int(key["minRevision"]):
    fail("CURRENT revision below signer window")
if key.get("maxRevision") is not None and revision > int(key["maxRevision"]):
    fail("CURRENT revision above signer window")
(tmp / "wolf-current-signer.pem").write_text(key["publicKeyPem"])

print(f"CURRENT STRUCTURE PASS: {release_id}")
