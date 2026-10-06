#!/usr/bin/env python3
import base64
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CURRENT = ROOT / "current" / "release-envelope.json"
ENVELOPE = ROOT / "trust" / "rollback-risk-registry-envelope.json"
KEYSET_ENVELOPE = ROOT / "trust" / "keyset-envelope.json"
ROOT_PUBLIC = ROOT / "wolf-root-public.pem"
SOURCE_ID = "WOLFTRADING_INDEPENDENT_RISK_REGISTRY"

def fail(msg):
    raise SystemExit(msg)

def bound(value, label):
    if not isinstance(value, str) or not value.strip() or value == "UNBOUND":
        fail(f"{label} must be bound")
    return value

def append_field(parts, name, value):
    parts.append(f"{len(name)}:{name}:{len(value)}:{value}\n")

def canonical_manifest(m):
    protocol_hash = m["protocolHash"].lower()
    if len(protocol_hash) != 64 or any(c not in "0123456789abcdef" for c in protocol_hash):
        fail("invalid protocolHash")
    if m["independentSourceId"] != SOURCE_ID:
        fail("risk manifest independentSourceId mismatch")
    if m["independentOfReleaseArtifact"] is not True:
        fail("risk manifest must be independent of release artifact")
    rules = m["rules"]
    if not isinstance(rules, list) or not rules:
        fail("risk manifest rules empty")
    ids = [r["id"] for r in rules]
    if len(ids) != len(set(ids)):
        fail("duplicate risk rule id")

    parts=["WOLF_ROLLBACK_RISK_MANIFEST_V2\n"]
    append_field(parts,"protocolHash",protocol_hash)
    append_field(parts,"independentSourceId",m["independentSourceId"])
    append_field(parts,"independentOfReleaseArtifact","true")
    for r in sorted(rules,key=lambda x:x["id"]):
        rid=bound(r["id"],"rule id")
        kind=r["kind"]
        if kind not in {"REQUIRE_TRUE","FORBID_ACTION","MAX_DECIMAL","MIN_DECIMAL"}:
            fail(f"unsupported risk rule kind {kind}")
        eh=r["evidenceHash"].lower()
        if len(eh)!=64 or any(c not in "0123456789abcdef" for c in eh):
            fail("invalid evidenceHash")
        append_field(parts,"ruleId",rid)
        append_field(parts,"ruleKind",kind)
        if kind in {"REQUIRE_TRUE","FORBID_ACTION"}:
            if not isinstance(r.get("booleanValue"),bool):
                fail("boolean rule requires booleanValue")
            append_field(parts,"booleanValue","true" if r["booleanValue"] else "false")
            if "decimalValue" in r and r["decimalValue"] is not None:
                fail("boolean rule may not carry decimalValue")
        else:
            value=bound(r.get("decimalValue"),"decimalValue")
            # App canonicalizes BigDecimal with trailing zeros stripped.
            from decimal import Decimal, InvalidOperation
            try:
                d=Decimal(value)
            except InvalidOperation:
                fail("invalid decimalValue")
            normalized=format(d.normalize(),"f")
            if normalized=="-0":
                normalized="0"
            append_field(parts,"decimalValue",normalized)
            if "booleanValue" in r and r["booleanValue"] is not None:
                fail("decimal rule may not carry booleanValue")
        append_field(parts,"evidenceHash",eh)
    return "".join(parts).encode()

def openssl_verify(public_pem, payload, signature_b64, label):
    sig=base64.b64decode(signature_b64)
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td)
        payload_path=td/"payload.bin"
        sig_path=td/"sig.der"
        key_path=td/"key.pem"
        payload_path.write_bytes(payload)
        sig_path.write_bytes(sig)
        key_path.write_text(public_pem)
        p=subprocess.run([
            "openssl","dgst","-sha256","-verify",str(key_path),
            "-signature",str(sig_path),str(payload_path)
        ],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        if p.returncode != 0:
            fail(f"{label} signature invalid: {p.stdout.strip()}")

if not ENVELOPE.exists():
    if CURRENT.exists():
        fail("CURRENT exists but rollback risk registry envelope is missing")
    print("Rollback risk registry absent: allowed only in bootstrap because CURRENT is absent.")
    raise SystemExit(0)

envelope=json.loads(ENVELOPE.read_text())
if envelope.get("schemaVersion") != 1:
    fail("unsupported rollback risk registry envelope schema")
registry_bytes=base64.b64decode(bound(envelope.get("registryBase64"),"registryBase64"))
root_sig=bound(envelope.get("rootSignatureBase64"),"rootSignatureBase64")
openssl_verify(ROOT_PUBLIC.read_text(),registry_bytes,root_sig,"root registry")

doc=json.loads(registry_bytes)
if doc.get("schemaVersion") != 1:
    fail("unsupported rollback risk registry schema")
generation=doc.get("generation")
if not isinstance(generation,int) or generation < 1:
    fail("invalid rollback risk registry generation")
if doc.get("sourceId") != SOURCE_ID:
    fail("unexpected rollback risk registry sourceId")
bound(doc.get("registryId"),"registryId")
manifests=doc.get("manifests")
if not isinstance(manifests,list) or not manifests:
    fail("rollback risk registry must contain manifests")
hashes=[m.get("protocolHash","").lower() for m in manifests]
if len(hashes)!=len(set(hashes)):
    fail("duplicate protocolHash in rollback risk registry")

keyset_env=json.loads(KEYSET_ENVELOPE.read_text())
keyset=json.loads(base64.b64decode(keyset_env["keysetBase64"]))
keys={k["keyId"]:k for k in keyset["signingKeys"]}

for entry in manifests:
    payload=canonical_manifest(entry)
    key_id=bound(entry.get("keyId"),"keyId")
    if entry.get("keysetGeneration") != keyset["generation"]:
        fail("risk manifest keysetGeneration mismatch")
    key=keys.get(key_id)
    if not key:
        fail(f"risk manifest signing key not in keyset: {key_id}")
    if key["state"] != "ACTIVE":
        fail("risk manifest must use ACTIVE signing key")
    if key["algorithm"] != "SHA256withECDSA":
        fail("unsupported risk manifest signing algorithm")
    openssl_verify(key["publicKeyPem"],payload,bound(entry.get("signatureBase64"),"signatureBase64"),f"risk manifest {entry['protocolHash']}")

if CURRENT.exists():
    print("CURRENT publication gate: root-signed rollback risk registry present and verified.")
else:
    print("Bootstrap registry verified; CURRENT remains absent.")
