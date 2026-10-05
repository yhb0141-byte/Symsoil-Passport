"""Independent Python verifier for synthetic Passport wire-protocol vectors.

Optional development dependency: cryptography. Not imported by the application.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def string_json(value):
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    result, position = [], 0
    while position < len(encoded):
        code = ord(encoded[position])
        if 0xD800 <= code <= 0xDBFF and position + 1 < len(encoded) and 0xDC00 <= ord(encoded[position + 1]) <= 0xDFFF:
            low = ord(encoded[position + 1])
            result.append(chr(0x10000 + ((code - 0xD800) << 10) + low - 0xDC00))
            position += 2
        else:
            result.append("\\u%04x" % code if 0xD800 <= code <= 0xDFFF else encoded[position])
            position += 1
    return "".join(result)


def canonical(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return string_json(value)
    if isinstance(value, int) and abs(value) <= 9007199254740991:
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(string_json(key) + ":" + canonical(value[key]) for key in keys) + "}"
    raise ValueError("Protocol only accepts JSON strings, booleans, null, arrays, objects and safe integers")


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify(document):
    if document["protocol"] != "symsoil-passport/1" or document.get("synthetic") is not True:
        raise ValueError("Expected a synthetic symsoil-passport/1 vector file")
    for example in document["serializerCases"]:
        if canonical(example["value"]) != example["expected"]:
            raise ValueError("Serializer mismatch: " + example["name"])
    for vector in document["vectors"]:
        request = vector["request"]
        content = {field: request[field] for field in ["communityId", "memberId", "kind", "sourceId", "version", "payload"]}
        serialized = canonical(content)
        if serialized != vector["canonicalContent"] or hashlib.sha256(serialized.encode("utf-8")).hexdigest() != request["digest"]:
            raise ValueError("Content mismatch: " + vector["name"])
        frame = {
            "protocol": document["protocol"], "communityId": request["communityId"],
            "requestId": request["id"], "requestDigest": request["digest"],
            "requestVersion": request["version"], "nonce": request["nonce"],
            "expiresAt": request["expiresAt"], "memberId": request["memberId"],
            "deviceId": vector["deviceId"], "decision": vector["decision"], "counter": vector["counter"],
        }
        serialized_frame = canonical(frame)
        if serialized_frame != vector["canonicalFrame"]:
            raise ValueError("Frame mismatch: " + vector["name"])
        jwk = vector["publicKey"]
        if jwk["kty"] != "EC" or jwk["crv"] != "P-256" or "d" in jwk:
            raise ValueError("Expected a public-only P-256 key")
        public_key = ec.EllipticCurvePublicNumbers(int.from_bytes(decode(jwk["x"]), "big"), int.from_bytes(decode(jwk["y"]), "big"), ec.SECP256R1()).public_key()
        signature = decode(vector["signature"])
        if len(signature) != 64:
            raise ValueError("Expected 64-byte P1363 signature")
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        public_key.verify(der, serialized_frame.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        try:
            changed = dict(frame, counter=frame["counter"] + 1)
            public_key.verify(der, canonical(changed).encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            pass
        else:
            raise ValueError("Modified frame unexpectedly passed verification")
    return len(document["vectors"])


if __name__ == "__main__":
    filename = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "firmware/protocol-vectors/confirmation-v1.json"
    count = verify(json.loads(filename.read_text(encoding="utf-8")))
    print(f"Independent Python verification passed: {count} P-256 vectors and UTF-16/UTF-8 serializer cases.")
