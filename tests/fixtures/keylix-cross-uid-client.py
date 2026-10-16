"""Disposable NixOS cross-UID client: synthetic keys and real DPoP/IPC verification."""

import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


PEER_ID = "vm-fixture"
PEER_SECRET = bytes(32)  # Deterministic, non-production peer fixture.
TOKEN = "synthetic-verifier-token"
TARGET = "https://operator.example/v1/health"
REQUEST_DOMAIN = b"keylix-verifier-request-v1\0"
RESPONSE_DOMAIN = b"keylix-verifier-response-v1\0"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def encoded_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def envelope_mac(domain: bytes, correlation: bytes, payload: bytes) -> bytes:
    return hmac.new(
        PEER_SECRET, domain + PEER_ID.encode("ascii") + b"\0" + correlation + payload,
        hashlib.sha256,
    ).digest()


def request(path: str, payload: bytes, bad_mac: bool = False) -> dict:
    # Every IPC attempt gets a distinct correlation even when probing DPoP replay.
    correlation = os.urandom(32)
    mac = envelope_mac(REQUEST_DOMAIN, correlation, payload)
    if bad_mac:
        mac = bytes(32)
    frame = {
        "version": 1,
        "peer_id": PEER_ID,
        "correlation_base64url": b64(correlation),
        "payload_base64url": b64(payload),
        "mac_base64url": b64(mac),
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(path)
        client.sendall(encoded_json(frame) + b"\n")
        data = client.makefile("rb").readline(65537)
    assert data.endswith(b"\n") and len(data) <= 65536
    reply = json.loads(data)
    if bad_mac:
        assert reply == {"status": "rejected", "version": 1, "failure": "malformed_request"}
        return reply

    assert reply["version"] == 1
    assert reply["peer_id"] == PEER_ID
    assert reply["correlation_base64url"] == b64(correlation)
    decoded = unb64(reply["payload_base64url"])
    actual_mac = unb64(reply["mac_base64url"])
    expected_mac = envelope_mac(RESPONSE_DOMAIN, correlation, decoded)
    assert hmac.compare_digest(actual_mac, expected_mac), "response MAC not authenticated"
    return json.loads(decoded)


def valid_application_payload() -> tuple[bytes, str]:
    # No production private keys or tokens. The ephemeral ES256 key is guest-only.
    signer = ec.generate_private_key(ec.SECP256R1())
    numbers = signer.public_key().public_numbers()
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64(numbers.x.to_bytes(32, "big")),
        "y": b64(numbers.y.to_bytes(32, "big")),
    }
    thumbprint = b64(hashlib.sha256(encoded_json(public_jwk)).digest())
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk}
    now = int(time.time())
    claims = {
        "htm": "GET",
        "htu": TARGET,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "ath": b64(hashlib.sha256(TOKEN.encode()).digest()),
    }
    signing_input = b64(encoded_json(header)) + "." + b64(encoded_json(claims))
    der_signature = signer.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_signature)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    proof = signing_input + "." + b64(signature)
    payload = {
        "version": 1,
        "method": "GET",
        "target": TARGET,
        "access_token": TOKEN,
        "dpop_proof": proof,
        "confirmation_jkt": thumbprint,
    }
    return encoded_json(payload), thumbprint


def main(path: str, mode: str) -> None:
    if mode == "denied":
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            try:
                client.connect(path)
            except PermissionError:
                print("cross_uid_nonmember=denied")
                return
        raise AssertionError("nonmember connected to the restricted socket")

    if mode == "badmac":
        request(path, b"{}", bad_mac=True)
        print("cross_uid_bad_mac=denied")
        return

    if mode == "malformed":
        outcome = request(path, b"{}")
        assert outcome == {"status": "rejected", "version": 1, "failure": "malformed_request"}
        print("cross_uid_malformed_application=denied")
        return

    assert mode == "valid_and_replay", mode
    payload, thumbprint = valid_application_payload()
    outcome = request(path, payload)
    assert outcome["status"] == "verified", outcome
    assert outcome["version"] == 1
    assert outcome["binding"]["key_thumbprint"] == thumbprint
    assert outcome["binding"]["replay_checked"] is True
    assert outcome["binding"]["nonce_enforced"] is False
    print("cross_uid_sender_binding=verified")
    replay = request(path, payload)
    assert replay == {"status": "rejected", "version": 1, "failure": "replay"}, replay
    print("cross_uid_replay=denied")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: client.py SOCKET valid_and_replay|badmac|malformed|denied")
    main(*sys.argv[1:])
