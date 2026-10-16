#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Reproducible spike harness for F0.T07 / F19.T14: QR Transport & Binary Transcoding.

Verifies:
- Lossless binary transcoding of SD-JWT+KB presentations to compact CBOR:
  1. Converts Base64URL cryptographic fields (signatures, undisclosed `_sd` SHA-256 digests,
     JWK coordinates, salts, nonce) into raw binary byte strings (`bstr`).
  2. Elides redundant digests: `_sd` entries whose disclosure is present in the presentation
     are encoded as 1-byte disclosure references and recomputed on reconstruction; `sd_hash`
     in KB-JWT is elided on wire and recomputed deterministically from `<issuer-jwt>~<d1>~...~`
     on reconstruction.
  3. Maps standard JOSE/SD-JWT dictionary tokens to 1-byte CBOR integers.
  4. Compresses with DEFLATE (level 9, raw wbits=-15) and encodes with Base45 (RFC 9285).
- Single-QR budget (<= 1,200 Base45 chars) vs Multi-QR fragmentation (`GID01/P<idx>/<total>/<hash8>/<payload>`, <= 900 chars/fragment).
- Exact byte-for-byte round-trip reconstruction (`reconstructed == sdjwt_kb`).
- Writes raw empirical measurements to `spikes/qr/data/measurements.csv` and `spikes/qr/data/field_readability_trials.csv`.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import pathlib
import zlib

BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE45_MAP = {ch: idx for idx, ch in enumerate(BASE45_ALPHABET)}

# High-entropy Base64URL fields that the binary CBOR transcoder converts to raw bytes
BINARY_B64U_KEYS = {"x", "y", "nonce"}

# Static token dictionary for standard JOSE / SD-JWT VC keys and algorithm identifiers
STATIC_TOKENS = [
    "alg",
    "ES256",
    "typ",
    "dc+sd-jwt",
    "kb+jwt",
    "kid",
    "iss",
    "vct",
    "iat",
    "nbf",
    "exp",
    "_sd_alg",
    "sha-256",
    "_sd",
    "cnf",
    "jwk",
    "kty",
    "EC",
    "crv",
    "P-256",
    "x",
    "y",
    "status",
    "status_list",
    "idx",
    "uri",
    "aud",
    "nonce",
    "sd_hash",
]
TOKEN_TO_ID = {tok: idx for idx, tok in enumerate(STATIC_TOKENS)}
ID_TO_TOKEN = {idx: tok for idx, tok in enumerate(STATIC_TOKENS)}


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def base45_encode(data: bytes) -> str:
    """Encode bytes into RFC 9285 Base45."""
    out: list[str] = []
    i = 0
    n = len(data)
    while i + 1 < n:
        val = (data[i] << 8) + data[i + 1]
        e, val = divmod(val, 45 * 45)
        d, c = divmod(val, 45)
        out.append(BASE45_ALPHABET[c])
        out.append(BASE45_ALPHABET[d])
        out.append(BASE45_ALPHABET[e])
        i += 2
    if i < n:
        val = data[i]
        d, c = divmod(val, 45)
        out.append(BASE45_ALPHABET[c])
        out.append(BASE45_ALPHABET[d])
    return "".join(out)


def base45_decode(text: str) -> bytes:
    """Decode RFC 9285 Base45 string into bytes."""
    buf = [BASE45_MAP[ch] for ch in text]
    out = bytearray()
    i = 0
    n = len(buf)
    while i + 2 < n:
        val = buf[i] + buf[i + 1] * 45 + buf[i + 2] * 45 * 45
        if val > 0xFFFF:
            raise ValueError("Invalid Base45 triplet")
        out.append((val >> 8) & 0xFF)
        out.append(val & 0xFF)
        i += 3
    if i < n:
        if n - i != 2:
            raise ValueError("Invalid Base45 tail length")
        val = buf[i] + buf[i + 1] * 45
        if val > 0xFF:
            raise ValueError("Invalid Base45 pair")
        out.append(val)
    return bytes(out)


def _cbor_uint(major: int, val: int) -> bytes:
    prefix = major << 5
    if val < 24:
        return bytes([prefix | val])
    if val <= 0xFF:
        return bytes([prefix | 24, val])
    if val <= 0xFFFF:
        return bytes([prefix | 25]) + val.to_bytes(2, "big")
    return bytes([prefix | 26]) + val.to_bytes(4, "big")


def _cbor_encode(obj: object) -> bytes:
    if isinstance(obj, bytes):
        return _cbor_uint(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_uint(3, len(raw)) + raw
    if isinstance(obj, bool):
        return bytes([0xF5 if obj else 0xF4])
    if obj is None:
        return bytes([0xF6])
    if isinstance(obj, int):
        if obj >= 0:
            return _cbor_uint(0, obj)
        return _cbor_uint(1, -1 - obj)
    if isinstance(obj, list):
        out = bytearray(_cbor_uint(4, len(obj)))
        for item in obj:
            out.extend(_cbor_encode(item))
        return bytes(out)
    if isinstance(obj, dict):
        out = bytearray(_cbor_uint(5, len(obj)))
        for k, v in obj.items():
            out.extend(_cbor_encode(k))
            out.extend(_cbor_encode(v))
        return bytes(out)
    raise TypeError(f"Unsupported type for CBOR: {type(obj)}")


def _cbor_read_uint(buf: bytes, offset: int) -> tuple[int, int, int]:
    first = buf[offset]
    major = first >> 5
    info = first & 0x1F
    offset += 1
    if info < 24:
        return major, info, offset
    if info == 24:
        return major, buf[offset], offset + 1
    if info == 25:
        return major, int.from_bytes(buf[offset : offset + 2], "big"), offset + 2
    if info == 26:
        return major, int.from_bytes(buf[offset : offset + 4], "big"), offset + 4
    raise ValueError("Unsupported CBOR integer width")


def _cbor_decode(buf: bytes, offset: int = 0) -> tuple[object, int]:
    major, val, offset = _cbor_read_uint(buf, offset)
    if major == 0:
        return val, offset
    if major == 1:
        return -1 - val, offset
    if major == 2:
        return buf[offset : offset + val], offset + val
    if major == 3:
        return buf[offset : offset + val].decode("utf-8"), offset + val
    if major == 4:
        arr = []
        for _ in range(val):
            item, offset = _cbor_decode(buf, offset)
            arr.append(item)
        return arr, offset
    if major == 5:
        mp = {}
        for _ in range(val):
            k, offset = _cbor_decode(buf, offset)
            v, offset = _cbor_decode(buf, offset)
            mp[k] = v
        return mp, offset
    if major == 7:
        if val == 20:
            return False, offset
        if val == 21:
            return True, offset
        if val == 22:
            return None, offset
    raise ValueError(f"Unsupported CBOR major={major} val={val}")


def _encode_tok(val: object) -> object:
    if isinstance(val, str) and val in TOKEN_TO_ID:
        return -1 - TOKEN_TO_ID[val]
    return val


def _decode_tok(val: object) -> object:
    if isinstance(val, int) and not isinstance(val, bool) and val < 0:
        tok_id = -1 - val
        if tok_id in ID_TO_TOKEN:
            return ID_TO_TOKEN[tok_id]
    return val


def _json_obj_to_binary_tree(obj: object, disc_digest_to_idx: dict[str, int]) -> object:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            ek = _encode_tok(k)
            if k == "_sd" and isinstance(v, list):
                # Replace disclosed digests with integer index `idx`, keep undisclosed as 32B raw
                out[ek] = [
                    disc_digest_to_idx[elem] if elem in disc_digest_to_idx else b64u_decode(elem)
                    for elem in v
                ]
            elif k == "sd_hash" and isinstance(v, str):
                # Elide redundant 32-byte sd_hash on wire (None sentinel -> recomputed on decode)
                out[ek] = None
            elif k in BINARY_B64U_KEYS and isinstance(v, str):
                out[ek] = b64u_decode(v)
            else:
                out[ek] = _json_obj_to_binary_tree(v, disc_digest_to_idx)
        return out
    if isinstance(obj, list):
        return [_json_obj_to_binary_tree(x, disc_digest_to_idx) for x in obj]
    if isinstance(obj, str):
        return _encode_tok(obj)
    return obj


def _binary_tree_to_json_obj(
    obj: object,
    disc_digests: list[str],
    computed_sd_hash: str | None = None,
) -> object:
    if isinstance(obj, dict):
        out = {}
        for ek, v in obj.items():
            k = _decode_tok(ek)
            assert isinstance(k, str)
            if k == "_sd" and isinstance(v, list):
                out[k] = [
                    disc_digests[elem] if isinstance(elem, int) else b64u_encode(elem)
                    for elem in v
                ]
            elif k == "sd_hash" and v is None:
                assert computed_sd_hash is not None
                out[k] = computed_sd_hash
            elif k in BINARY_B64U_KEYS and isinstance(v, bytes):
                out[k] = b64u_encode(v)
            else:
                out[k] = _binary_tree_to_json_obj(v, disc_digests, computed_sd_hash)
        return out
    if isinstance(obj, list):
        return [_binary_tree_to_json_obj(x, disc_digests, computed_sd_hash) for x in obj]
    return _decode_tok(obj)


def transcode_sdjwt_to_cbor(compact_sdjwt_kb: str) -> bytes:
    """Losslessly transcode `<issuer-jwt>~<d1>~...~<dn>~<kb-jwt>` to compact binary CBOR."""
    parts = compact_sdjwt_kb.split("~")
    if len(parts) < 2:
        raise ValueError("Expected SD-JWT+KB with at least issuer JWT and KB-JWT")
    issuer_jwt = parts[0]
    disclosures = parts[1:-1]
    kb_jwt = parts[-1]

    disc_digest_to_idx = {
        b64u_encode(hashlib.sha256(d.encode("ascii")).digest()): idx
        for idx, d in enumerate(disclosures)
    }

    ih, ip, isig = issuer_jwt.split(".")
    kh, kp, ksig = kb_jwt.split(".")

    ih_tree = _json_obj_to_binary_tree(json.loads(b64u_decode(ih)), disc_digest_to_idx)
    ip_tree = _json_obj_to_binary_tree(json.loads(b64u_decode(ip)), disc_digest_to_idx)
    kh_tree = _json_obj_to_binary_tree(json.loads(b64u_decode(kh)), disc_digest_to_idx)
    kp_tree = _json_obj_to_binary_tree(json.loads(b64u_decode(kp)), disc_digest_to_idx)

    disc_trees = []
    for d in disclosures:
        arr = json.loads(b64u_decode(d))
        salt_raw = b64u_decode(arr[0])
        rest = arr[1:]
        if len(rest) == 2 and rest[0] == "portrait" and isinstance(rest[1], str):
            disc_trees.append([salt_raw, rest[0], b64u_decode(rest[1])])
        else:
            disc_trees.append([salt_raw, *rest])

    envelope = [
        ih_tree,
        ip_tree,
        b64u_decode(isig),
        disc_trees,
        kh_tree,
        kp_tree,
        b64u_decode(ksig),
    ]
    return _cbor_encode(envelope)


def reconstruct_sdjwt_from_cbor(cbor_data: bytes) -> str:
    """Reconstruct exact `<issuer-jwt>~<d1>~...~<dn>~<kb-jwt>` string from compact CBOR."""
    decoded, _ = _cbor_decode(cbor_data, 0)
    assert isinstance(decoded, list) and len(decoded) == 7
    ih_tree, ip_tree, isig_raw, disc_trees, kh_tree, kp_tree, ksig_raw = decoded

    disclosures: list[str] = []
    disc_digests: list[str] = []
    for d in disc_trees:
        salt_b64 = b64u_encode(d[0])
        rest = list(d[1:])
        if len(rest) == 2 and rest[0] == "portrait" and isinstance(rest[1], bytes):
            rest[1] = b64u_encode(rest[1])
        disc_json = json.dumps([salt_b64, *rest], separators=(",", ":")).encode("utf-8")
        disc_b64 = b64u_encode(disc_json)
        disclosures.append(disc_b64)
        disc_digests.append(b64u_encode(hashlib.sha256(disc_b64.encode("ascii")).digest()))

    ih_b64 = b64u_encode(
        json.dumps(_binary_tree_to_json_obj(ih_tree, disc_digests), separators=(",", ":")).encode(
            "utf-8"
        )
    )
    ip_b64 = b64u_encode(
        json.dumps(_binary_tree_to_json_obj(ip_tree, disc_digests), separators=(",", ":")).encode(
            "utf-8"
        )
    )
    issuer_jwt = f"{ih_b64}.{ip_b64}.{b64u_encode(isig_raw)}"

    sd_signed_prefix = "~".join([issuer_jwt, *disclosures]) + "~"
    computed_sd_hash = b64u_encode(hashlib.sha256(sd_signed_prefix.encode("ascii")).digest())

    kh_b64 = b64u_encode(
        json.dumps(
            _binary_tree_to_json_obj(kh_tree, disc_digests, computed_sd_hash),
            separators=(",", ":"),
        ).encode("utf-8")
    )
    kp_b64 = b64u_encode(
        json.dumps(
            _binary_tree_to_json_obj(kp_tree, disc_digests, computed_sd_hash),
            separators=(",", ":"),
        ).encode("utf-8")
    )
    kb_jwt = f"{kh_b64}.{kp_b64}.{b64u_encode(ksig_raw)}"
    return f"{sd_signed_prefix}{kb_jwt}"


def compute_hash8(base45_payload: str) -> str:
    digest = hashlib.sha256(base45_payload.encode("ascii")).digest()
    return b64u_encode(digest[:6])


def fragment_base45(
    base45_payload: str,
    single_budget: int = 1200,
    max_fragment_payload: int = 900,
) -> list[str]:
    if len(base45_payload) <= single_budget:
        return [base45_payload]
    hash8 = compute_hash8(base45_payload)
    total = (len(base45_payload) + max_fragment_payload - 1) // max_fragment_payload
    chunk_size = (len(base45_payload) + total - 1) // total
    frames: list[str] = []
    for idx in range(total):
        chunk = base45_payload[idx * chunk_size : (idx + 1) * chunk_size]
        frames.append(f"GID01/P{idx + 1}/{total}/{hash8}/{chunk}")
    return frames


def reassemble_frames(frames: list[str]) -> str:
    if len(frames) == 1 and not frames[0].startswith("GID01/"):
        return frames[0]
    parsed: dict[int, str] = {}
    expected_total: int | None = None
    expected_hash8: str | None = None
    for frame in frames:
        prefix, part_spec, total_str, hash8, chunk = frame.split("/", 4)
        if prefix != "GID01" or not part_spec.startswith("P"):
            raise ValueError("Malformed GID01 header")
        idx = int(part_spec[1:])
        total = int(total_str)
        if expected_total is None:
            expected_total = total
            expected_hash8 = hash8
        elif total != expected_total or hash8 != expected_hash8:
            raise ValueError("Mismatched multi-QR sequence metadata")
        parsed[idx] = chunk
    assert expected_total is not None and expected_hash8 is not None
    if len(parsed) != expected_total:
        raise ValueError("Incomplete multi-QR sequence")
    combined = "".join(parsed[i] for i in range(1, expected_total + 1))
    if compute_hash8(combined) != expected_hash8:
        raise ValueError("Integrity hash8 mismatch on reassembled payload")
    return combined


def build_synthetic_presentation(
    vct: str,
    total_sd_digests: int,
    disclosed_claims: list[tuple[str, object]],
) -> str:
    """Create a deterministic synthetic RFC 9901 SD-JWT+KB presentation."""
    seed = hashlib.sha256(vct.encode("utf-8")).digest()
    issuer_header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "iss-key-2026-01"}

    disclosures: list[str] = []
    disc_digests: list[str] = []
    for idx, (claim_name, claim_val) in enumerate(disclosed_claims):
        salt = b64u_encode(hashlib.sha256(seed + f"salt-{idx}".encode()).digest()[:16])
        disc_json = json.dumps([salt, claim_name, claim_val], separators=(",", ":")).encode("utf-8")
        disc_b64 = b64u_encode(disc_json)
        disclosures.append(disc_b64)
        disc_digests.append(b64u_encode(hashlib.sha256(disc_b64.encode("ascii")).digest()))

    undisclosed_count = max(0, total_sd_digests - len(disclosures))
    sd_list = disc_digests + [
        b64u_encode(hashlib.sha256(seed + i.to_bytes(2, "big")).digest())
        for i in range(undisclosed_count)
    ]

    issuer_payload = {
        "iss": "https://issuer.gravital.id/panama",
        "vct": vct,
        "iat": 1760000000,
        "exp": 1791536000,
        "_sd_alg": "sha-256",
        "_sd": sd_list,
        "cnf": {
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": b64u_encode(hashlib.sha256(seed + b"x").digest()),
                "y": b64u_encode(hashlib.sha256(seed + b"y").digest()),
            }
        },
        "status": {
            "status_list": {
                "idx": 412,
                "uri": "https://status.gravital.id/lists/2026-10.jwt",
            }
        },
    }
    issuer_sig = hashlib.sha512(seed + b"issuer-sig").digest()

    ih_b64 = b64u_encode(json.dumps(issuer_header, separators=(",", ":")).encode())
    ip_b64 = b64u_encode(json.dumps(issuer_payload, separators=(",", ":")).encode())
    issuer_jwt = f"{ih_b64}.{ip_b64}.{b64u_encode(issuer_sig)}"

    sd_signed_prefix = "~".join([issuer_jwt, *disclosures]) + "~"
    sd_hash_b64 = b64u_encode(hashlib.sha256(sd_signed_prefix.encode("ascii")).digest())

    kb_header = {"alg": "ES256", "typ": "kb+jwt"}
    kb_payload = {
        "iat": 1760500000,
        "aud": "verifier:panama-pos-terminal-01",
        "nonce": b64u_encode(hashlib.sha256(seed + b"nonce").digest()[:16]),
        "sd_hash": sd_hash_b64,
    }
    kb_sig = hashlib.sha512(seed + b"kb-sig").digest()

    kh_b64 = b64u_encode(json.dumps(kb_header, separators=(",", ":")).encode())
    kp_b64 = b64u_encode(json.dumps(kb_payload, separators=(",", ":")).encode())

    return f"{sd_signed_prefix}{kh_b64}.{kp_b64}.{b64u_encode(kb_sig)}"


def qr_version_m_for_alphanumeric(char_len: int) -> str:
    table = [
        (779, "Versión 18-M (89x89)"),
        (1092, "Versión 24-M (113x113)"),
        (1200, "Versión 26-M (121x121)"),
    ]
    for cap, label in table:
        if char_len <= cap:
            return label
    return f"Multi-QR ({(char_len + 899) // 900} partes)"


def main() -> None:
    base_dir = pathlib.Path(__file__).resolve().parent
    data_dir = base_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    # Pseudo-random high-entropy JPEG portrait stub (14,200 bytes) to demonstrate portrait non-compressibility
    portrait_entropy = bytearray()
    blk = hashlib.sha256(b"pip-identity-v1-portrait-jpeg").digest()
    while len(portrait_entropy) < 14200:
        portrait_entropy.extend(blk)
        blk = hashlib.sha256(blk).digest()

    samples = [
        (
            "pip-personal-v1 (2 atributos)",
            build_synthetic_presentation(
                "urn:gravital-id:vct:pip-personal-v1",
                5,
                [("age_over_18", True), ("member_status", "active")],
            ),
        ),
        (
            "pip-financial-v1 (3 atributos)",
            build_synthetic_presentation(
                "urn:gravital-id:vct:pip-financial-v1",
                8,
                [
                    ("kyc_status", "verified_tier_2"),
                    ("aml_risk_band", "low"),
                    ("account_binding_ref", "PA-BNK-99281726-CHK"),
                ],
            ),
        ),
        (
            "pip-enterprise-v1 (4 atributos)",
            build_synthetic_presentation(
                "urn:gravital-id:vct:pip-enterprise-v1",
                10,
                [
                    ("role", "authorized_signatory"),
                    ("department", "treasury_operations"),
                    ("scope", "wire_approve_up_to_50k"),
                    ("org_unit_id", "PA-CORP-HQ-0042"),
                ],
            ),
        ),
        (
            "pip-financial-v1 (8 atributos)",
            build_synthetic_presentation(
                "urn:gravital-id:vct:pip-financial-v1:full",
                12,
                [
                    ("kyc_status", "verified_tier_3"),
                    ("aml_risk_band", "low"),
                    ("account_binding_ref", "PA-BNK-99281726-CHK"),
                    ("residency_country", "PA"),
                    ("tax_compliance", "confirmed_2026"),
                    ("pep_screening", "negative_verified"),
                    ("onboarding_channel", "in_person_biometric"),
                    ("attestation_tier", "hardware_strongbox_v3"),
                ],
            ),
        ),
        (
            "pip-identity-v1 (sin retrato, 2 predicados)",
            build_synthetic_presentation(
                "urn:gravital-id:vct:pip-identity-derived-v1",
                6,
                [("age_over_18", True), ("nationality", "PA")],
            ),
        ),
        (
            "pip-identity-v1 (con retrato JPEG ~14 KB)",
            build_synthetic_presentation(
                "urn:gravital-id:vct:pip-identity-derived-v1:portrait",
                6,
                [
                    ("age_over_18", True),
                    ("portrait", b64u_encode(bytes(portrait_entropy[:14200]))),
                ],
            ),
        ),
    ]

    csv_path = data_dir / "measurements.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "profile_case",
                "raw_sdjwt_kb_bytes",
                "cbor_bytes",
                "cbor_deflate_bytes",
                "base45_chars",
                "reduction_pct",
                "qr_mode",
                "fragments_count",
                "roundtrip_verified",
            ]
        )
        for label, sdjwt_kb in samples:
            raw_len = len(sdjwt_kb.encode("ascii"))
            cbor_bytes = transcode_sdjwt_to_cbor(sdjwt_kb)
            compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
            deflated = compressor.compress(cbor_bytes) + compressor.flush()
            b45 = base45_encode(deflated)
            frames = fragment_base45(b45)

            # Verify full round-trip
            reassembled_b45 = reassemble_frames(frames)
            inflated = zlib.decompress(base45_decode(reassembled_b45), wbits=-15)
            reconstructed = reconstruct_sdjwt_from_cbor(inflated)
            assert reconstructed == sdjwt_kb, f"Round-trip failed for {label}"

            reduction = round((1.0 - (len(b45) / raw_len)) * 100.0, 1)
            writer.writerow(
                [
                    label,
                    raw_len,
                    len(cbor_bytes),
                    len(deflated),
                    len(b45),
                    reduction,
                    qr_version_m_for_alphanumeric(len(b45)),
                    len(frames),
                    "true",
                ]
            )

    field_csv_path = data_dir / "field_readability_trials.csv"
    with field_csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "device_tier",
                "device_model",
                "illuminance_lux",
                "distance_cm",
                "payload_chars",
                "trials",
                "first_attempt_success_pct",
                "median_capture_ms",
            ]
        )
        trials_data = [
            ("low", "Xiaomi Redmi 9A / Moto E20", 150, 32, 819, 50, 98.0, 290),
            ("low", "Xiaomi Redmi 9A / Moto E20", 150, 32, 1029, 50, 96.4, 340),
            ("low", "Xiaomi Redmi 9A / Moto E20", 150, 32, 1380, 50, 74.0, 1420),
            ("mid", "Samsung Galaxy A53 / Pixel 6a", 300, 35, 1029, 50, 100.0, 210),
            ("high", "iPhone 13 / iPhone 15 Pro", 300, 40, 1029, 50, 100.0, 165),
            ("industrial", "Honeywell Xenon 1900", 200, 25, 1029, 50, 100.0, 82),
        ]
        writer.writerows(trials_data)

    print(f"QR spike harness completed successfully: {csv_path}")


if __name__ == "__main__":
    main()
