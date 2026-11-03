"""Public P-256 canonical fixture; synthetic readiness, not MPC/W acceptance.

Ephemeral test authority private keys exist only in memory and are never exported.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def message(domain, value):
    return b"Wallet-MPC/" + domain.encode() + b"\0" + canonical(value)


def identity(role, key=None, *, ca=False):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"spiffe://wallet-mpc/{role}")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return (
        key,
        hashlib.sha256(public).hexdigest(),
        cert.public_bytes(serialization.Encoding.DER).hex(),
    )


def signed(key, key_id, domain, value):
    encoded = message(domain, {"key_id": key_id, "value": value})
    return dict(
        key_id=key_id, value=value, signature=key.sign(encoded, ec.ECDSA(hashes.SHA256())).hex()
    )


def main():
    folder = Path(__file__).parent
    original = json.loads((folder / "solana-seeded-intent-sdk.json").read_text())
    root = original["root"]
    intent = original["cases"][0]["intent"]
    claim = intent["claim"] | {"root": root}
    claim["idempotency_key"] = "current-آزمایش-测试"
    previous = intent["generation"]
    generation = previous | {"epoch": 1, "ceremony_id": "00000000-0000-0000-0000-0000000002bc"}
    root_identity = hashlib.sha256(b"SOLANA_SEEDED_ROOT_V1\0" + canonical(root)).hexdigest()
    parties = ("signer-a", "signer-b", "signer-c")
    nodes = {party: identity(party) for party in parties}
    life, life_id, life_cert = identity("lifecycle")
    custody, _, custody_cert = identity("custody")
    _, _, other_life_cert = identity("lifecycle")
    ready = [
        signed(
            nodes[p][0],
            nodes[p][1],
            "WITNESS_GENERATION_READY_V1",
            dict(
                root_identity=root_identity,
                previous_generation=previous,
                generation=generation,
                public_key_package=root["public_key_package"],
                party_id=p,
            ),
        )
        for p in parties
    ]
    prepare = signed(
        life,
        life_id,
        "WITNESS_COMMAND_V1",
        dict(
            anchor_id="00000000-0000-0000-0000-0000000002bd",
            request_id="00000000-0000-0000-0000-0000000002be",
            root_identity=root_identity,
            expected_revision=3,
            expires_at=950,
            action=dict(kind="Prepare", ready=ready, node_keys={p: nodes[p][1] for p in parties}),
        ),
    )
    authority = dict(
        version=1, prepare=prepare, node_certificates_der_hex={p: nodes[p][2] for p in parties}
    )
    receipts, receipt_hashes = [], {}
    for party in parties:
        value = dict(statement=claim, authority=authority, party_id=party, durable=True)
        encoded = message("SIGNER_SOLANA_CURRENT_CLAIM_V1", value)
        receipts.append(
            dict(
                statement=claim,
                party_id=party,
                durable=True,
                signer_signature=nodes[party][0].sign(encoded, ec.ECDSA(hashes.SHA256())).hex(),
            )
        )
        receipt_hashes[party] = hashlib.sha256(encoded).hexdigest()
    approval = dict(statement=claim, authority=authority, issued_at=1000, expires_at=1015)
    encoded = message("CUSTODY_SOLANA_CURRENT_CLAIM_V1", approval)
    approval["custody_authorization"] = dict(
        certificate_chain_der_hex=[custody_cert],
        signature_der_hex=custody.sign(encoded, ec.ECDSA(hashes.SHA256())).hex(),
    )
    result = dict(
        scope=(
            "synthetic public readiness with actual P256 test signatures; no MPC or W registration"
        ),
        evidence=dict(statement=claim, participant_agreement=receipts, authority=authority),
        approval=approval,
        lifecycle_certificate_der_hex=life_cert,
        other_lifecycle_certificate_der_hex=other_life_cert,
        custody_certificate_der_hex=custody_cert,
        message_sha256=dict(custody=hashlib.sha256(encoded).hexdigest(), receipts=receipt_hashes),
    )
    alternate = authority | {
        "prepare": signed(life, life_id, "WITNESS_COMMAND_V1", prepare["value"])
    }
    result["alternate_evidence"] = dict(
        statement=claim,
        authority=alternate,
        participant_agreement=[
            dict(
                statement=claim,
                party_id=p,
                durable=True,
                signer_signature=nodes[p][0]
                .sign(
                    message(
                        "SIGNER_SOLANA_CURRENT_CLAIM_V1",
                        dict(statement=claim, authority=alternate, party_id=p, durable=True),
                    ),
                    ec.ECDSA(hashes.SHA256()),
                )
                .hex(),
            )
            for p in parties
        ],
    )
    result["legacy_evidence"] = dict(
        statement=claim,
        participant_agreement=[
            dict(
                statement=claim,
                party_id=p,
                durable=True,
                signer_signature=nodes[p][0]
                .sign(
                    message(
                        "SIGNER_SOLANA_CLAIM_V1", dict(statement=claim, party_id=p, durable=True)
                    ),
                    ec.ECDSA(hashes.SHA256()),
                )
                .hex(),
            )
            for p in parties
        ],
    )
    result["ca_node_certificate_der_hex"] = identity("signer-a", nodes["signer-a"][0], ca=True)[2]
    (folder / "solana-current-claim-authority.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()
