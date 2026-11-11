"""Public P256 cross-language contracts; readiness is synthetic, not MPC evidence."""

import copy
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from custody.mpc_binding import MpcBindingError
from custody.solana_claim_authority import verify_current_claim


@pytest.fixture
def current(tmp_path):
    path = Path(__file__).resolve().parents[3] / "mpc-side/protocol/tests/fixtures"
    fixture = json.loads((path / "solana-current-claim-authority.json").read_text())
    certificate = x509.load_der_x509_certificate(
        bytes.fromhex(fixture["lifecycle_certificate_der_hex"])
    )
    pin = tmp_path / "life-public.pem"
    pin.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return fixture, pin


def check(fixture, pin, evidence=None):
    original = fixture["evidence"]
    verify_current_claim(
        original["statement"],
        evidence if evidence is not None else original,
        lifecycle_certificate=pin,
        witness_anchor_id=original["authority"]["prepare"]["value"]["anchor_id"],
    )


@pytest.mark.parametrize("variant", ["evidence", "alternate_evidence"])
def test_actual_public_p256_contract_and_utf8_canonicalization(current, variant):
    fixture, pin = current
    check(fixture, pin, fixture[variant])


@pytest.mark.parametrize("fault", range(20))
def test_untrusted_public_fields_and_archival_pins_fail_closed(current, fault):
    fixture, pin = current
    evidence = copy.deepcopy(fixture["evidence"])
    authority = evidence["authority"]
    command = authority["prepare"]["value"]
    if fault == 0:
        evidence = fixture["legacy_evidence"]
    elif fault == 1:
        authority["version"] = True
    elif fault == 2:
        authority["extra"] = "not a field"
    elif fault == 3:
        authority["prepare"]["signature"] = "00" * 70
    elif fault == 4:
        command["anchor_id"] = None
    elif fault == 5:
        command["root_identity"] = "00" * 32
    elif fault == 6:
        authority["node_certificates_der_hex"].pop("signer-c")
    elif fault == 7:
        authority["node_certificates_der_hex"]["signer-a"] += "00"
    elif fault == 8:
        authority["node_certificates_der_hex"]["signer-a"] = fixture["ca_node_certificate_der_hex"]
    elif fault == 9:
        command["action"]["node_keys"]["signer-a"] = authority["prepare"]["key_id"]
    elif fault == 10:
        command["action"]["ready"].reverse()
    elif fault == 11:
        command["action"]["ready"][0]["value"]["generation"]["epoch"] = True
    elif fault == 12:
        evidence["participant_agreement"].reverse()
    elif fault == 13:
        evidence["participant_agreement"][0]["durable"] = 1
    elif fault == 14:
        evidence["participant_agreement"][0]["signer_signature"] = "00" * 70
    elif fault == 15:
        evidence["statement"]["owner_ref"] += "other"
    elif fault == 16:
        evidence["participant_agreement"].pop()
    elif fault == 17:
        evidence["participant_agreement"][0]["extra"] = True
    elif fault == 18:
        cert = x509.load_der_x509_certificate(
            bytes.fromhex(fixture["other_lifecycle_certificate_der_hex"])
        )
        pin.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    else:
        pin.unlink()
    with pytest.raises(MpcBindingError):
        check(fixture, pin, evidence)


@pytest.mark.parametrize("bad", [None, [], {}, True, "garbage"])
def test_malformed_evidence_never_falls_back_to_original_receipts(current, bad):
    fixture, pin = current
    with pytest.raises(MpcBindingError):
        verify_current_claim(
            fixture["evidence"]["statement"],
            bad,
            lifecycle_certificate=pin,
            witness_anchor_id="00000000-0000-0000-0000-000000000001",
        )
