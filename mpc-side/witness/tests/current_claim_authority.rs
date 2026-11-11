//! Actual public-signature verification; fixture readiness is explicitly synthetic.
use wallet_mpc_protocol::{
    solana_claim_authority::{receipt_message, CurrentClaimApproval},
    solana_provisioning::{Claim, Evidence},
    witness::hash,
};
use wallet_mpc_transport::{verify_bound_public_identity, PinnedIdentity, AUTHORITY_ROLES, ROLES};

fn verify_current_claim_evidence(
    evidence: &Evidence<Claim>,
    life: &PinnedIdentity,
) -> anyhow::Result<()> {
    wallet_mpc_protocol::solana_claim_authority::verify_evidence(
        evidence,
        &life.key_id,
        |message, signature| life.verify(message, signature),
        |der, role, expected, message, signature| {
            verify_bound_public_identity(der, role, &ROLES, expected, message, signature)
        },
    )
}

fn sample() -> (serde_json::Value, Evidence<Claim>, PinnedIdentity) {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../protocol/tests/fixtures/solana-current-claim-authority.json"
    ))
    .unwrap();
    let evidence = serde_json::from_value(value["evidence"].clone()).unwrap();
    let der = wallet_mpc_protocol::sign::decode_hex(
        value["lifecycle_certificate_der_hex"].as_str().unwrap(),
    )
    .unwrap();
    let life = PinnedIdentity::from_der_certificate(&der, "lifecycle", &AUTHORITY_ROLES).unwrap();
    (value, evidence, life)
}

#[test]
fn python_canonical_authorization_and_actual_three_receipts_verify() {
    let (value, evidence, life) = sample();
    verify_current_claim_evidence(&evidence, &life).unwrap();
    assert!(evidence.statement.idempotency_key.contains('آ'));
    let alternate: Evidence<Claim> =
        serde_json::from_value(value["alternate_evidence"].clone()).unwrap();
    assert_ne!(evidence, alternate);
    verify_current_claim_evidence(&alternate, &life).unwrap();
    let approval: CurrentClaimApproval = serde_json::from_value(value["approval"].clone()).unwrap();
    assert_eq!(
        hash(&approval.message().unwrap()),
        value["message_sha256"]["custody"]
    );
    let der = wallet_mpc_protocol::sign::decode_hex(
        value["custody_certificate_der_hex"].as_str().unwrap(),
    )
    .unwrap();
    let custody = PinnedIdentity::from_der_certificate(&der, "custody", &AUTHORITY_ROLES).unwrap();
    custody
        .verify(
            &approval.message().unwrap(),
            &wallet_mpc_protocol::sign::decode_hex(
                &approval.custody_authorization.signature_der_hex,
            )
            .unwrap(),
        )
        .unwrap();
    for party in wallet_mpc_protocol::dkg::PARTIES {
        assert_eq!(
            hash(
                &receipt_message(
                    evidence.authority.as_ref().unwrap(),
                    &evidence.statement,
                    party
                )
                .unwrap()
            ),
            value["message_sha256"]["receipts"][party]
        );
    }
}

#[test]
fn a_ca_certificate_cannot_be_substituted_for_the_same_authorized_receipt_key() {
    let (value, evidence, _) = sample();
    let authority = evidence.authority.as_ref().unwrap();
    let (ready, keys) = authority.prepared().unwrap();
    let der = wallet_mpc_protocol::sign::decode_hex(
        value["ca_node_certificate_der_hex"].as_str().unwrap(),
    )
    .unwrap();
    assert!(verify_bound_public_identity(
        &der,
        "signer-a",
        &ROLES,
        &keys["signer-a"],
        &ready[0]
            .signing_message("WITNESS_GENERATION_READY_V1")
            .unwrap(),
        &ready[0].signature_bytes().unwrap()
    )
    .is_err());
}

#[test]
fn forged_or_malformed_some_authority_never_becomes_legacy_evidence() {
    let (value, evidence, life) = sample();
    for fault in 0..5 {
        let mut changed = evidence.clone();
        match fault {
            0 => changed.authority.as_mut().unwrap().version = 2,
            1 => changed.authority.as_mut().unwrap().prepare.signature = "00".repeat(70),
            2 => changed.participant_agreement[1].signer_signature = "00".repeat(70),
            3 => {
                changed.statement.idempotency_key = "other-claim".into();
                for report in &mut changed.participant_agreement {
                    report.statement = changed.statement.clone();
                }
            }
            _ => {
                let auth = changed.authority.as_mut().unwrap();
                let cert = auth.node_certificates_der_hex["signer-a"].clone();
                auth.node_certificates_der_hex
                    .insert("signer-b".into(), cert);
            }
        }
        assert!(
            verify_current_claim_evidence(&changed, &life).is_err(),
            "accepted fault{fault}"
        );
        assert!(changed.validate().is_err());
    }
    let der = wallet_mpc_protocol::sign::decode_hex(
        value["other_lifecycle_certificate_der_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let other = PinnedIdentity::from_der_certificate(&der, "lifecycle", &AUTHORITY_ROLES).unwrap();
    assert!(verify_current_claim_evidence(&evidence, &other).is_err());
}
