//! Synthetic public shape contracts; these are not real signature/MPC evidence.
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::PARTIES,
    solana_claim_authority::{
        authorization_message, receipt_message, ClaimAuthority, CurrentClaimApproval,
    },
    solana_provisioning::Claim,
    witness::{hash, Command, CommandAction, GenerationReady, Signed},
};

fn sample() -> (Claim, ClaimAuthority) {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/solana-seeded-intent-sdk.json")).unwrap();
    let intent = &fixture["cases"][0]["intent"];
    let mut claim_value = intent["claim"].clone();
    claim_value["root"] = fixture["root"].clone();
    let claim: Claim = serde_json::from_value(claim_value).unwrap();
    let previous: wallet_mpc_protocol::solana_intent::Generation =
        serde_json::from_value(intent["generation"].clone()).unwrap();
    let mut generation: wallet_mpc_protocol::solana_intent::Generation = previous.clone();
    generation.epoch += 1;
    generation.ceremony_id = Uuid::from_u128(700);
    let keys: BTreeMap<_, _> = PARTIES
        .iter()
        .map(|party| {
            (
                party.to_string(),
                hash(format!("current-{party}").as_bytes()),
            )
        })
        .collect();
    let ready = PARTIES
        .iter()
        .map(|party| Signed {
            key_id: keys[*party].clone(),
            signature: "00".repeat(70),
            value: GenerationReady {
                root_identity: claim.root.identity().unwrap(),
                previous_generation: previous.clone(),
                generation: generation.clone(),
                public_key_package: claim.root.public_key_package.clone(),
                party_id: party.to_string(),
            },
        })
        .collect();
    let authority = ClaimAuthority {
        version: 1,
        prepare: Box::new(Signed {
            key_id: hash(b"lifecycle"),
            signature: "11".repeat(70),
            value: Command {
                anchor_id: Uuid::from_u128(701),
                request_id: Uuid::from_u128(702),
                root_identity: claim.root.identity().unwrap(),
                expected_revision: 2,
                expires_at: 1,
                action: CommandAction::Prepare {
                    ready,
                    node_keys: keys,
                },
            },
        }),
        node_certificates_der_hex: PARTIES
            .iter()
            .map(|party| (party.to_string(), "01".repeat(256)))
            .collect(),
    };
    (claim, authority)
}

#[test]
fn current_receipt_domains_bind_original_claim_and_complete_archival_authority() {
    let (claim, authority) = sample();
    authority.validate_shape(&claim.root).unwrap();
    // The expired Prepare is archival authorization, not a new live command.
    assert!(authority.prepare.value.validate(1000).is_err());
    let old =
        wallet_mpc_protocol::solana_provisioning::receipt_message("claim", &claim, PARTIES[0])
            .unwrap();
    let current = receipt_message(&authority, &claim, PARTIES[0]).unwrap();
    assert!(current.starts_with(b"Wallet-MPC/SIGNER_SOLANA_CURRENT_CLAIM_V1\0"));
    assert_ne!(old, current);
    assert_ne!(
        authorization_message(&authority, &claim, 1000, 1015).unwrap(),
        current
    );
    let mut other = claim.clone();
    other.reservation_id = Uuid::from_u128(703);
    assert_ne!(
        current,
        receipt_message(&authority, &other, PARTIES[0]).unwrap()
    );
    assert_ne!(
        current,
        receipt_message(&authority, &claim, PARTIES[1]).unwrap()
    );
    assert!(receipt_message(&authority, &claim, "signer-d").is_err());
}

#[test]
fn malformed_or_cross_root_authority_cannot_define_current_receipt_roster() {
    let (claim, authority) = sample();
    for fault in 0..13 {
        let mut changed = authority.clone();
        match fault {
            0 => changed.version = 2,
            1 => changed.prepare.value.anchor_id = Uuid::nil(),
            2 => changed.prepare.value.root_identity = hash(b"other root"),
            3 => changed.prepare.value.action = CommandAction::Activate,
            4 => {
                changed.node_certificates_der_hex.remove(PARTIES[2]);
            }
            5 => {
                changed
                    .node_certificates_der_hex
                    .insert(PARTIES[0].into(), "FF".repeat(256));
            }
            6 => changed.prepare.signature = "ff".into(),
            _ => {
                let CommandAction::Prepare { ready, node_keys } = &mut changed.prepare.value.action
                else {
                    unreachable!()
                };
                match fault {
                    7 => {
                        ready.pop();
                    }
                    8 => ready[0].value.generation.epoch = 0,
                    9 => ready[1].value.party_id = PARTIES[0].into(),
                    10 => {
                        node_keys.insert(PARTIES[0].into(), changed.prepare.key_id.clone());
                    }
                    11 => ready[2].value.public_key_package[0] ^= 1,
                    _ => {
                        for item in ready {
                            item.value.previous_generation.ceremony_id = Uuid::from_u128(799);
                        }
                    }
                }
            }
        }
        assert!(
            changed.validate_shape(&claim.root).is_err(),
            "accepted fault{fault}"
        );
    }
}

#[test]
fn live_custody_approval_ttl_is_separate_from_archival_roster_authority() {
    let (claim, authority) = sample();
    let request = CurrentClaimApproval {
        statement: claim,
        authority,
        issued_at: 1000,
        expires_at: 1015,
        custody_authorization: wallet_mpc_protocol::sign::CustodyAuthorization {
            certificate_chain_der_hex: vec![],
            signature_der_hex: String::new(),
        },
    };
    assert!(request.validate_live(1000).is_ok());
    assert!(request.validate_live(1014).is_ok());
    assert!(request.validate_live(999).is_err());
    assert!(request.validate_live(1015).is_err());
    let mut changed = request.clone();
    changed.expires_at = 1301;
    assert!(changed.validate_live(1000).is_err());
    changed.expires_at = 1014;
    assert_ne!(request.message().unwrap(), changed.message().unwrap());
}

#[test]
fn absent_authority_retains_original_evidence_bytes_and_root_validation_is_strict() {
    use wallet_mpc_protocol::solana_provisioning::{Evidence, Report};
    let (claim, authority) = sample();
    let reports = PARTIES
        .iter()
        .map(|party| Report {
            statement: claim.clone(),
            party_id: party.to_string(),
            durable: true,
            signer_signature: "00".repeat(70),
        })
        .collect();
    let original = Evidence {
        statement: claim.clone(),
        participant_agreement: reports,
        authority: None,
    };
    let old = serde_json::json!({"statement":original.statement,"participant_agreement":original.participant_agreement});
    assert_eq!(serde_json::to_value(&original).unwrap(), old);
    let recovered: Evidence<Claim> = serde_json::from_value(old.clone()).unwrap();
    assert!(recovered.authority.is_none());
    assert_eq!(serde_json::to_value(recovered).unwrap(), old);
    let mut current = original;
    current.authority = Some(Box::new(authority.clone()));
    assert!(current.validate().is_err());
    assert!(current.validate_claim().is_ok());
    let root = current.statement.root.clone();
    let root_evidence = Evidence {
        statement: root.clone(),
        authority: Some(Box::new(authority)),
        participant_agreement: PARTIES
            .iter()
            .map(|party| Report {
                statement: root.clone(),
                party_id: party.to_string(),
                durable: true,
                signer_signature: "00".repeat(70),
            })
            .collect(),
    };
    assert!(root_evidence.validate().is_err());
}
