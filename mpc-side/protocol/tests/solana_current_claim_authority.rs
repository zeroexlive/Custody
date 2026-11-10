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
        rotation: None,
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

fn rotation_request() -> CurrentClaimApproval {
    use wallet_mpc_protocol::{
        solana_financial::SourceRole,
        solana_intent::Generation,
        solana_provisioning::{Asset, Root},
        solana_rotation::{
            inventory_fingerprint, FinancialPublication, MigrationSource, RotationApprovals,
            RotationDestination, RotationPlan, SourceMembership,
        },
        witness::ClaimIssuance,
    };
    let (claim, authority) = sample();
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/solana-rotation-roots.json")).unwrap();
    let mut target: Root = serde_json::from_value(fixture["target"]["root"].clone()).unwrap();
    target.ownership_scope = claim.root.ownership_scope.clone();
    target.genesis_hash = claim.root.genesis_hash.clone();
    let destination = Claim {
        root: target.clone(),
        index: 0,
        reservation_id: Uuid::new_v4(),
        owner_ref: format!("p1:{}", Uuid::new_v4()),
        idempotency_key: "target".into(),
        asset: Asset::Native,
    };
    let source = MigrationSource {
        claim: claim.clone(),
        asset_key: "SOL".into(),
        role: SourceRole::CustomerDeposit,
        membership: SourceMembership::Unpublished {},
        witness_evidence_fingerprint: None,
    };
    let plan = RotationPlan {
        version: 1,
        rotation_id: Uuid::new_v4(),
        authorization_id: Uuid::new_v4(),
        witness_anchor: authority.prepare.value.anchor_id,
        source: claim.root.clone(),
        source_generation: authority.generation().unwrap().clone(),
        source_node_keys: authority.prepared().unwrap().1.clone(),
        target: target.clone(),
        target_generation: Generation {
            epoch: 0,
            ceremony_id: target.dkg.execution_id,
            public_key_package_sha256: hash(&target.public_key_package),
        },
        target_node_keys: serde_json::from_value(fixture["target"]["node_keys"].clone()).unwrap(),
        allocated_high_water: 1,
        inventory_fingerprint: inventory_fingerprint(&claim.root, 1, &[source]).unwrap(),
        destinations: vec![RotationDestination {
            treasury: MigrationSource {
                claim: destination.clone(),
                asset_key: "SOL".into(),
                role: SourceRole::TenantTreasury,
                membership: SourceMembership::Financial {
                    issuance: ClaimIssuance {
                        reservation_id: destination.reservation_id,
                        issuance_id: Uuid::new_v4(),
                        command_id: Uuid::new_v4(),
                        initialization_execution_id: None,
                    },
                    publication: FinancialPublication::Active,
                },
                witness_evidence_fingerprint: Some(hash(b"target proof")),
            },
        }],
        max_fee_per_movement_lamports: 10000,
        total_fee_budget_lamports: 20000,
        retained_root_gas_lamports: 1000000,
        retained_classic_rent_lamports: 0,
        expires_at: 1100,
    };
    let approvals = RotationApprovals {
        custody: Signed {
            key_id: hash(b"custody"),
            value: plan.clone(),
            signature: "11".repeat(70),
        },
        policy: Signed {
            key_id: hash(b"policy"),
            value: plan,
            signature: "22".repeat(70),
        },
        custody_certificate_chain_der_hex: vec!["01".into()],
        policy_certificate_chain_der_hex: vec!["02".into()],
    };
    CurrentClaimApproval {
        statement: claim,
        authority,
        issued_at: 1000,
        expires_at: 1010,
        custody_authorization: wallet_mpc_protocol::sign::CustodyAuthorization {
            certificate_chain_der_hex: vec![],
            signature_der_hex: String::new(),
        },
        rotation: Some(Box::new(approvals)),
    }
}

#[test]
fn rotation_claim_context_uses_distinct_custody_domain_and_keeps_ordinary_bytes() {
    let request = rotation_request();
    request.validate_live(1000).unwrap();
    let message = request.message().unwrap();
    assert!(message.starts_with(b"Wallet-MPC/CUSTODY_SOLANA_ROTATION_CLAIM_V1\0"));
    let mut ordinary = request.clone();
    ordinary.rotation = None;
    assert_eq!(
        ordinary.message().unwrap(),
        authorization_message(&ordinary.authority, &ordinary.statement, 1000, 1010).unwrap()
    );
    assert!(serde_json::to_value(&ordinary)
        .unwrap()
        .get("rotation")
        .is_none());
    assert_ne!(message, ordinary.message().unwrap());
    let mut changed = request.clone();
    changed
        .rotation
        .as_mut()
        .unwrap()
        .custody
        .value
        .source_generation
        .epoch += 1;
    assert!(changed.message().is_err());
    let mut backdated = request.clone();
    backdated.issued_at = 799;
    backdated.expires_at = 1050;
    assert!(backdated.message().is_err()); // C/P must also be fresh at the original approval time.
    let mut expired = request;
    expired.expires_at = 1200;
    assert!(expired.validate_live(1100).is_err()); // live C/P plan is still required.
}

#[test]
fn frozen_rotation_claim_report_requires_exact_sealed_rotation_and_original_lease() {
    use wallet_mpc_protocol::{
        solana_claim_authority::ClaimQueryLease,
        solana_rotation::{RotationStatus, RotationView},
        witness::{ClaimAvailability, Phase, Query, QueryReply, RootView},
    };
    let mut approval = rotation_request();
    approval.expires_at = 1050; // The original own15s lease expires before either approval.
    let plan = approval.rotation.as_ref().unwrap().plan();
    let party = PARTIES[0];
    let query = Query {
        anchor_id: plan.witness_anchor,
        root_identity: plan.source.identity().unwrap(),
        challenge: hash(b"own query"),
        execution_id: None,
        claim_reservation_id: Some(approval.statement.reservation_id),
        candidate_claim: Some(Box::new(approval.statement.clone())),
        materialization_id: None,
        rotation_id: None,
    };
    let lease = ClaimQueryLease {
        approval: approval.clone(),
        query: Signed {
            value: query.clone(),
            key_id: approval.authority.prepared().unwrap().1[party].clone(),
            signature: "11".repeat(70),
        },
        issued_at: 1000,
        expires_at: 1015,
    };
    let reply = QueryReply {
        query,
        sequence: 5,
        root: RootView {
            original: approval.statement.root.clone(),
            revision: 4,
            phase: Phase::Frozen,
            generation: approval.authority.generation().unwrap().clone(),
            public_key_package: approval.authority.prepared().unwrap().0[0]
                .value
                .public_key_package
                .clone(),
            node_keys: approval.authority.prepared().unwrap().1.clone(),
            prepared: None,
            next_claim_index: 0,
            financial_mode: None,
            rotation: Some(RotationView {
                rotation_id: plan.rotation_id,
                source_identity: plan.source.identity().unwrap(),
                target_identity: plan.target.identity().unwrap(),
                business_fingerprint: plan.business_fingerprint().unwrap(),
                status: RotationStatus::Sealed,
                next_index: 1,
                allocated_high_water: 1,
                inventory_fingerprint: plan.inventory_fingerprint.clone(),
            }),
        },
        execution: None,
        abandoned: false,
        claim: None,
        lifecycle_key_id: Some(approval.authority.prepare.key_id.clone()),
        claim_issuance: None,
        replacement: None,
        node_profiles: BTreeMap::new(),
        refresh: None,
        claim_availability: Some(ClaimAvailability {
            reservation_id: approval.statement.reservation_id,
            index: None,
            owner: None,
            retry: None,
        }),
        generation_authority: Some(approval.authority.prepare.clone()),
        inventory_materialization: None,
        rotation_claim_registration: None,
    };
    lease.validate_new_report(&reply, party, 1001).unwrap();
    for fault in 0..6 {
        let mut altered = reply.clone();
        match fault {
            0 => altered.root.phase = Phase::Active,
            1 => altered.root.rotation.as_mut().unwrap().rotation_id = Uuid::new_v4(),
            2 => altered.root.rotation.as_mut().unwrap().status = RotationStatus::Collecting,
            3 => {
                altered
                    .root
                    .rotation
                    .as_mut()
                    .unwrap()
                    .inventory_fingerprint = hash(b"changed")
            }
            4 => altered.root.rotation.as_mut().unwrap().next_index = 0,
            _ => altered.query.challenge = hash(b"another lease"),
        }
        assert!(
            lease.validate_new_report(&altered, party, 1001).is_err(),
            "fault{fault}"
        );
    }
    assert!(lease.validate_new_report(&reply, party, 1015).is_err());
    let mut ordinary = lease;
    ordinary.approval.rotation = None;
    assert!(ordinary.validate_new_report(&reply, party, 1001).is_err());
}

#[test]
fn rotation_registration_command_accepts_current_evidence_shape_without_original_domain_rewrite() {
    let request = rotation_request();
    let evidence = wallet_mpc_protocol::solana_provisioning::Evidence {
        statement: request.statement.clone(),
        authority: Some(Box::new(request.authority.clone())),
        participant_agreement: PARTIES
            .iter()
            .map(|party| wallet_mpc_protocol::solana_provisioning::Report {
                statement: request.statement.clone(),
                party_id: (*party).into(),
                durable: true,
                signer_signature: "11".repeat(70),
            })
            .collect(),
    };
    assert!(evidence.validate().is_err());
    evidence.validate_claim().unwrap();
    let command = Command {
        anchor_id: request.authority.prepare.value.anchor_id,
        root_identity: request.statement.root.identity().unwrap(),
        request_id: Uuid::new_v4(),
        expected_revision: 4,
        expires_at: 1100,
        action: CommandAction::RegisterRotationClaim {
            approvals: request.rotation.unwrap(),
            evidence: Box::new(evidence),
        },
    };
    command.validate(1000).unwrap();
}
