//! State-only: synthetic dealer public wire and fake P256 proofs bypass Trust.
//! Real node/RPC/W acceptance separately verifies every authority signature.
use super::*;
use crate::state::{Execution, LogicalOperation};
use std::collections::BTreeMap;
use uuid::Uuid;
use wallet_mpc_protocol::{
    solana_finality::{
        FinalityFact, FinalityLease, FinalityObservation, FinalityOutcome, FinalityRequest,
        ObservedFinality,
    },
    solana_provisioning::{Evidence, Report},
    witness::{hash, CommandAction, ExecutionView, PermitRequest, Query, QueryReply, RootView},
};
fn signed<T>(key: &str, value: T) -> Signed<T> {
    Signed {
        key_id: key.into(),
        value,
        signature: "30".repeat(8),
    }
}
fn evidence<T: Clone>(value: T) -> Evidence<T> {
    Evidence {
        statement: value.clone(),
        authority: None,
        participant_agreement: PARTIES
            .iter()
            .map(|p| Report {
                statement: value.clone(),
                party_id: (*p).into(),
                durable: true,
                signer_signature: "30".repeat(70),
            })
            .collect(),
    }
}
fn command(s: &Snapshot, root: &str, action: CommandAction) -> Command {
    Command {
        anchor_id: s.anchor_id,
        request_id: Uuid::new_v4(),
        root_identity: root.into(),
        expected_revision: s.roots.get(root).map_or(0, |r| r.revision),
        expires_at: 1200,
        action,
    }
}
fn apply(s: &mut Snapshot, c: &Command) -> Result<bool> {
    c.validate(1003)?;
    let mut candidate = s.clone();
    let changed = candidate.command_at(c, 1003)?;
    *s = candidate;
    Ok(changed)
}
fn setup() -> (Snapshot, FinalityRequest) {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/tests/fixtures/solana-finality-synthetic-public.json"
    ))
    .unwrap();
    let mut request: FinalityRequest = serde_json::from_value(f["request"].clone()).unwrap();
    request.binding.authorized.claim_evidence =
        evidence(request.binding.authorized.intent.claim.clone());
    let p = request.plan();
    let root = p.root.identity().unwrap();
    let mut s = Snapshot::empty(p.witness_anchor).unwrap();
    s.journal_rules = 5;
    let c = command(
        &s,
        &root,
        CommandAction::Enroll {
            evidence: Box::new(evidence(p.root.clone())),
            node_keys: p.observing_node_keys.clone(),
        },
    );
    apply(&mut s, &c).unwrap();
    let c = command(
        &s,
        &root,
        CommandAction::RegisterClaim {
            evidence: Box::new(request.binding.authorized.claim_evidence.clone()),
        },
    );
    apply(&mut s, &c).unwrap();
    let logical = request.binding.authorized.operation_key().unwrap();
    s.operations.insert(
        logical,
        LogicalOperation {
            business_fingerprint: request.binding.authorized.business_fingerprint().unwrap(),
            executions: vec![p.execution_id],
        },
    );
    s.executions.insert(
        p.execution_id,
        Execution {
            binding: request.binding.clone(),
            root_identity: root.clone(),
            package: request.signing_public_key_package.clone(),
            node_keys: p.observing_node_keys.clone(),
            grants: BTreeMap::new(),
            reports: BTreeMap::new(),
            signing_package: None,
            status: ExecutionStatus::SignedPending,
            signature: Some(p.signature_hex.clone()),
        },
    );
    let c = command(&s, &root, CommandAction::Freeze);
    apply(&mut s, &c).unwrap();
    request.authorization.value.expected_revision = s.roots[&root].revision;
    (s, request)
}
fn reports(s: &Snapshot, request: &FinalityRequest) -> Vec<Signed<FinalityReady>> {
    let p = request.plan();
    let root = &s.roots[&p.root.identity().unwrap()];
    let wire = request.validate_archived_wire().unwrap();
    PARTIES
        .iter()
        .enumerate()
        .map(|(index, party)| {
            let key = &p.observing_node_keys[*party];
            let initial = Query {
                anchor_id: s.anchor_id,
                root_identity: p.root.identity().unwrap(),
                challenge: hash(format!("{party}:initial").as_bytes()),
                execution_id: Some(p.execution_id),
                claim_reservation_id: None,
                candidate_claim: None,
                materialization_id: None,
            };
            let final_query = Query {
                challenge: hash(format!("{party}:final").as_bytes()),
                ..initial.clone()
            };
            let view = |query: Query| QueryReply {
                query,
                sequence: s.sequence,
                root: RootView {
                    original: p.root.clone(),
                    revision: root.revision,
                    phase: root.phase.clone(),
                    generation: root.generation.clone(),
                    public_key_package: root.public_key_package.clone(),
                    node_keys: root.node_keys.clone(),
                    prepared: None,
                    next_claim_index: 1,
                    financial_mode: None,
                    rotation: None,
                },
                execution: Some(ExecutionView {
                    binding_fingerprint: p.binding_fingerprint.clone(),
                    status: ExecutionStatus::SignedPending,
                    signature: Some(p.signature_hex.clone()),
                    reports: BTreeMap::new(),
                    finality: None,
                }),
                abandoned: false,
                claim: None,
                lifecycle_key_id: Some(request.authorization.key_id.clone()),
                claim_issuance: None,
                replacement: None,
                node_profiles: BTreeMap::new(),
                refresh: None,
                claim_availability: None,
                generation_authority: None,
                inventory_materialization: None,
            };
            let lease = FinalityLease {
                request: request.clone(),
                query: signed(key, initial.clone()),
                issued_at: 1000,
                expires_at: 1015,
            };
            let observed = ObservedFinality {
                lease,
                initial_witness: signed(&"aa".repeat(32), view(initial)),
                observation: FinalityObservation {
                    fact: FinalityFact {
                        transaction_slot: 400,
                        wire_fingerprint: hash(&wire),
                        message_fingerprint: request
                            .binding
                            .authorized
                            .intent
                            .message_fingerprint
                            .clone(),
                        metadata_fingerprint: hash(b"synthetic public metadata"),
                        fee_lamports: request.binding.authorized.intent.expected_fee_lamports,
                        outcome: FinalityOutcome::Succeeded {},
                    },
                    status_context_slot: 500 + u64::try_from(index).unwrap(),
                },
                final_query: signed(key, final_query.clone()),
                observed_at: 1001,
            };
            signed(
                key,
                FinalityReady {
                    party_id: (*party).into(),
                    observed,
                    final_witness: signed(&"aa".repeat(32), view(final_query)),
                    profile_fingerprint: hash(party.as_bytes()),
                    reported_at: 1002,
                },
            )
        })
        .collect()
}
#[test]
fn current_all_three_ack_preserves_signature_status_and_separate_observer_banks() {
    let (mut s, r) = setup();
    let root = r.plan().root.identity().unwrap();
    let original = s.executions[&r.plan().execution_id].clone();
    let c = command(
        &s,
        &root,
        CommandAction::AcknowledgeFinality {
            reports: reports(&s, &r),
        },
    );
    assert!(apply(&mut s, &c).unwrap());
    assert_eq!(s.executions[&r.plan().execution_id], original);
    let fact = &s.finalities[&r.plan().execution_id];
    assert_eq!(fact.status_context_slots.len(), 3);
    assert_eq!(fact.status_context_slots[PARTIES[0]], 500);
    assert_eq!(fact.status_context_slots[PARTIES[2]], 502);
    assert_eq!(fact.command_id, c.request_id);
    assert_eq!(fact.sequence, s.sequence);
    assert!(!apply(&mut s, &c).unwrap());
}
#[test]
fn wrong_quorum_fact_current_context_or_unsigned_execution_cannot_be_acknowledged() {
    let (s, r) = setup();
    let root = r.plan().root.identity().unwrap();
    for fault in 0..10 {
        let mut candidate = s.clone();
        let mut ready = reports(&candidate, &r);
        match fault {
            0 => {
                ready.pop();
            }
            1 => ready[2] = ready[1].clone(),
            2 => {
                ready[2]
                    .value
                    .observed
                    .observation
                    .fact
                    .metadata_fingerprint = hash(b"different terminal metadata")
            }
            3 => {
                candidate
                    .executions
                    .get_mut(&r.plan().execution_id)
                    .unwrap()
                    .status = ExecutionStatus::Open
            }
            4 => {
                candidate
                    .executions
                    .get_mut(&r.plan().execution_id)
                    .unwrap()
                    .signature = Some("00".repeat(64))
            }
            5 => candidate.roots.get_mut(&root).unwrap().phase = Phase::Active,
            6 => {
                candidate
                    .roots
                    .get_mut(&root)
                    .unwrap()
                    .node_keys
                    .insert(PARTIES[0].into(), "bb".repeat(32));
            }
            7 => candidate.journal_rules = 4,
            8 => ready[0].value.final_witness.value.query.challenge = hash(b"other nonce"),
            9 => ready[0].value.profile_fingerprint = "00".repeat(32),
            _ => unreachable!(),
        }
        let before = candidate.clone();
        let c = command(
            &candidate,
            &root,
            CommandAction::AcknowledgeFinality { reports: ready },
        );
        assert!(apply(&mut candidate, &c).is_err(), "fault {fault}");
        assert_eq!(candidate, before);
    }
}
#[test]
fn finalized_failure_never_becomes_no_signature_or_releases_logical_attempt_ownership() {
    let (mut s, r) = setup();
    let root = r.plan().root.identity().unwrap();
    let mut ready = reports(&s, &r);
    for report in &mut ready {
        report.value.observed.observation.fact.outcome = FinalityOutcome::Failed {
            error_fingerprint: hash(b"actual terminal error reference"),
        };
    }
    let c = command(
        &s,
        &root,
        CommandAction::AcknowledgeFinality { reports: ready },
    );
    apply(&mut s, &c).unwrap();
    // Give the retry an otherwise eligible source context to isolate the old
    // logical ownership check; this is not a new production activation path.
    s.roots.get_mut(&root).unwrap().phase = Phase::Active;
    let mut binding = r.binding.clone();
    binding.authorized.intent.crypto_execution_id = Uuid::new_v4();
    binding.authorized.intent.session_id = Uuid::new_v4();
    binding.authorized.intent.attempt_id += 1;
    let req = PermitRequest {
        anchor_id: s.anchor_id,
        binding,
        party_id: PARTIES[0].into(),
        round: 1,
        challenge: hash(b"fresh retry challenge"),
        expires_at: 1010,
        signing_package: None,
        node_profile_sha256: None,
    };
    assert!(s
        .permit(&req, &r.plan().observing_node_keys[PARTIES[0]], 1003)
        .unwrap_err()
        .to_string()
        .contains("already possibly signed"));
    assert_eq!(
        s.executions[&r.plan().execution_id].status,
        ExecutionStatus::SignedPending
    );
}
#[test]
fn expired_report_and_reused_public_observation_identity_remain_closed() {
    let (mut s, r) = setup();
    let root = r.plan().root.identity().unwrap();
    let c = command(
        &s,
        &root,
        CommandAction::AcknowledgeFinality {
            reports: reports(&s, &r),
        },
    );
    assert!(c.validate(1015).is_err());
    apply(&mut s, &c).unwrap();
    let id = r.plan().observation_id;
    let mut next = command(
        &s,
        &root,
        CommandAction::AbandonRefresh {
            ceremony_id: Uuid::new_v4(),
        },
    );
    next.request_id = id;
    assert!(apply(&mut s, &next).is_err());
    assert!(s.migration_identity_used(id));
}
#[test]
fn source_profile_cohort_pending_elsewhere_blocks_even_matching_public_views() {
    let (mut s, r) = setup();
    let root = r.plan().root.identity().unwrap();
    let ready = reports(&s, &r);
    let fence = crate::state::tests::migration_fence(&s, std::slice::from_ref(&r.binding));
    let id = fence.value.approvals.plan().migration_id;
    s.profile_migrations.insert(
        id,
        wallet_mpc_protocol::solana_profile_migration::MigrationReservation {
            fence,
            renewal: None,
            first_command_id: Uuid::new_v4(),
            root_commands: BTreeMap::new(),
        },
    );
    let c = command(
        &s,
        &root,
        CommandAction::AcknowledgeFinality { reports: ready },
    );
    assert!(apply(&mut s, &c).is_err());
    assert!(s.finalities.is_empty());
}

pub(crate) fn admission_command() -> Command {
    let (s, r) = setup();
    command(
        &s,
        &r.plan().root.identity().unwrap(),
        CommandAction::AcknowledgeFinality {
            reports: reports(&s, &r),
        },
    )
}
