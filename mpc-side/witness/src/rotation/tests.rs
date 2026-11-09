//! State-only fixtures deliberately bypass Trust. They establish no genuine
//! signature, chain-finality, financial publication or movement acceptance.
use super::*;
use wallet_mpc_protocol::{
    dkg::PARTIES,
    solana_financial::{FinancialModeApprovals, FinancialModePlan, SourceRole},
    solana_intent::Generation,
    solana_provisioning::{Asset, Claim, Evidence, Report, Root},
    solana_rotation::{
        inventory_fingerprint, FinancialPublication, RotationDestination, RotationPlan,
    },
    witness::{hash, CommandAction, Signed},
};
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
fn proof<T: Clone>(value: &T, key: &str) -> Signed<T> {
    Signed {
        key_id: key.repeat(32),
        value: value.clone(),
        signature: "30".repeat(8),
    }
}
fn command(s: &Snapshot, root: &Root, action: CommandAction) -> Command {
    let id = root.identity().unwrap();
    Command {
        anchor_id: s.anchor_id,
        request_id: Uuid::new_v4(),
        root_identity: id.clone(),
        expected_revision: s.roots.get(&id).map_or(0, |r| r.revision),
        expires_at: 1200,
        action,
    }
}
fn apply(s: &mut Snapshot, c: &Command) -> Result<bool> {
    c.validate(1000)?;
    let mut candidate = s.clone();
    let changed = candidate.command_at(c, 1000)?;
    *s = candidate;
    Ok(changed)
}
fn act(s: &mut Snapshot, root: &Root, action: CommandAction) {
    let c = command(s, root, action);
    apply(s, &c).unwrap();
}
fn enable(s: &mut Snapshot, root: &Root) {
    let r = &s.roots[&root.identity().unwrap()];
    let plan = FinancialModePlan {
        version: 1,
        activation_id: Uuid::new_v4(),
        witness_anchor: s.anchor_id,
        root: root.clone(),
        generation: r.generation.clone(),
        node_keys: r.node_keys.clone(),
        expires_at: 1200,
    };
    act(
        s,
        root,
        CommandAction::EnableFinancialMode {
            approvals: Box::new(FinancialModeApprovals {
                custody: proof(&plan, "11"),
                policy: proof(&plan, "22"),
                custody_certificate_chain_der_hex: vec!["01".into()],
                policy_certificate_chain_der_hex: vec!["02".into()],
            }),
        },
    );
}
fn entry(root: &Root, index: u64) -> MigrationSource {
    MigrationSource {
        claim: Claim {
            root: root.clone(),
            index,
            reservation_id: Uuid::new_v4(),
            owner_ref: format!("p1:{}", Uuid::new_v4()),
            idempotency_key: Uuid::new_v4().to_string(),
            asset: Asset::Native,
        },
        asset_key: "SOL".into(),
        role: SourceRole::CustomerDeposit,
        membership: SourceMembership::Unpublished {},
        witness_evidence_fingerprint: None,
    }
}
fn issue(s: &mut Snapshot, entry: &mut MigrationSource, financial: bool) {
    let root = entry.claim.root.clone();
    act(
        s,
        &root,
        CommandAction::RegisterClaim {
            evidence: Box::new(evidence(entry.claim.clone())),
        },
    );
    act(
        s,
        &root,
        CommandAction::IssueNativeClaim {
            reservation_id: entry.claim.reservation_id,
            issuance_id: Uuid::new_v4(),
        },
    );
    entry.witness_evidence_fingerprint = Some(
        fingerprint(
            "SOLANA_ROTATION_CLAIM_EVIDENCE_V1",
            &s.claims[&entry.claim.reservation_id],
        )
        .unwrap(),
    );
    let issuance = s.claim_issuances[&entry.claim.reservation_id].clone();
    entry.membership = if financial {
        SourceMembership::Financial {
            issuance,
            publication: FinancialPublication::Pending,
        }
    } else {
        SourceMembership::LegacyControl {
            issuance: Some(issuance),
        }
    };
}
fn setup(count: u64, financial: bool) -> (Snapshot, RotationApprovals, Vec<MigrationSource>) {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/tests/fixtures/solana-rotation-roots.json"
    ))
    .unwrap();
    let mut s = Snapshot::empty(Uuid::new_v4()).unwrap();
    s.journal_rules = 4;
    let mut roots = vec![];
    for name in ["source", "target"] {
        let root: Root = serde_json::from_value(f[name]["root"].clone()).unwrap();
        let keys = serde_json::from_value(f[name]["node_keys"].clone()).unwrap();
        act(
            &mut s,
            &root,
            CommandAction::Enroll {
                evidence: Box::new(evidence(root.clone())),
                node_keys: keys,
            },
        );
        roots.push(root);
    }
    let (source, target) = (&roots[0], &roots[1]);
    if financial {
        enable(&mut s, source);
    }
    enable(&mut s, target);
    let mut treasury = entry(target, 0);
    issue(&mut s, &mut treasury, true);
    treasury.role = SourceRole::TenantTreasury;
    if let SourceMembership::Financial { publication, .. } = &mut treasury.membership {
        *publication = FinancialPublication::Active;
    }
    let mut entries: Vec<_> = (0..count).map(|n| entry(source, n)).collect();
    if let Some(first) = entries.first_mut() {
        issue(&mut s, first, financial);
    }
    act(&mut s, source, CommandAction::Freeze);
    let a = &s.roots[&source.identity().unwrap()];
    let b = &s.roots[&target.identity().unwrap()];
    let plan = RotationPlan {
        version: 1,
        rotation_id: Uuid::new_v4(),
        authorization_id: Uuid::new_v4(),
        witness_anchor: s.anchor_id,
        source: source.clone(),
        source_generation: a.generation.clone(),
        source_node_keys: a.node_keys.clone(),
        target: target.clone(),
        target_generation: b.generation.clone(),
        target_node_keys: b.node_keys.clone(),
        allocated_high_water: count,
        inventory_fingerprint: inventory_fingerprint(source, count, &entries).unwrap(),
        destinations: vec![RotationDestination { treasury }],
        max_fee_per_movement_lamports: 20000,
        total_fee_budget_lamports: 100000,
        retained_root_gas_lamports: 1000000,
        retained_classic_rent_lamports: 0,
        expires_at: 1200,
    };
    (s, approvals(plan), entries)
}
fn approvals(plan: RotationPlan) -> RotationApprovals {
    RotationApprovals {
        custody: proof(&plan, "11"),
        policy: proof(&plan, "22"),
        custody_certificate_chain_der_hex: vec!["01".into()],
        policy_certificate_chain_der_hex: vec!["02".into()],
    }
}
fn stage(s: &Snapshot, a: &RotationApprovals, entries: &[MigrationSource], start: u64) -> Command {
    command(
        s,
        &a.plan().source,
        CommandAction::StageRotationInventory {
            approvals: Box::new(a.clone()),
            chunk: Box::new(InventoryChunk {
                business_fingerprint: a.plan().business_fingerprint().unwrap(),
                start_index: start,
                entries: entries.to_vec(),
            }),
        },
    )
}
#[test]
fn contiguous_chunks_seal_original_complete_inventory_and_retry_exactly() {
    let (mut s, a, entries) = setup(33, false);
    let wrong = stage(&s, &a, &entries[32..], 32);
    assert!(apply(&mut s, &wrong).is_err());
    let first = stage(&s, &a, &entries[..32], 0);
    assert!(apply(&mut s, &first).unwrap());
    assert!(!apply(&mut s, &first).unwrap());
    let repeat = stage(&s, &a, &entries[..32], 0);
    assert!(apply(&mut s, &repeat).unwrap());
    assert_eq!(s.rotations[&a.plan().rotation_id].entries.len(), 32);
    assert_eq!(
        s.rotation_view(&a.plan().source.identity().unwrap())
            .unwrap()
            .unwrap()
            .status,
        RotationStatus::Collecting
    );
    let last = stage(&s, &a, &entries[32..], 32);
    apply(&mut s, &last).unwrap();
    let view = s
        .rotation_view(&a.plan().source.identity().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(view.status, RotationStatus::Sealed);
    assert_eq!(view.next_index, 33);
    assert_eq!(s.rotations[&view.rotation_id].entries, entries);
}
#[test]
fn final_hash_failure_rolls_back_candidate_and_preserves_all_known_claims() {
    let (mut s, mut a, entries) = setup(2, false);
    a.custody.value.inventory_fingerprint = hash(b"wrong complete manifest");
    a.policy.value = a.custody.value.clone();
    let c = stage(&s, &a, &entries, 0);
    let old = s.clone();
    assert!(apply(&mut s, &c).is_err());
    assert_eq!(s, old);
    let mut plan = a.plan().clone();
    plan.allocated_high_water = 0;
    plan.inventory_fingerprint = inventory_fingerprint(&plan.source, 0, &[]).unwrap();
    let c = stage(&s, &approvals(plan), &[], 0);
    assert!(apply(&mut s, &c).is_err());
}
#[test]
fn zero_inventory_has_one_explicit_sealed_chunk_and_cannot_hide_registered_claims() {
    let (mut s, a, entries) = setup(0, false);
    let c = stage(&s, &a, &entries, 0);
    apply(&mut s, &c).unwrap();
    assert_eq!(
        s.rotations[&a.plan().rotation_id].status,
        RotationStatus::Sealed
    );
    let c = command(
        &s,
        &a.plan().source,
        CommandAction::BeginRotation {
            approvals: Box::new(a.clone()),
        },
    );
    apply(&mut s, &c).unwrap();
    assert_eq!(
        s.roots[&a.plan().source.identity().unwrap()].phase,
        Phase::Migrating
    );
}
#[test]
fn financial_pending_preserves_w_grant_and_rejects_downgrade_or_substitution() {
    let (mut s, a, entries) = setup(1, true);
    for membership in [
        SourceMembership::Unpublished {},
        SourceMembership::LegacyControl { issuance: None },
    ] {
        let mut altered = entries.clone();
        altered[0].membership = membership;
        let mut plan = a.plan().clone();
        plan.inventory_fingerprint = inventory_fingerprint(&plan.source, 1, &altered).unwrap();
        let c = stage(&s, &approvals(plan), &altered, 0);
        assert!(apply(&mut s, &c).is_err());
    }
    let mut altered = entries.clone();
    if let SourceMembership::Financial { issuance, .. } = &mut altered[0].membership {
        issuance.issuance_id = Uuid::new_v4();
    }
    let mut plan = a.plan().clone();
    plan.inventory_fingerprint = inventory_fingerprint(&plan.source, 1, &altered).unwrap();
    let c = stage(&s, &approvals(plan), &altered, 0);
    assert!(apply(&mut s, &c).is_err());
    let c = stage(&s, &a, &entries, 0);
    apply(&mut s, &c).unwrap();
}
#[test]
fn mode_off_issuance_remains_archival_without_inventing_membership() {
    let (mut s, a, entries) = setup(1, false);
    let original = s.claim_issuances[&entries[0].claim.reservation_id].clone();
    for membership in [
        SourceMembership::Unpublished {},
        SourceMembership::LegacyControl { issuance: None },
        SourceMembership::Financial {
            issuance: original,
            publication: FinancialPublication::Active,
        },
    ] {
        let mut changed = entries.clone();
        changed[0].membership = membership;
        let mut plan = a.plan().clone();
        plan.inventory_fingerprint = inventory_fingerprint(&plan.source, 1, &changed).unwrap();
        let c = stage(&s, &approvals(plan), &changed, 0);
        assert!(apply(&mut s, &c).is_err());
    }
    let c = stage(&s, &a, &entries, 0);
    apply(&mut s, &c).unwrap();
    assert!(s.roots[&a.plan().source.identity().unwrap()]
        .financial_mode
        .is_none());
}
#[test]
fn original_evidence_and_target_issuance_are_required_even_with_same_claim() {
    let (mut s, a, entries) = setup(1, false);
    let mut changed = entries.clone();
    changed[0].witness_evidence_fingerprint = Some(hash(b"other evidence"));
    let mut plan = a.plan().clone();
    plan.inventory_fingerprint = inventory_fingerprint(&plan.source, 1, &changed).unwrap();
    let c = stage(&s, &approvals(plan), &changed, 0);
    assert!(apply(&mut s, &c).is_err());
    let mut plan = a.plan().clone();
    plan.destinations[0].treasury.witness_evidence_fingerprint =
        Some(hash(b"other treasury evidence"));
    let c = stage(&s, &approvals(plan), &entries, 0);
    assert!(apply(&mut s, &c).is_err());
    let mut plan = a.plan().clone();
    if let SourceMembership::Financial { issuance, .. } =
        &mut plan.destinations[0].treasury.membership
    {
        issuance.command_id = Uuid::new_v4();
    }
    let c = stage(&s, &approvals(plan), &entries, 0);
    assert!(apply(&mut s, &c).is_err());
}
#[test]
fn fresh_context_cannot_change_business_replenish_budget_or_reuse_old_approval() {
    let (mut s, a, entries) = setup(1, false);
    let c = stage(&s, &a, &entries, 0);
    apply(&mut s, &c).unwrap();
    let mut plan = a.plan().clone();
    plan.authorization_id = Uuid::new_v4();
    plan.expires_at = 1250;
    let renewed = approvals(plan.clone());
    let c = stage(&s, &renewed, &entries, 0);
    apply(&mut s, &c).unwrap();
    assert_eq!(s.rotations[&plan.rotation_id].authorizations.len(), 2);
    plan.authorization_id = Uuid::new_v4();
    plan.total_fee_budget_lamports += 1;
    let c = stage(&s, &approvals(plan), &entries, 0);
    assert!(apply(&mut s, &c).is_err());
    let mut changed = a.clone();
    changed.custody.signature = "31".repeat(8);
    let c = stage(&s, &changed, &entries, 0);
    assert!(apply(&mut s, &c).is_err());
}
#[test]
fn lifecycle_context_requires_current_frozen_source_and_active_target() {
    let (s, a, entries) = setup(1, false);
    for fault in 0..6 {
        let mut changed = s.clone();
        let mut plan = a.plan().clone();
        match fault {
            0 => {
                changed
                    .roots
                    .get_mut(&plan.source.identity().unwrap())
                    .unwrap()
                    .phase = Phase::Active
            }
            1 => {
                changed
                    .roots
                    .get_mut(&plan.target.identity().unwrap())
                    .unwrap()
                    .phase = Phase::Frozen
            }
            2 => {
                plan.source_generation = Generation {
                    epoch: 1,
                    ceremony_id: Uuid::new_v4(),
                    public_key_package_sha256: hash(b"stale"),
                }
            }
            3 => {
                plan.target_generation = Generation {
                    epoch: 1,
                    ceremony_id: Uuid::new_v4(),
                    public_key_package_sha256: hash(b"stale target"),
                }
            }
            4 => {
                changed
                    .roots
                    .get_mut(&plan.target.identity().unwrap())
                    .unwrap()
                    .financial_mode = None
            }
            5 => changed.journal_rules = 3,
            _ => unreachable!(),
        }
        let c = stage(&changed, &approvals(plan), &entries, 0);
        assert!(apply(&mut changed, &c).is_err(), "fault{fault}");
    }
}
#[test]
fn globally_reserved_claim_issuance_keyset_and_command_ids_cannot_be_approvals() {
    let (s, a, entries) = setup(1, false);
    for id in [
        entries[0].claim.reservation_id,
        s.claim_issuances[&entries[0].claim.reservation_id].issuance_id,
        a.plan().source.dkg.keyset_id,
        *s.commands.keys().next().unwrap(),
    ] {
        let mut changed = s.clone();
        let mut plan = a.plan().clone();
        plan.authorization_id = id;
        let mut c = stage(&changed, &a, &entries, 0);
        if let CommandAction::StageRotationInventory {
            approvals: actual, ..
        } = &mut c.action
        {
            *actual = Box::new(approvals(plan));
        }
        assert!(apply(&mut changed, &c).is_err());
    }
}
#[test]
fn staging_and_migration_fence_ordinary_lifecycle_and_preserve_abandoned_tombstones() {
    let (mut s, a, entries) = setup(1, false);
    let original_stage = stage(&s, &a, &entries, 0);
    apply(&mut s, &original_stage).unwrap();
    for action in [
        CommandAction::AbandonRefresh {
            ceremony_id: Uuid::new_v4(),
        },
        CommandAction::Activate,
        CommandAction::RegisterClaim {
            evidence: Box::new(evidence(entries[0].claim.clone())),
        },
    ] {
        let c = command(&s, &a.plan().source, action);
        assert!(apply(&mut s, &c)
            .unwrap_err()
            .to_string()
            .contains("durable rotation"));
    }
    let c = command(
        &s,
        &a.plan().source,
        CommandAction::BeginRotation {
            approvals: Box::new(a.clone()),
        },
    );
    apply(&mut s, &c).unwrap();
    let c = command(
        &s,
        &a.plan().source,
        CommandAction::AbandonRotationInventory {
            rotation_id: a.plan().rotation_id,
        },
    );
    apply(&mut s, &c).unwrap();
    assert_eq!(
        s.roots[&a.plan().source.identity().unwrap()].phase,
        Phase::Frozen
    );
    assert!(s
        .active_rotation(&a.plan().source.identity().unwrap())
        .is_none());
    assert_eq!(
        s.rotations[&a.plan().rotation_id].status,
        RotationStatus::Abandoned
    );
    let before = s.clone();
    assert!(!apply(&mut s, &original_stage).unwrap());
    assert_eq!(s, before); // An old ACK cannot revive a tombstoned reservation.

    let c = stage(&s, &a, &entries, 0);
    assert!(apply(&mut s, &c).is_err());
}
#[test]
fn new_public_aliases_cannot_reuse_a_rotation_or_authorization_identity() {
    let (mut s, a, entries) = setup(1, false);
    let c = stage(&s, &a, &entries, 0);
    apply(&mut s, &c).unwrap();
    let mut next = entry(&a.plan().target, 1);
    next.claim.reservation_id = a.plan().rotation_id;
    let c = command(
        &s,
        &a.plan().target,
        CommandAction::RegisterClaim {
            evidence: Box::new(evidence(next.claim)),
        },
    );
    assert!(apply(&mut s, &c).is_err());
    let fresh = entry(&a.plan().target, 1);
    act(
        &mut s,
        &a.plan().target,
        CommandAction::RegisterClaim {
            evidence: Box::new(evidence(fresh.claim.clone())),
        },
    );
    let c = command(
        &s,
        &a.plan().target,
        CommandAction::IssueNativeClaim {
            reservation_id: fresh.claim.reservation_id,
            issuance_id: a.plan().authorization_id,
        },
    );
    assert!(apply(&mut s, &c).is_err());
}

#[test]
fn cross_chunk_reservation_owner_and_retry_aliases_fail_before_prefix_commit() {
    let (s, a, entries) = setup(34, false);
    for fault in 0..3 {
        let mut changed = entries.clone();
        match fault {
            0 => changed[32].claim.reservation_id = changed[1].claim.reservation_id,
            1 => changed[32].claim.owner_ref = changed[1].claim.owner_ref.clone(),
            2 => changed[32].claim.idempotency_key = changed[1].claim.idempotency_key.clone(),
            _ => unreachable!(),
        }
        // The full manifest is intentionally contradictory. Its declaration is
        // shape-valid; W must reject the second prefix before the final chunk.
        let mut plan = a.plan().clone();
        plan.inventory_fingerprint = hash(b"contradictory independently approved manifest");
        let a = approvals(plan);
        let mut candidate = s.clone();
        let c = stage(&candidate, &a, &changed[..32], 0);
        apply(&mut candidate, &c).unwrap();
        let before = candidate.clone();
        let c = stage(&candidate, &a, &changed[32..33], 32);
        assert!(apply(&mut candidate, &c)
            .unwrap_err()
            .to_string()
            .contains("staged"));
        assert_eq!(candidate, before);
    }
}

#[test]
fn unknown_source_proofs_and_invented_issuance_cannot_be_admitted() {
    let (s, _, entries) = setup(2, false);
    let mut forged = entries[1].clone();
    forged.witness_evidence_fingerprint = Some(hash(b"invented proof"));
    assert!(s.check_rotation_entry(&forged).is_err());
    forged.membership = SourceMembership::LegacyControl {
        issuance: Some(wallet_mpc_protocol::witness::ClaimIssuance {
            reservation_id: forged.claim.reservation_id,
            issuance_id: Uuid::new_v4(),
            command_id: Uuid::new_v4(),
            initialization_execution_id: None,
        }),
    };
    assert!(s.check_rotation_entry(&forged).is_err());
    s.check_rotation_entry(&entries[1]).unwrap();
}
#[test]
fn renewed_target_cannot_recycle_an_old_source_identity_after_first_chunk() {
    let (mut s, a, entries) = setup(2, false);
    let c = stage(&s, &a, &entries[..1], 0);
    apply(&mut s, &c).unwrap();
    let source = a.plan().source.identity().unwrap();
    let target = a.plan().target.identity().unwrap();
    let mut historical = s
        .commands
        .values()
        .find(|c| c.root_identity == source && matches!(c.action, CommandAction::Enroll { .. }))
        .unwrap()
        .clone();
    historical.request_id = Uuid::new_v4();
    if let CommandAction::Enroll { node_keys, .. } = &mut historical.action {
        node_keys.insert("signer-a".into(), "aa".repeat(32));
    }
    s.commands.insert(historical.request_id, historical);
    s.roots
        .get_mut(&target)
        .unwrap()
        .node_keys
        .insert("signer-a".into(), "aa".repeat(32));
    let mut plan = a.plan().clone();
    plan.authorization_id = Uuid::new_v4();
    plan.target_node_keys = s.roots[&target].node_keys.clone();
    let c = stage(&s, &approvals(plan), &entries[1..], 1);
    assert!(apply(&mut s, &c)
        .unwrap_err()
        .to_string()
        .contains("historical source node"));
}
#[test]
fn signed_source_and_incoming_history_are_never_inferred_finalized() {
    let (mut s, a, entries) = setup(1, false);
    let c = stage(&s, &a, &entries, 0);
    apply(&mut s, &c).unwrap();
    let source = a.plan().source.identity().unwrap();
    let target = a.plan().target.identity().unwrap();
    for incoming in [false, true] {
        let mut candidate = s.clone();
        let mut b = crate::state::tests::admission_request().binding;
        b.authorized.intent.claim.root = if incoming {
            a.plan().target.clone()
        } else {
            a.plan().source.clone()
        };
        b.authorized.intent.action = wallet_mpc_protocol::solana_intent::Action::NativeTransfer {
            destination: entries[0].claim.address().unwrap(),
            amount: 1,
        };
        let id = b.authorized.intent.crypto_execution_id;
        candidate.executions.insert(
            id,
            crate::state::Execution {
                binding: b,
                root_identity: if incoming {
                    target.clone()
                } else {
                    source.clone()
                },
                package: vec![],
                node_keys: BTreeMap::new(),
                grants: BTreeMap::new(),
                reports: BTreeMap::new(),
                signing_package: None,
                status: ExecutionStatus::SignedPending,
                signature: Some("archival-signed-wire".into()),
            },
        );
        let c = command(
            &candidate,
            &a.plan().source,
            CommandAction::BeginRotation {
                approvals: Box::new(a.clone()),
            },
        );
        assert!(apply(&mut candidate, &c).is_err());
        assert_eq!(
            candidate.executions[&id].status,
            ExecutionStatus::SignedPending
        );
        // NoSignature is an explicitly definitive original W result, never a
        // timeout/local DB assertion. This unit fixture supplies that state.
        candidate.executions.get_mut(&id).unwrap().status = ExecutionStatus::NoSignature;
        let c = command(
            &candidate,
            &a.plan().source,
            CommandAction::BeginRotation {
                approvals: Box::new(a.clone()),
            },
        );
        apply(&mut candidate, &c).unwrap();
    }
}

pub(crate) fn admission_command() -> Command {
    let (s, mut a, entries) = setup(0, false);
    a.custody.value.expires_at = 1010;
    a.policy.value = a.custody.value.clone();
    stage(&s, &a, &entries, 0)
}

#[test]
fn unpublished_entries_cannot_become_permanently_unregistrable_by_uuid_collision() {
    let (s, a, entries) = setup(2, false);
    for id in [
        a.plan().rotation_id,
        a.plan().authorization_id,
        *s.commands.keys().next().unwrap(),
    ] {
        let mut candidate = s.clone();
        let mut entries = entries.clone();
        entries[1].claim.reservation_id = id;
        let mut plan = a.plan().clone();
        plan.inventory_fingerprint = inventory_fingerprint(&plan.source, 2, &entries).unwrap();
        let c = stage(&candidate, &approvals(plan), &entries, 0);
        assert!(apply(&mut candidate, &c).is_err());
        assert_eq!(candidate, s);
    }
}
#[test]
fn unpublished_staged_address_is_incoming_fenced_without_creating_a_claim_grant() {
    let (mut s, a, entries) = setup(2, false);
    let c = stage(&s, &a, &entries, 0);
    apply(&mut s, &c).unwrap();
    let mut binding = crate::state::tests::admission_request().binding;
    binding.authorized.intent.claim.root = a.plan().target.clone();
    binding.authorized.intent.action = wallet_mpc_protocol::solana_intent::Action::NativeTransfer {
        destination: entries[1].claim.address().unwrap(),
        amount: 1,
    };
    assert!(s
        .incoming_roots(&binding)
        .unwrap()
        .contains(&a.plan().source.identity().unwrap()));
    assert!(s.check_live_recipients(&binding).is_err());
    assert!(!s.claims.contains_key(&entries[1].claim.reservation_id));
    assert!(!s
        .claim_issuances
        .contains_key(&entries[1].claim.reservation_id));
}

#[test]
fn staged_unpublished_aliases_survive_abandonment_and_cannot_be_registered_by_another_root() {
    let (mut s, a, entries) = setup(2, false);
    let c = stage(&s, &a, &entries, 0);
    apply(&mut s, &c).unwrap();
    let original = entries[1].claim.clone();
    assert_eq!(s.claim_candidates[&original.reservation_id], original);
    assert!(!s.claims.contains_key(&original.reservation_id));
    let availability = s.claim_availability(&original).unwrap();
    assert!(
        availability.index.is_none()
            && availability.owner.is_none()
            && availability.retry.is_none()
    );
    let mut foreign = original.clone();
    foreign.root = a.plan().target.clone();
    assert!(s.claim_availability(&foreign).is_err());
    let c = command(
        &s,
        &a.plan().target,
        CommandAction::RegisterClaim {
            evidence: Box::new(evidence(foreign)),
        },
    );
    assert!(apply(&mut s, &c)
        .unwrap_err()
        .to_string()
        .contains("staged allocation"));
    let c = command(
        &s,
        &a.plan().source,
        CommandAction::AbandonRotationInventory {
            rotation_id: a.plan().rotation_id,
        },
    );
    apply(&mut s, &c).unwrap();
    for fault in 0..4 {
        let mut fork = original.clone();
        match fault {
            0 => fork.reservation_id = Uuid::new_v4(),
            1 => fork.owner_ref = format!("p1:{}", Uuid::new_v4()),
            2 => fork.index = 2,
            3 => fork.idempotency_key = Uuid::new_v4().to_string(),
            _ => unreachable!(),
        }
        assert!(s.claim_availability(&fork).is_err());
        assert!(s.check_candidate_binding(&fork).is_err());
    }
    assert_eq!(s.claim_candidates[&original.reservation_id], original);
    let mut retry_plan = a.plan().clone();
    retry_plan.rotation_id = Uuid::new_v4();
    retry_plan.authorization_id = Uuid::new_v4();
    let retry_approvals = approvals(retry_plan);
    let c = stage(&s, &retry_approvals, &entries, 0);
    apply(&mut s, &c).unwrap();
    let c = command(
        &s,
        &a.plan().source,
        CommandAction::AbandonRotationInventory {
            rotation_id: retry_approvals.plan().rotation_id,
        },
    );
    apply(&mut s, &c).unwrap();
    // Model independently authorized ordinary refresh activation. No production
    // path changes phase here; the existing refresh tests cover that transition.
    s.roots
        .get_mut(&a.plan().source.identity().unwrap())
        .unwrap()
        .phase = Phase::Active;
    let c = command(
        &s,
        &a.plan().source,
        CommandAction::RegisterClaim {
            evidence: Box::new(evidence(original.clone())),
        },
    );
    apply(&mut s, &c).unwrap();
    assert_eq!(s.claims[&original.reservation_id].statement, original);
    assert!(!s.claim_issuances.contains_key(&original.reservation_id));
}
#[test]
fn staged_candidate_ids_cannot_become_commands_ceremonies_or_private_sessions() {
    let (mut s, a, entries) = setup(2, false);
    let c = stage(&s, &a, &entries, 0);
    apply(&mut s, &c).unwrap();
    let id = entries[1].claim.reservation_id;
    let mut c = command(&s, &a.plan().target, CommandAction::Freeze);
    c.request_id = id;
    assert!(apply(&mut s, &c).is_err());
    assert!(s.migration_identity_used(id));
    // Existing fresh-plan admission uses the same global reservation predicate.
    let mut plan = a.plan().clone();
    plan.authorization_id = id;
    let c = stage(&s, &approvals(plan), &entries, 0);
    assert!(apply(&mut s, &c).is_err());
}
