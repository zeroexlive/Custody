use anyhow::{ensure, Context, Result};
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::{hex, identifier, PARTIES},
    sign::{decode_hex, public_package},
    solana_intent::Generation,
    solana_provisioning::{Claim, Evidence, Root},
    witness::{
        hash, hash_text, Binding, Command, CommandAction, ExecutionStatus, GenerationReady, Permit,
        PermitRequest, Phase, PublicRound, Signed,
    },
};

#[cfg(test)]
pub(crate) mod tests;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub generation: Generation,
    pub public_key_package: Vec<u8>,
    pub node_keys: BTreeMap<String, String>,
    pub ready: Vec<Signed<GenerationReady>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootState {
    pub evidence: Evidence<Root>,
    pub revision: u64,
    pub phase: Phase,
    pub generation: Generation,
    pub public_key_package: Vec<u8>,
    pub node_keys: BTreeMap<String, String>,
    pub prepared: Option<Prepared>,
    pub next_claim_index: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub financial_mode: Option<wallet_mpc_protocol::solana_financial::FinancialRootMode>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub binding: Binding,
    pub root_identity: String,
    pub package: Vec<u8>,
    pub node_keys: BTreeMap<String, String>,
    pub grants: BTreeMap<String, PermitRequest>,
    pub reports: BTreeMap<String, Signed<PublicRound>>,
    pub signing_package: Option<Vec<u8>>,
    pub status: ExecutionStatus,
    pub signature: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogicalOperation {
    pub business_fingerprint: String,
    pub executions: Vec<Uuid>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub anchor_id: Uuid,
    pub sequence: u64,
    pub journal_rules: u16,
    pub roots: BTreeMap<String, RootState>,
    pub executions: BTreeMap<Uuid, Execution>,
    pub operations: BTreeMap<String, LogicalOperation>,
    pub attempts: BTreeMap<String, String>,
    pub sessions: BTreeMap<Uuid, String>,
    pub challenges: BTreeSet<String>,
    pub abandoned: BTreeMap<Uuid, String>,
    pub commands: BTreeMap<Uuid, Command>,
    pub claims: BTreeMap<Uuid, Evidence<Claim>>,
    pub claim_indices: BTreeMap<String, Uuid>,
    pub claim_owners: BTreeMap<String, Uuid>,
    pub claim_retries: BTreeMap<String, Uuid>,
    pub wires: BTreeMap<String, String>,
    pub claim_issuances: BTreeMap<Uuid, wallet_mpc_protocol::witness::ClaimIssuance>,
    pub issuance_ids: BTreeMap<Uuid, Uuid>,
    pub replacements:
        BTreeMap<String, wallet_mpc_protocol::solana_recovery::ReplacementReservation>,
    #[serde(default)]
    pub node_profiles: BTreeMap<
        String,
        BTreeMap<String, wallet_mpc_protocol::solana_profile_migration::NodeProfilePin>,
    >,
    #[serde(default)]
    pub profile_migrations:
        BTreeMap<Uuid, wallet_mpc_protocol::solana_profile_migration::MigrationReservation>,
    #[serde(default)]
    pub refreshes: BTreeMap<String, wallet_mpc_protocol::solana_generation::RefreshReservation>,
    #[serde(default)]
    pub financial_reservations: BTreeMap<Uuid, String>,
}

pub(crate) fn slot(party: &str, round: u16) -> String {
    format!("{party}:{round}")
}
pub(crate) fn roster(keys: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        keys.len() == 3
            && PARTIES
                .iter()
                .all(|p| keys.get(*p).is_some_and(|v| hash_text(v)))
            && keys.values().collect::<BTreeSet<_>>().len() == 3,
        "three independent node identity pins required"
    );
    Ok(())
}
impl Snapshot {
    pub(crate) fn empty(anchor_id: Uuid) -> Result<Self> {
        ensure!(
            !anchor_id.is_nil(),
            "explicit authority anchor identity required"
        );
        Ok(Self {
            anchor_id,
            sequence: 0,
            journal_rules: 0,
            roots: BTreeMap::new(),
            executions: BTreeMap::new(),
            operations: BTreeMap::new(),
            attempts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            challenges: BTreeSet::new(),
            abandoned: BTreeMap::new(),
            commands: BTreeMap::new(),
            claims: BTreeMap::new(),
            claim_indices: BTreeMap::new(),
            claim_owners: BTreeMap::new(),
            claim_retries: BTreeMap::new(),
            wires: BTreeMap::new(),
            claim_issuances: BTreeMap::new(),
            issuance_ids: BTreeMap::new(),
            replacements: BTreeMap::new(),
            node_profiles: BTreeMap::new(),
            profile_migrations: BTreeMap::new(),
            refreshes: BTreeMap::new(),
            financial_reservations: BTreeMap::new(),
        })
    }
    fn advance(&mut self, root: &str) -> Result<()> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("authority sequence exhausted")?;
        let state = self.roots.get_mut(root).context("unknown root")?;
        state.revision = state
            .revision
            .checked_add(1)
            .context("root revision exhausted")?;
        Ok(())
    }
    fn lifecycle_id_reserved(&self, id: Uuid) -> bool {
        self.profile_migrations.values().any(|m| {
            let p = m.fence.value.approvals.plan();
            p.migration_id == id
                || p.new_anchor_id == id
                || m.renewal
                    .as_ref()
                    .is_some_and(|r| r.custody.value.renewal_id == id)
        }) || self.commands.values().any(|command| match &command.action {
            CommandAction::EnableFinancialMode { approvals } => {
                approvals.plan().activation_id == id
            }
            CommandAction::ReserveRefresh { plan } => {
                [plan.value.session_id, plan.value.ceremony_id].contains(&id)
            }
            CommandAction::ReserveReplacement { plan } => [
                plan.repair_session_id,
                plan.repair_ceremony_id,
                plan.refresh.session_id,
                plan.refresh.ceremony_id,
                plan.recipient_anchor_id,
            ]
            .contains(&id),
            _ => false,
        })
    }
    fn migration_identity_used(&self, id: Uuid) -> bool {
        self.lifecycle_id_reserved(id)
            || self.commands.contains_key(&id)
            || self.executions.contains_key(&id)
            || self.sessions.contains_key(&id)
            || self.abandoned.contains_key(&id)
            || self.commands.values().any(|c| matches!(&c.action, CommandAction::Prepare { ready, .. }
                if ready.iter().any(|r| r.value.generation.ceremony_id == id || r.value.previous_generation.ceremony_id == id)))
            || self.roots.values().any(|r| {
                [
                    r.evidence.statement.dkg.session_id,
                    r.evidence.statement.dkg.execution_id,
                    r.generation.ceremony_id,
                ]
                .contains(&id)
            })
    }
    #[cfg(test)]
    pub(crate) fn command(&mut self, command: &Command) -> Result<bool> {
        self.command_with_rules(command, false, None)
    }
    pub(crate) fn command_at(&mut self, command: &Command, time: u64) -> Result<bool> {
        self.command_with_rules(command, false, Some(time))
    }
    /// Only journal replay may retain the previously accepted implicit roster
    /// rule. Fresh admissions always require an explicit replacement reservation.
    pub(crate) fn command_legacy(&mut self, command: &Command) -> Result<bool> {
        self.command_with_rules(command, true, None)
    }
    fn command_with_rules(
        &mut self,
        command: &Command,
        legacy_roster: bool,
        time: Option<u64>,
    ) -> Result<bool> {
        ensure!(
            command.anchor_id == self.anchor_id,
            "wrong authority anchor"
        );
        if let Some(previous) = self.commands.get(&command.request_id) {
            ensure!(
                previous == command,
                "original lifecycle command cannot change"
            );
            return Ok(false);
        }
        ensure!(
            !self.lifecycle_id_reserved(command.request_id),
            "replacement identities remain permanently reserved"
        );
        let id = &command.root_identity;
        if let CommandAction::Enroll {
            evidence,
            node_keys,
        } = &command.action
        {
            evidence.validate()?;
            let root = &evidence.statement;
            root.validate()?;
            ensure!(
                !self.lifecycle_id_reserved(root.dkg.session_id)
                    && !self.lifecycle_id_reserved(root.dkg.execution_id),
                "replacement identities cannot become new original DKG identities"
            );
            roster(node_keys)?;
            ensure!(
                root.identity()? == *id && command.expected_revision == 0,
                "original root enrollment identity"
            );
            ensure!(
                !self.roots.contains_key(id)
                    && !self
                        .roots
                        .values()
                        .any(|r| r.evidence.statement.dkg.keyset_id == root.dkg.keyset_id
                            || r.evidence.statement.group_public_key == root.group_public_key),
                "root/key identity already enrolled"
            );
            self.roots.insert(
                id.clone(),
                RootState {
                    evidence: (**evidence).clone(),
                    revision: 0,
                    phase: Phase::Active,
                    generation: Generation {
                        epoch: 0,
                        ceremony_id: root.dkg.execution_id,
                        public_key_package_sha256: hash(&root.public_key_package),
                    },
                    public_key_package: root.public_key_package.clone(),
                    node_keys: node_keys.clone(),
                    prepared: None,
                    next_claim_index: 0,
                    financial_mode: None,
                },
            );
        } else {
            let r = self.roots.get(id).context("unknown original root")?;
            ensure!(
                r.revision == command.expected_revision,
                "stale lifecycle CAS revision"
            );
            if matches!(
                command.action,
                CommandAction::Prepare { .. }
                    | CommandAction::Activate
                    | CommandAction::ReserveReplacement { .. }
                    | CommandAction::ReserveRefresh { .. }
                    | CommandAction::EnableFinancialMode { .. }
            ) {
                ensure!(
                    !self
                        .profile_migrations
                        .values()
                        .any(|m| m.pending_root(id).unwrap_or(true)),
                    "partial profile cohort migration fences lifecycle advance and replacement"
                );
            }
            match &command.action {
                CommandAction::EnableFinancialMode { approvals } => {
                    ensure!(
                        self.journal_rules >= 2 && !legacy_roster,
                        "financial activation requires current strict authority rules"
                    );
                    approvals.validate_shape()?;
                    let p = approvals.plan();
                    p.validate(time.context("independent financial activation clock required")?)?;
                    ensure!(r.phase == Phase::Active && r.prepared.is_none()
                        && r.financial_mode.is_none() && r.next_claim_index == 0
                        && !self.replacements.contains_key(id) && !self.refreshes.contains_key(id)
                        && p.witness_anchor == self.anchor_id && p.root == r.evidence.statement
                        && p.generation == r.generation && p.node_keys == r.node_keys
                        && !self.claims.values().any(|c| c.statement.root == p.root)
                        && !self.executions.values().any(|e| e.root_identity == *id)
                        && !self.commands.values().any(|c| c.root_identity == *id && matches!(
                            c.action, CommandAction::CloseNoSignature { .. } | CommandAction::CloseUnreleased { .. })),
                        "financial activation requires a clean Root before any Claim or private signing history; no automatic legacy adoption");
                    ensure!(
                        p.activation_id != command.request_id
                            && !self.migration_identity_used(p.activation_id),
                        "financial activation identity is globally permanent"
                    );
                    self.roots.get_mut(id).unwrap().financial_mode =
                        Some(wallet_mpc_protocol::solana_financial::FinancialRootMode {
                            version: p.version,
                            activation_id: p.activation_id,
                            command_id: command.request_id,
                        });
                }
                CommandAction::ReserveRefresh { plan } => {
                    ensure!(
                        self.journal_rules >= 2 && !legacy_roster,
                        "ordinary refresh reservation requires current strict event rules"
                    );
                    let p = &plan.value;
                    p.validate(time.context("independent refresh reservation clock required")?)?;
                    ensure!(r.phase == Phase::Frozen && r.prepared.is_none()
                        && !self.replacements.contains_key(id) && !self.refreshes.contains_key(id)
                        && p.anchor_id == self.anchor_id && p.root == r.evidence.statement
                        && p.previous == r.generation && p.previous_public_key_package == r.public_key_package
                        && p.node_keys == r.node_keys
                        && !self.executions.values().any(|e| e.root_identity == *id
                            && e.status == ExecutionStatus::Open),
                        "one exact Frozen current Root/generation/roster with drained executions required");
                    ensure!([p.session_id,p.ceremony_id].iter().all(|new|
                        *new != command.request_id && !self.migration_identity_used(*new)),
                        "ordinary refresh identities are globally permanent and cannot alias previous work");
                    self.refreshes.insert(
                        id.clone(),
                        wallet_mpc_protocol::solana_generation::RefreshReservation {
                            plan: (**plan).clone(),
                            command_id: command.request_id,
                        },
                    );
                }
                CommandAction::AbandonRefresh { ceremony_id } => {
                    ensure!(
                        r.phase == Phase::Frozen
                            && r.prepared.is_none()
                            && self
                                .refreshes
                                .get(id)
                                .is_some_and(|r| r.plan.value.ceremony_id == *ceremony_id),
                        "only the exact Frozen unprepared refresh reservation may be abandoned"
                    );
                    self.refreshes.remove(id);
                }
                CommandAction::InstallNodeProfile { fence, renewal } => {
                    use wallet_mpc_protocol::solana_profile_migration::{
                        MigrationReservation, NodeProfilePin,
                    };
                    ensure!(
                        !legacy_roster,
                        "profile migration requires strict live event rules"
                    );
                    fence.value.validate_shape()?;
                    let p = fence.value.approvals.plan();
                    ensure!(
                        fence.key_id == p.node_key_id
                            && p.witness_anchor == self.anchor_id
                            && p.cohort
                                .iter()
                                .any(|c| c.original.identity().is_ok_and(|root| root == *id)),
                        "exact original signer/authority/cohort migration required"
                    );
                    if let Some(original) = self.profile_migrations.get(&p.migration_id) {
                        ensure!(
                            original.fence == **fence
                                && original.renewal.as_ref() == renewal.as_deref()
                                && !original.root_commands.contains_key(id),
                            "timely migration reservation/renewal/target cannot change or repeat"
                        );
                    } else {
                        fence.value.validate_first_registration(
                            time.context(
                                "first witness registration needs its locked admission clock",
                            )?,
                            renewal.as_deref(),
                        )?;
                        let mut ids = vec![p.migration_id, p.new_anchor_id];
                        if let Some(renewal) = renewal {
                            ids.push(renewal.custody.value.renewal_id);
                        }
                        ensure!(ids.iter().all(|new| *new != command.request_id && !self.migration_identity_used(*new))
                            && !self.profile_migrations.values().any(|m| {
                                let old = m.fence.value.approvals.plan();
                                old.node_key_id == p.node_key_id && old.old_profile_sha256 == p.old_profile_sha256
                            }), "migration source/anchor/approval identities remain permanently consumed");
                        for cohort in &p.cohort {
                            let root = cohort.original.identity()?;
                            let current = self
                                .roots
                                .get(&root)
                                .context("every migration cohort Root must be enrolled")?;
                            ensure!(current.phase == Phase::Frozen && current.prepared.is_none()
                                && !self.replacements.contains_key(&root)
                                && !self.refreshes.contains_key(&root)
                                && current.evidence.statement == cohort.original
                                && current.generation == cohort.generation && current.public_key_package == cohort.public_key_package
                                && current.node_keys == cohort.node_keys
                                && self.node_profiles.get(&root).is_none_or(|pins| !pins.contains_key(&p.party_id)),
                                "entire exact original cohort must be Frozen with unchanged generation/roster and unbound profile");
                        }
                        self.profile_migrations.insert(
                            p.migration_id,
                            MigrationReservation {
                                fence: (**fence).clone(),
                                renewal: renewal.as_deref().cloned(),
                                first_command_id: command.request_id,
                                root_commands: BTreeMap::new(),
                            },
                        );
                    }
                    let pin = NodeProfilePin {
                        node_key_id: p.node_key_id.clone(),
                        profile_sha256: p.new_profile_sha256.clone(),
                        anchor_id: p.new_anchor_id,
                        authority_id: p.migration_id,
                        source_fence_sha256: fence.value.identity()?,
                    };
                    pin.validate_shape()?;
                    self.node_profiles
                        .entry(id.clone())
                        .or_default()
                        .insert(p.party_id.clone(), pin);
                    self.profile_migrations
                        .get_mut(&p.migration_id)
                        .unwrap()
                        .root_commands
                        .insert(id.clone(), command.request_id);
                }
                CommandAction::ReserveReplacement { plan } => {
                    plan.validate_shape()?;
                    ensure!(r.phase == Phase::Frozen && r.prepared.is_none()
                        && !self.replacements.contains_key(id)
                        && !self.refreshes.contains_key(id)
                        && plan.refresh.anchor_id == self.anchor_id
                        && plan.refresh.root == r.evidence.statement
                        && plan.refresh.previous == r.generation
                        && plan.refresh.previous_public_key_package == r.public_key_package
                        && plan.previous_node_keys == r.node_keys
                        && !self.executions.values().any(|e| e.root_identity == *id
                            && e.status == ExecutionStatus::Open),
                        "exact frozen current generation/roster required; unresolved executions cannot be erased");
                    let new_key = &plan.refresh.node_keys[&plan.party_id];
                    let new_ids = [
                        plan.repair_session_id,
                        plan.repair_ceremony_id,
                        plan.refresh.session_id,
                        plan.refresh.ceremony_id,
                        plan.recipient_anchor_id,
                    ];
                    ensure!(
                        !new_ids.contains(&command.request_id),
                        "replacement identities cannot alias their approval command"
                    );
                    ensure!(
                        new_ids.iter().all(|id| !self.lifecycle_id_reserved(*id)),
                        "replacement identities remain permanently reserved"
                    );
                    ensure!(
                        !self.commands.values().any(|c| {
                            if new_ids.contains(&c.request_id) {
                                return true;
                            }
                            match &c.action {
                                CommandAction::Enroll {
                                    evidence,
                                    node_keys,
                                } => {
                                    node_keys.values().any(|v| v == new_key)
                                        || new_ids.contains(&evidence.statement.dkg.session_id)
                                        || new_ids.contains(&evidence.statement.dkg.execution_id)
                                }
                                CommandAction::Prepare { ready, node_keys } => {
                                    node_keys.values().any(|v| v == new_key)
                                        || ready.iter().any(|r| {
                                            new_ids.contains(&r.value.generation.ceremony_id)
                                        })
                                }
                                CommandAction::ReserveReplacement { plan: prior } => {
                                    prior.refresh.node_keys[&prior.party_id] == *new_key
                                        || prior.recipient_anchor_id == plan.recipient_anchor_id
                                        || [
                                            prior.repair_session_id,
                                            prior.repair_ceremony_id,
                                            prior.refresh.session_id,
                                            prior.refresh.ceremony_id,
                                        ]
                                        .iter()
                                        .any(|v| new_ids.contains(v))
                                }
                                _ => false,
                            }
                        }) && new_ids.iter().all(|id| !self.executions.contains_key(id)
                            && !self.sessions.contains_key(id)
                            && !self.abandoned.contains_key(id)),
                        "original or previously reserved identity/anchor/ceremony cannot be reused"
                    );
                    self.replacements.insert(
                        id.clone(),
                        wallet_mpc_protocol::solana_recovery::ReplacementReservation {
                            command_id: command.request_id,
                            plan: (**plan).clone(),
                            original_evidence: r.evidence.clone(),
                        },
                    );
                }
                CommandAction::AbandonReplacement { repair_ceremony_id } => {
                    let original = self
                        .replacements
                        .get(id)
                        .context("no pending replacement to abandon")?;
                    ensure!(
                        r.phase == Phase::Frozen
                            && r.prepared.is_none()
                            && original.plan.repair_ceremony_id == *repair_ceremony_id,
                        "only the exact frozen unprepared replacement may be abandoned"
                    );
                    // Original command remains forever: no key, anchor or UUID
                    // is released. Old partial work cannot prepare a new plan.
                    self.replacements.remove(id);
                }
                CommandAction::IssueNativeClaim {
                    reservation_id,
                    issuance_id,
                } => {
                    let claim = self
                        .claims
                        .get(reservation_id)
                        .context("original registered claim required before issuance")?;
                    ensure!(r.phase==Phase::Active && !issuance_id.is_nil()
                        && claim.statement.root==r.evidence.statement
                        && matches!(claim.statement.asset, wallet_mpc_protocol::solana_provisioning::Asset::Native)
                        && !self.claim_issuances.contains_key(reservation_id)
                        && !self.issuance_ids.contains_key(issuance_id),
                        "one original native claim, active root and globally unique issuance identity required");
                    self.claim_issuances.insert(
                        *reservation_id,
                        wallet_mpc_protocol::witness::ClaimIssuance {
                            reservation_id: *reservation_id,
                            issuance_id: *issuance_id,
                            command_id: command.request_id,
                            initialization_execution_id: None,
                        },
                    );
                    self.issuance_ids.insert(*issuance_id, *reservation_id);
                }
                CommandAction::IssueClassicClaim {
                    reservation_id,
                    issuance_id,
                    initialization_execution_id,
                } => {
                    let claim = self
                        .claims
                        .get(reservation_id)
                        .context("original registered classic claim required")?;
                    let execution = self
                        .executions
                        .get(initialization_execution_id)
                        .context("original MPC token initialization required")?;
                    let intent = &execution.binding.authorized.intent;
                    ensure!(
                        r.phase == Phase::Active
                            && r.financial_mode.is_some()
                            && intent.financial.is_some()
                            && !issuance_id.is_nil()
                            && !initialization_execution_id.is_nil()
                            && issuance_id != initialization_execution_id
                            && claim.statement.root == r.evidence.statement
                            && matches!(
                                claim.statement.asset,
                                wallet_mpc_protocol::solana_provisioning::Asset::ClassicToken { .. }
                            )
                            && execution.root_identity == *id
                            && execution.status == ExecutionStatus::SignedPending
                            && execution.signature.is_some()
                            && intent.claim == claim.statement
                            && intent.operation_type
                                == wallet_mpc_protocol::solana_intent::BusinessOperation::Provision
                            && matches!(
                                intent.action,
                                wallet_mpc_protocol::solana_intent::Action::CreateClassicToken { .. }
                            )
                            && !self.claim_issuances.contains_key(reservation_id)
                            && !self.issuance_ids.contains_key(issuance_id),
                        "one original signed classic initializer and unique issuance required"
                    );
                    self.claim_issuances.insert(
                        *reservation_id,
                        wallet_mpc_protocol::witness::ClaimIssuance {
                            reservation_id: *reservation_id,
                            issuance_id: *issuance_id,
                            command_id: command.request_id,
                            initialization_execution_id: Some(*initialization_execution_id),
                        },
                    );
                    self.issuance_ids.insert(*issuance_id, *reservation_id);
                }
                CommandAction::RegisterClaim { evidence } => {
                    evidence.validate()?;
                    evidence.statement.validate()?;
                    let claim = &evidence.statement;
                    ensure!(
                        claim.root == r.evidence.statement && claim.root.identity()? == *id,
                        "claim requires exact enrolled original root"
                    );
                    let index = format!("{id}:{}", claim.index);
                    let owner = claim.owner_slot()?;
                    let retry = claim.retry_slot()?;
                    let reservation = claim.reservation_id;
                    if let Some(original) = self.claims.get(&reservation) {
                        ensure!(
                            original.statement == *claim
                                && self.claim_indices.get(&index) == Some(&reservation)
                                && self.claim_owners.get(&owner) == Some(&reservation)
                                && self.claim_retries.get(&retry) == Some(&reservation),
                            "original claim registration cannot change"
                        );
                    } else {
                        ensure!(
                            r.phase == Phase::Active
                                && claim.index == r.next_claim_index
                                && !self.claim_indices.contains_key(&index)
                                && !self.claim_owners.contains_key(&owner)
                                && !self.claim_retries.contains_key(&retry),
                            "claim index/owner/retry already reserved or out of sequence"
                        );
                        // One authority transaction commits all permanent aliases
                        // before a wallet may be issued or a permit acknowledged.
                        self.claims.insert(reservation, (**evidence).clone());
                        self.claim_indices.insert(index, reservation);
                        self.claim_owners.insert(owner, reservation);
                        self.claim_retries.insert(retry, reservation);
                        self.roots.get_mut(id).unwrap().next_claim_index = claim
                            .index
                            .checked_add(1)
                            .context("claim counter exhausted")?;
                    }
                }
                CommandAction::Freeze => {
                    ensure!(
                        r.phase == Phase::Active,
                        "only active generation can freeze"
                    );
                    self.roots.get_mut(id).unwrap().phase = Phase::Frozen;
                }
                CommandAction::CloseNoSignature { execution_id } => {
                    ensure!(
                        !execution_id.is_nil() && r.phase != Phase::Prepared,
                        "valid original execution and active/frozen authority required"
                    );
                    if let Some(e) = self.executions.get_mut(execution_id) {
                        ensure!(
                            e.root_identity == *id
                                && e.status == ExecutionStatus::Open
                                && e.grants.values().all(|g| g.round != 2),
                            "any R2 grant remains potentially signed"
                        );
                        // The same durable authority transaction serializes this
                        // terminal fence with R2 permit creation.
                        e.status = ExecutionStatus::NoSignature;
                    } else {
                        ensure!(
                            !self.abandoned.contains_key(execution_id),
                            "execution already abandoned"
                        );
                        self.abandoned.insert(*execution_id, id.clone());
                    }
                }
                CommandAction::CloseUnreleased {
                    execution_id,
                    attestations,
                } => {
                    ensure!(
                        r.phase == Phase::Frozen,
                        "freeze required for terminal R2 closure"
                    );
                    let e = self
                        .executions
                        .get_mut(execution_id)
                        .context("original execution missing")?;
                    ensure!(
                        e.root_identity == *id && e.status == ExecutionStatus::Open,
                        "original open execution required"
                    );
                    let grantees: BTreeMap<_, _> = e
                        .grants
                        .values()
                        .filter(|g| g.round == 2)
                        .map(|g| (g.party_id.as_str(), g))
                        .collect();
                    ensure!(
                        !grantees.is_empty()
                            && grantees.len() == attestations.len()
                            && !e.reports.values().any(|p| p.value.round == 2),
                        "every actual R2 grantee must attest with no contradictory result"
                    );
                    let mut seen = BTreeSet::new();
                    for a in attestations {
                        let proof = &a.value;
                        let request = &proof.request;
                        let party = request.value.party_id.as_str();
                        proof.authorization.value.matches(request)?;
                        ensure!(
                            seen.insert(party)
                                && grantees.get(party).is_some_and(|g| **g == request.value)
                                && e.node_keys.get(party) == Some(&a.key_id)
                                && a.key_id == request.key_id
                                && request.value.binding == e.binding
                                && request.value.signing_package == e.signing_package,
                            "original grantee/key/request/package mismatch or duplicate"
                        );
                    }
                    // This CAS shares the permission/result mutex. After commit
                    // no original late R2 report or permission may revive it.
                    e.status = ExecutionStatus::NoSignature;
                }
                CommandAction::Prepare { ready, node_keys } => {
                    ensure!(
                        r.phase == Phase::Frozen && r.prepared.is_none(),
                        "generation must be frozen before preparation"
                    );
                    ensure!(
                        !self
                            .executions
                            .values()
                            .any(|e| e.root_identity == *id && e.status == ExecutionStatus::Open),
                        "unresolved private executions must drain"
                    );
                    roster(node_keys)?;
                    ensure!(
                        ready.len() == 3,
                        "all three durable generation agreements required"
                    );
                    let next = &ready[0].value;
                    if let Some(reservation) = self.replacements.get(id) {
                        let plan = &reservation.plan.refresh;
                        ensure!(
                            node_keys == &plan.node_keys
                                && next.previous_generation == plan.previous
                                && next.generation.epoch == plan.next_epoch
                                && next.generation.ceremony_id == plan.ceremony_id,
                            "preparation must complete the exact reserved replacement refresh"
                        );
                    } else if let Some(reservation) = self.refreshes.get(id) {
                        let plan = &reservation.plan.value;
                        ensure!(plan.root == r.evidence.statement && plan.previous == r.generation
                            && plan.previous_public_key_package == r.public_key_package
                            && node_keys == &plan.node_keys && node_keys == &r.node_keys
                            && next.previous_generation == plan.previous
                            && next.generation.epoch == plan.next_epoch
                            && next.generation.ceremony_id == plan.ceremony_id,
                            "all-three readiness must complete the exact independently reserved refresh");
                    } else {
                        ensure!(
                            self.journal_rules < 2,
                            "new ordinary readiness requires original durable refresh reservation"
                        );
                        ensure!(
                            legacy_roster
                                || !self.lifecycle_id_reserved(next.generation.ceremony_id),
                            "ordinary refresh cannot reuse a replacement identity"
                        );
                        ensure!(
                            legacy_roster || node_keys == &r.node_keys,
                            "new identity requires an explicit frozen replacement reservation"
                        );
                    }
                    ensure!(
                        next.generation.epoch
                            == r.generation
                                .epoch
                                .checked_add(1)
                                .context("epoch exhausted")?
                            && !next.generation.ceremony_id.is_nil()
                            && next.generation.ceremony_id != r.generation.ceremony_id
                            && next.generation.ceremony_id != r.evidence.statement.dkg.execution_id
                            && next.generation.ceremony_id != r.evidence.statement.dkg.session_id
                            && !self.commands.values().any(|c| {
                                matches!(&c.action, CommandAction::Prepare { ready, .. }
                                    if ready.iter().any(|r| r.value.generation.ceremony_id
                                        == next.generation.ceremony_id))
                            })
                            && next.public_key_package.len() <= 4096
                            && next.public_key_package != r.public_key_package
                            && next.generation.public_key_package_sha256
                                == hash(&next.public_key_package),
                        "genuine next generation/package required"
                    );
                    public_package(
                        &next.public_key_package,
                        &r.evidence.statement.group_public_key,
                    )?;
                    for (report, party) in ready.iter().zip(PARTIES) {
                        ensure!(
                            report.value.root_identity == *id
                                && report.value.party_id == party
                                && report.key_id == node_keys[party]
                                && report.value.previous_generation == r.generation
                                && report.value.generation == next.generation
                                && report.value.public_key_package == next.public_key_package,
                            "generation readiness disagreement"
                        );
                    }
                    let prepared = Prepared {
                        generation: next.generation.clone(),
                        public_key_package: next.public_key_package.clone(),
                        node_keys: node_keys.clone(),
                        ready: ready.clone(),
                    };
                    let r = self.roots.get_mut(id).unwrap();
                    r.phase = Phase::Prepared;
                    r.prepared = Some(prepared);
                }
                CommandAction::Activate => {
                    ensure!(
                        r.phase == Phase::Prepared,
                        "all-three prepared agreement required"
                    );
                    ensure!(
                        !self
                            .executions
                            .values()
                            .any(|e| e.root_identity == *id && e.status == ExecutionStatus::Open),
                        "unresolved executions cannot be reset by activation"
                    );
                    let r = self.roots.get_mut(id).unwrap();
                    let next = r.prepared.take().context("missing prepared generation")?;
                    r.generation = next.generation;
                    r.public_key_package = next.public_key_package;
                    r.node_keys = next.node_keys;
                    r.phase = Phase::Active;
                    // Historical4a replacements had no profile pins. Preserve
                    // their original valid None request replay semantics.
                    if let Some(replacement) = self.replacements.get(id) {
                        let p = &replacement.plan;
                        if let Some(pins) = self.node_profiles.get_mut(id) {
                            if pins.contains_key(&p.party_id) {
                                pins.insert(
                                    p.party_id.clone(),
                                    wallet_mpc_protocol::solana_profile_migration::NodeProfilePin {
                                        node_key_id: p.refresh.node_keys[&p.party_id].clone(),
                                        profile_sha256: p.recipient_profile_sha256.clone(),
                                        anchor_id: p.recipient_anchor_id,
                                        authority_id: p.repair_ceremony_id,
                                        source_fence_sha256: p.identity()?,
                                    },
                                );
                            }
                        }
                    }
                    self.replacements.remove(id);
                    self.refreshes.remove(id);
                }
                CommandAction::Enroll { .. } => unreachable!(),
            }
        }
        self.advance(id)?;
        self.commands.insert(command.request_id, command.clone());
        Ok(true)
    }

    pub(crate) fn permit(
        &mut self,
        req: &PermitRequest,
        node_key: &str,
        now: u64,
    ) -> Result<Permit> {
        req.validate(now)?;
        ensure!(req.anchor_id == self.anchor_id, "wrong anchor");
        let i = &req.binding.authorized.intent;
        ensure!(
            !self.lifecycle_id_reserved(i.crypto_execution_id)
                && !self.lifecycle_id_reserved(i.session_id),
            "replacement identities cannot become private signing executions or sessions"
        );
        let root = i.claim.root.identity()?;
        let r = self
            .roots
            .get(&root)
            .context("unregistered original root")?;
        if let Some(financial) = &i.financial {
            financial.validate(i)?;
        }
        ensure!(r.financial_mode.is_none() || i.financial.is_some(),
            "financial Root requires a typed immutable financial reservation on every private round");
        if let Some(pin) = self
            .node_profiles
            .get(&root)
            .and_then(|pins| pins.get(&req.party_id))
        {
            pin.validate_shape()?;
            ensure!(
                pin.node_key_id == node_key
                    && req.node_profile_sha256.as_ref() == Some(&pin.profile_sha256),
                "private admission requires exact current witness profile pin"
            );
        }
        ensure!(
            r.phase == Phase::Active
                && r.generation == i.generation
                && r.evidence.statement == i.claim.root
                && r.node_keys
                    .get(&req.party_id)
                    .is_some_and(|k| k == node_key),
            "inactive/stale generation or node identity"
        );
        ensure!(
            self.claims
                .get(&i.claim.reservation_id)
                .is_some_and(|e| e.statement == i.claim),
            "exact original claim must be durably registered before private permission"
        );
        let challenge = format!("{node_key}:{}:{}", req.party_id, req.challenge);
        ensure!(
            !self.challenges.contains(&challenge),
            "signer challenge already used"
        );
        let execution_id = i.crypto_execution_id;
        let logical_key = req.binding.authorized.operation_key()?;
        if let Some(financial) = &i.financial {
            ensure!(
                self.financial_reservations
                    .get(&financial.reservation_id)
                    .is_none_or(|old| old == &logical_key),
                "one financial reservation cannot back multiple business operations"
            );
        }
        let wire = req.binding.authorized.wire_key()?;
        ensure!(
            self.wires.get(&wire).is_none_or(|old| old == &logical_key),
            "exact Solana message belongs to another logical operation"
        );
        ensure!(
            !self.abandoned.contains_key(&execution_id),
            "late request for definitively abandoned execution"
        );
        if !self.executions.contains_key(&execution_id) {
            ensure!(
                req.round == 1,
                "first private round must reserve the operation"
            );
            let business = req.binding.authorized.business_fingerprint()?;
            if let Some(previous) = self.operations.get(&logical_key) {
                ensure!(
                    previous.business_fingerprint == business
                        && previous.executions.iter().all(|id| self
                            .executions
                            .get(id)
                            .is_some_and(|e| e.status == ExecutionStatus::NoSignature)),
                    "logical operation already possibly signed or business intent changed"
                );
            }
            let attempt = req.binding.authorized.attempt_key()?;
            ensure!(
                self.attempts
                    .get(&attempt)
                    .is_none_or(|old| old == &logical_key)
                    && self
                        .sessions
                        .get(&i.session_id)
                        .is_none_or(|old| old == &logical_key),
                "attempt/session belongs to another operation"
            );
            if let Some(financial) = &i.financial {
                self.financial_reservations
                    .insert(financial.reservation_id, logical_key.clone());
            }
            self.attempts.insert(attempt, logical_key.clone());
            self.wires.insert(wire.clone(), logical_key.clone());
            self.sessions.insert(i.session_id, logical_key.clone());
            self.operations
                .entry(logical_key.clone())
                .or_insert(LogicalOperation {
                    business_fingerprint: business,
                    executions: vec![],
                })
                .executions
                .push(execution_id);
            self.executions.insert(
                execution_id,
                Execution {
                    binding: req.binding.clone(),
                    root_identity: root.clone(),
                    package: r.public_key_package.clone(),
                    node_keys: r.node_keys.clone(),
                    grants: BTreeMap::new(),
                    reports: BTreeMap::new(),
                    signing_package: None,
                    status: ExecutionStatus::Open,
                    signature: None,
                },
            );
        }
        ensure!(
            self.wires.get(&wire) == Some(&logical_key),
            "original execution wire alias missing"
        );
        let e = self.executions.get_mut(&execution_id).unwrap();
        ensure!(
            e.binding.identity()? == req.binding.identity()?
                && e.root_identity == root
                && e.status == ExecutionStatus::Open,
            "original execution identity/status conflict"
        );
        let key = slot(&req.party_id, req.round);
        ensure!(
            !e.grants.contains_key(&key),
            "private round grant already consumed; no secret retry"
        );
        if req.round == 2 {
            let bytes = req.signing_package.as_ref().context("R2 package missing")?;
            let package = frost::SigningPackage::deserialize(bytes)?;
            let payload = decode_hex(&req.binding.authorized.payload_hex).context("payload")?;
            ensure!(
                package.serialize()? == *bytes
                    && package.message() == &payload
                    && package.signing_commitments().len() == 2,
                "canonical original signing package required"
            );
            for party in &e.binding.selected_signers {
                let record = e
                    .reports
                    .get(&slot(party, 1))
                    .context("all original R1 receipts required")?;
                let c = frost::round1::SigningCommitments::deserialize(
                    record
                        .value
                        .commitments
                        .as_ref()
                        .context("R1 commitment missing")?,
                )?;
                ensure!(
                    package.signing_commitment(&identifier(party).context("party identity")?)
                        == Some(c),
                    "original party commitment mismatch"
                );
            }
            if let Some(original) = &e.signing_package {
                ensure!(original == bytes, "execution signing package cannot change");
            } else {
                e.signing_package = Some(bytes.clone());
            }
        }
        e.grants.insert(key, req.clone());
        self.challenges.insert(challenge);
        self.advance(&root)?;
        Ok(Permit {
            request: req.clone(),
            sequence: self.sequence,
            root_revision: self.roots[&root].revision,
            financial_mode: self.roots[&root].financial_mode.clone(),
            node_profile: self
                .node_profiles
                .get(&root)
                .and_then(|pins| pins.get(&req.party_id))
                .cloned(),
        })
    }

    pub(crate) fn record(&mut self, frame: &Signed<PublicRound>) -> Result<bool> {
        let p = &frame.value;
        ensure!(p.anchor_id == self.anchor_id, "wrong public result anchor");
        let e = self
            .executions
            .get_mut(&p.execution_id)
            .context("unknown result execution")?;
        let key = slot(&p.party_id, p.round);
        ensure!(
            e.binding.identity()? == p.binding_fingerprint
                && e.node_keys
                    .get(&p.party_id)
                    .is_some_and(|k| k == &frame.key_id)
                && e.grants.contains_key(&key),
            "result lacks original identity/round grant"
        );
        if let Some(original) = e.reports.get(&key) {
            ensure!(original == frame, "original public receipt cannot change");
            return Ok(false);
        }
        // A closed zero-R2 operation cannot gain a private partial later.
        ensure!(
            e.status == ExecutionStatus::Open,
            "closed original operation"
        );
        if p.round == 1 {
            ensure!(
                p.signature_share.is_none() && p.signing_package.is_none(),
                "R1 public shape"
            );
            let bytes = p.commitments.as_ref().context("R1 commitments required")?;
            let commitments = frost::round1::SigningCommitments::deserialize(bytes)?;
            ensure!(
                commitments.serialize()? == *bytes,
                "canonical R1 commitments"
            );
        } else {
            ensure!(
                p.round == 2 && p.commitments.is_none() && p.signing_package == e.signing_package,
                "original R2 package required"
            );
            let bytes = p.signature_share.as_ref().context("R2 share required")?;
            let share = frost::round2::SignatureShare::deserialize(bytes)?;
            ensure!(share.serialize() == *bytes, "canonical signature share");
            let package = frost::SigningPackage::deserialize(
                e.signing_package.as_ref().context("missing R2 package")?,
            )?;
            let public = public_package(
                &e.package,
                &e.binding.authorized.intent.claim.root.group_public_key,
            )?;
            let id = identifier(&p.party_id).context("party identity")?;
            frost_core::verify_signature_share::<frost::Ed25519Sha512>(
                id,
                public
                    .verifying_shares()
                    .get(&id)
                    .context("missing party share")?,
                &share,
                &package,
                public.verifying_key(),
            )?;
        }
        e.reports.insert(key, frame.clone());
        if e.binding
            .selected_signers
            .iter()
            .all(|party| e.reports.contains_key(&slot(party, 2)))
        {
            let shares = e
                .binding
                .selected_signers
                .iter()
                .map(|party| -> Result<_> {
                    Ok((
                        identifier(party).context("party identity")?,
                        frost::round2::SignatureShare::deserialize(
                            e.reports[&slot(party, 2)]
                                .value
                                .signature_share
                                .as_ref()
                                .context("share")?,
                        )?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let package = frost::SigningPackage::deserialize(e.signing_package.as_ref().unwrap())?;
            let public = public_package(
                &e.package,
                &e.binding.authorized.intent.claim.root.group_public_key,
            )?;
            let signature = frost::aggregate(&package, &shares, &public)?;
            public
                .verifying_key()
                .verify(package.message(), &signature)?;
            e.signature = Some(hex(&signature.serialize()?));
            // Crypto completion permits epoch draining, NEVER a fresh financial
            // attempt. Logical-operation fencing remains permanent until an
            // independently authoritative financial reconciliation is added.
            e.status = ExecutionStatus::SignedPending;
        }
        let root = e.root_identity.clone();
        self.advance(&root)?;
        Ok(true)
    }
}
