//! Durable governed manifest staging. This does not implement migration private
//! rounds, chain finality attestation, retirement or rescue.
use crate::state::Snapshot;
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use wallet_mpc_protocol::{
    hd::fingerprint,
    solana_rotation::{
        InventoryChunk, MigrationSource, RotationApprovals, RotationStatus, RotationView,
        SourceMembership,
    },
    witness::{Command, ExecutionStatus, Phase},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RotationReservation {
    pub source_identity: String,
    pub target_identity: String,
    pub business_fingerprint: String,
    pub authorizations: BTreeMap<Uuid, RotationApprovals>,
    pub entries: Vec<MigrationSource>,
    pub chunks: BTreeMap<u64, String>,
    pub status: RotationStatus,
    pub begin_command_id: Option<Uuid>,
    pub abandon_command_id: Option<Uuid>,
}
impl Snapshot {
    pub(crate) fn rotation_view(&self, root: &str) -> Result<Option<RotationView>> {
        self.rotations
            .iter()
            .find(|(_, r)| r.source_identity == root && r.status != RotationStatus::Abandoned)
            .map(|(id, r)| {
                let plan = r
                    .authorizations
                    .values()
                    .next()
                    .context("admitted rotation plan missing")?
                    .plan();
                Ok(RotationView {
                    rotation_id: *id,
                    source_identity: r.source_identity.clone(),
                    target_identity: r.target_identity.clone(),
                    business_fingerprint: r.business_fingerprint.clone(),
                    status: r.status.clone(),
                    next_index: u64::try_from(r.entries.len())?,
                    allocated_high_water: plan.allocated_high_water,
                    inventory_fingerprint: plan.inventory_fingerprint.clone(),
                })
            })
            .transpose()
    }
    pub(crate) fn active_rotation(&self, root: &str) -> Option<&RotationReservation> {
        self.rotations
            .values()
            .find(|r| r.source_identity == root && r.status != RotationStatus::Abandoned)
    }
    fn rotation_identity_used(&self, id: Uuid) -> bool {
        self.migration_identity_used(id)
            || self.claims.contains_key(&id)
            || self.issuance_ids.contains_key(&id)
            || self
                .roots
                .values()
                .any(|r| r.evidence.statement.dkg.keyset_id == id)
    }
    fn rotation_context(
        &self,
        command: &Command,
        approvals: &RotationApprovals,
        time: Option<u64>,
    ) -> Result<()> {
        ensure!(
            self.journal_rules >= 4,
            "rotation requires explicit current journal rules"
        );
        approvals.validate_shape()?;
        let plan = approvals.plan();
        plan.validate(time.context("independent rotation admission clock required")?)?;
        let source_id = plan.source.identity()?;
        let target_id = plan.target.identity()?;
        let source = self
            .roots
            .get(&source_id)
            .context("unknown original source Root")?;
        let target = self
            .roots
            .get(&target_id)
            .context("unknown original target Root")?;
        ensure!(
            command.root_identity == source_id
                && plan.witness_anchor == self.anchor_id
                && command.request_id != plan.rotation_id
                && command.request_id != plan.authorization_id
                && source.evidence.statement == plan.source
                && target.evidence.statement == plan.target
                && source.phase == Phase::Frozen
                && source.prepared.is_none()
                && source.generation == plan.source_generation
                && source.node_keys == plan.source_node_keys
                && target.phase == Phase::Active
                && target.prepared.is_none()
                && target.generation == plan.target_generation
                && target.node_keys == plan.target_node_keys
                && target.financial_mode.is_some()
                && source.next_claim_index <= plan.allocated_high_water
                && !self.replacements.contains_key(&source_id)
                && !self.refreshes.contains_key(&source_id)
                && !self
                    .profile_migrations
                    .values()
                    .any(|m| m.pending_root(&source_id).unwrap_or(true)
                        || m.pending_root(&target_id).unwrap_or(true))
                && !self
                    .executions
                    .values()
                    .any(|e| e.root_identity == source_id && e.status == ExecutionStatus::Open),
            "exact independently frozen source and active governed target context required"
        );
        // A renewal may refer to a newly repaired/refreshed target. Freshness
        // must hold against BOTH complete histories on every admission, not
        // only the rosters at the first chunk.
        let history = |root: &str| {
            let mut keys: std::collections::BTreeSet<String> =
                self.roots[root].node_keys.values().cloned().collect();
            for old in self.commands.values().filter(|c| c.root_identity == root) {
                match &old.action {
                    wallet_mpc_protocol::witness::CommandAction::Enroll { node_keys, .. }
                    | wallet_mpc_protocol::witness::CommandAction::Prepare { node_keys, .. } => {
                        keys.extend(node_keys.values().cloned())
                    }
                    wallet_mpc_protocol::witness::CommandAction::ReserveReplacement { plan } => {
                        keys.extend(plan.refresh.node_keys.values().cloned())
                    }
                    _ => {}
                }
            }
            keys
        };
        ensure!(
            history(&source_id).is_disjoint(&history(&target_id)),
            "fresh target cohort cannot reuse any historical source node identity"
        );
        for destination in &plan.destinations {
            let d = &destination.treasury;
            let registered = self
                .claims
                .get(&d.claim.reservation_id)
                .context("target Claim is not registered")?;
            ensure!(registered.statement==d.claim
                && d.witness_evidence_fingerprint.as_deref()==Some(&fingerprint("SOLANA_ROTATION_CLAIM_EVIDENCE_V1", registered)?)
                && matches!(&d.membership, SourceMembership::Financial { issuance, .. }
                    if self.claim_issuances.get(&d.claim.reservation_id)==Some(issuance)),
                "target exact registered evidence and original issuance required; role is a separately approved declaration");
        }
        Ok(())
    }
    fn check_rotation_entry(&self, entry: &MigrationSource) -> Result<()> {
        entry.validate_shape()?;
        self.check_candidate_binding(&entry.claim)?;
        let root = entry.claim.root.identity()?;
        let index = format!("{root}:{}", entry.claim.index);
        if let Some(registered) = self.claims.get(&entry.claim.reservation_id) {
            ensure!(
                registered.statement == entry.claim
                    && entry.witness_evidence_fingerprint.as_deref()
                        == Some(&fingerprint(
                            "SOLANA_ROTATION_CLAIM_EVIDENCE_V1",
                            registered
                        )?),
                "original registered source evidence cannot be omitted or substituted"
            );
        } else {
            ensure!(
                entry.witness_evidence_fingerprint.is_none()
                    && (!self.rotation_identity_used(entry.claim.reservation_id)
                        || self.claim_candidates.get(&entry.claim.reservation_id)
                            == Some(&entry.claim))
                    && !self.claim_indices.contains_key(&index)
                    && !matches!(entry.membership, SourceMembership::Financial { .. }),
                "unregistered source remains explicitly unpublished/control-only inventory"
            );
        }
        let financial = self
            .roots
            .get(&root)
            .context("exact original source Root required")?
            .financial_mode
            .is_some();
        match (
            self.claim_issuances.get(&entry.claim.reservation_id),
            &entry.membership,
        ) {
            (Some(original), SourceMembership::Financial { issuance, .. }) if financial => ensure!(
                original == issuance,
                "prior financial issuance must be the exact immutable W grant"
            ),
            (
                Some(original),
                SourceMembership::LegacyControl {
                    issuance: Some(issuance),
                },
            ) if !financial => ensure!(
                original == issuance,
                "mode-off issuance must remain archival control-only evidence"
            ),
            (
                None,
                SourceMembership::Unpublished {}
                | SourceMembership::LegacyControl { issuance: None },
            ) => {}
            _ => anyhow::bail!(
                "manifest must preserve original W issuance without inventing financial membership"
            ),
        }
        Ok(())
    }
    fn add_rotation_authorization(
        &mut self,
        id: Uuid,
        approvals: &RotationApprovals,
    ) -> Result<()> {
        let plan = approvals.plan();
        if let Some(old) = self.rotations[&id]
            .authorizations
            .get(&plan.authorization_id)
        {
            ensure!(
                old == approvals,
                "original rotation approval attempt cannot change"
            );
        } else {
            ensure!(
                !self.rotation_identity_used(plan.authorization_id),
                "rotation approval identity is globally reserved"
            );
            self.rotations
                .get_mut(&id)
                .unwrap()
                .authorizations
                .insert(plan.authorization_id, approvals.clone());
        }
        Ok(())
    }
    pub(crate) fn stage_rotation(
        &mut self,
        command: &Command,
        approvals: &RotationApprovals,
        chunk: &InventoryChunk,
        time: Option<u64>,
    ) -> Result<()> {
        self.rotation_context(command, approvals, time)?;
        let plan = approvals.plan();
        chunk.validate(plan)?;
        let source = plan.source.identity()?;
        let target = plan.target.identity()?;
        if !self.rotations.contains_key(&plan.rotation_id) {
            ensure!(
                chunk.start_index == 0
                    && !self.rotation_identity_used(plan.rotation_id)
                    && self.active_rotation(&source).is_none(),
                "one original rotation; inventory must begin at zero"
            );
            self.rotations.insert(
                plan.rotation_id,
                RotationReservation {
                    source_identity: source.clone(),
                    target_identity: target,
                    business_fingerprint: plan.business_fingerprint()?,
                    authorizations: BTreeMap::new(),
                    entries: vec![],
                    chunks: BTreeMap::new(),
                    status: RotationStatus::Collecting,
                    begin_command_id: None,
                    abandon_command_id: None,
                },
            );
        }
        let reservation = &self.rotations[&plan.rotation_id];
        ensure!(
            reservation.source_identity == source
                && reservation.business_fingerprint == plan.business_fingerprint()?
                && matches!(
                    reservation.status,
                    RotationStatus::Collecting | RotationStatus::Sealed
                ),
            "rotation business and admitted inventory cannot change or revive"
        );
        self.add_rotation_authorization(plan.rotation_id, approvals)?;
        for entry in &chunk.entries {
            self.check_rotation_entry(entry)?;
        }
        let old = &self.rotations[&plan.rotation_id];
        let identity = chunk.identity(plan)?;
        if let Some(previous) = old.chunks.get(&chunk.start_index) {
            ensure!(
                *previous == identity,
                "original inventory chunk cannot change"
            );
            return Ok(());
        }
        ensure!(
            u64::try_from(old.entries.len())? == chunk.start_index
                && old.status == RotationStatus::Collecting,
            "next exact contiguous inventory chunk required"
        );
        // The original Root is common to every validated entry. Compare its
        // alias components directly so an inconsistent prefix cannot be saved,
        // without rerunning old Root/public-package validation for each chunk.
        let mint = |e: &MigrationSource| match &e.claim.asset {
            wallet_mpc_protocol::solana_provisioning::Asset::Native => "SOL".to_owned(),
            wallet_mpc_protocol::solana_provisioning::Asset::ClassicToken { mint, .. } => {
                mint.clone()
            }
        };
        for entry in &chunk.entries {
            ensure!(
                old.entries
                    .iter()
                    .all(
                        |previous| previous.claim.reservation_id != entry.claim.reservation_id
                            && previous.claim.idempotency_key != entry.claim.idempotency_key
                            && (previous.claim.owner_ref != entry.claim.owner_ref
                                || mint(previous) != mint(entry))
                    ),
                "new inventory chunk cannot duplicate an already staged permanent alias"
            );
        }
        let mutable = self.rotations.get_mut(&plan.rotation_id).unwrap();
        mutable.entries.extend_from_slice(&chunk.entries);
        mutable.chunks.insert(chunk.start_index, identity);
        if u64::try_from(mutable.entries.len())? == plan.allocated_high_water {
            plan.validate_inventory(&mutable.entries)?;
            // Every source W Claim is mandatory, even when never published.
            for registered in self
                .claims
                .values()
                .filter(|e| e.statement.root == plan.source)
            {
                let index = usize::try_from(registered.statement.index)?;
                ensure!(
                    mutable
                        .entries
                        .get(index)
                        .is_some_and(|e| e.claim == registered.statement),
                    "source inventory omits an original W Claim"
                );
            }
            mutable.status = RotationStatus::Sealed;
        }
        for entry in &chunk.entries {
            if !self.claims.contains_key(&entry.claim.reservation_id) {
                self.bind_claim_candidate(&entry.claim)?;
            }
            self.index_claim_recipient(&entry.claim)?;
        }
        Ok(())
    }
    pub(crate) fn begin_rotation(
        &mut self,
        command: &Command,
        approvals: &RotationApprovals,
        time: Option<u64>,
    ) -> Result<()> {
        self.rotation_context(command, approvals, time)?;
        let plan = approvals.plan();
        let old = self
            .rotations
            .get(&plan.rotation_id)
            .context("original sealed inventory required")?;
        ensure!(
            old.status == RotationStatus::Sealed
                && old.business_fingerprint == plan.business_fingerprint()?,
            "sealed exact original inventory required before migration preparation"
        );
        for entry in &old.entries {
            self.check_rotation_entry(entry)?;
        }
        // No finality inference from SignedPending. A later independently
        // attested finality contract must resolve these before real movement.
        ensure!(
            !self
                .executions
                .values()
                .any(|e| e.root_identity == old.source_identity
                    && e.status == ExecutionStatus::SignedPending),
            "unsettled original signed execution blocks migration entry"
        );
        ensure!(
            !self.has_unsettled_incoming(&old.source_identity)?,
            "unsettled known inbound execution blocks migration entry"
        );
        self.add_rotation_authorization(plan.rotation_id, approvals)?;
        let mutable = self.rotations.get_mut(&plan.rotation_id).unwrap();
        mutable.status = RotationStatus::Migrating;
        mutable.begin_command_id = Some(command.request_id);
        self.roots.get_mut(&command.root_identity).unwrap().phase = Phase::Migrating;
        Ok(())
    }
    pub(crate) fn abandon_rotation(&mut self, command: &Command, id: Uuid) -> Result<()> {
        ensure!(
            self.journal_rules >= 4,
            "rotation abandonment requires current strict rules"
        );
        let old = self
            .rotations
            .get_mut(&id)
            .context("original rotation reservation required")?;
        ensure!(
            old.source_identity == command.root_identity && old.status != RotationStatus::Abandoned,
            "exact current source rotation required"
        );
        // This staging-only layer grants NO movement. Before adding private
        // movement, this boundary must additionally require all such attempts
        // definitively NoSignature; possible signatures can never be abandoned.
        old.status = RotationStatus::Abandoned;
        old.abandon_command_id = Some(command.request_id);
        self.roots
            .get_mut(&command.root_identity)
            .context("source Root missing")?
            .phase = Phase::Frozen;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
