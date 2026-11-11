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
        inventory_fingerprint, InventoryChunk, MigrationSource, RotationApprovals, RotationStatus,
        RotationView, SourceMembership,
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
/// Separate public provenance; the original sealed entry stays unchanged.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RotationClaimRegistration {
    pub command_id: Uuid,
    pub source_fingerprint: String,
    pub evidence: wallet_mpc_protocol::solana_provisioning::Evidence<
        wallet_mpc_protocol::solana_provisioning::Claim,
    >,
}
impl Snapshot {
    pub(crate) fn unresolved_rotation_commitment(&self, root: &str) -> Result<bool> {
        if self.journal_rules >= 7 {
            if self.has_inventory_conflict(root) {
                return Ok(true);
            }
            for old in self
                .rotations
                .values()
                .filter(|r| r.source_identity == root)
            {
                for approval in old.authorizations.values() {
                    let Some(entries) = self.historical_inventory(approval.plan())? else {
                        return Ok(true);
                    };
                    if self
                        .check_historical_bindings(approval.plan(), entries)
                        .is_err()
                    {
                        return Ok(true);
                    }
                }
            }
            return Ok(false);
        }
        for old in self
            .rotations
            .values()
            .filter(|r| r.source_identity == root)
        {
            for authorization in old.authorizations.values() {
                let plan = authorization.plan();
                let count = usize::try_from(plan.allocated_high_water)?;
                let mut proved = false;
                for available in self
                    .rotations
                    .values()
                    .filter(|r| r.source_identity == root)
                {
                    if available.entries.len() >= count
                        && inventory_fingerprint(
                            &plan.source,
                            plan.allocated_high_water,
                            &available.entries[..count],
                        )? == plan.inventory_fingerprint
                    {
                        proved = true;
                        break;
                    }
                }
                if !proved {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
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
    pub(crate) fn rotation_identity_used(&self, id: Uuid) -> bool {
        self.migration_identity_used_without_proposals(id)
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
        if self.journal_rules >= 6 {
            ensure!(
                self.claim_candidates
                    .values()
                    .filter(|c| c.root == plan.source)
                    .all(|c| c.index < plan.allocated_high_water)
                    && self.rotations.values().filter(|r| r.source_identity == source_id).all(|r| {
                        r.authorizations.values().all(|a| {
                            a.plan().allocated_high_water <= plan.allocated_high_water
                        })
                    }),
                "manifest must cover all retained candidates and prior declared allocation frontiers"
            );
        }
        if self.journal_rules >= 7 {
            ensure!(
                !self.has_inventory_conflict(&source_id),
                "conflicting archival inventory requires explicit recovery"
            );
            for prior in self
                .rotations
                .iter()
                .filter(|(id, r)| **id != plan.rotation_id && r.source_identity == source_id)
            {
                for old in prior.1.authorizations.values() {
                    ensure!(
                        self.historical_inventory(old.plan())?.is_some(),
                        "materialize every prior original commitment before new admission"
                    );
                }
            }
        }
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
    pub(crate) fn check_rotation_entry(&self, entry: &MigrationSource) -> Result<()> {
        self.check_rotation_entry_for_rotation(entry, None)
    }
    fn check_rotation_entry_for_rotation(
        &self,
        entry: &MigrationSource,
        rotation_id: Option<Uuid>,
    ) -> Result<()> {
        entry.validate_shape()?;
        self.check_candidate_binding(&entry.claim)?;
        let root = entry.claim.root.identity()?;
        let index = format!("{root}:{}", entry.claim.index);
        if let Some(registered) = self.claims.get(&entry.claim.reservation_id) {
            ensure!(
                registered.statement == entry.claim
                    && (entry.witness_evidence_fingerprint.as_deref()
                        == Some(&fingerprint(
                            "SOLANA_ROTATION_CLAIM_EVIDENCE_V1",
                            registered
                        )?)
                        || (self.journal_rules >= 8
                            && entry.witness_evidence_fingerprint.is_none()
                            && rotation_id.is_some_and(|id| self
                                .rotation_claim_registrations
                                .get(&format!("{id}:{}", entry.claim.reservation_id))
                                .is_some_and(|proof| proof.evidence == *registered
                                    && entry
                                        .identity()
                                        .is_ok_and(|fp| proof.source_fingerprint == fp))))),
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
                !self.rotation_identity_used(plan.authorization_id)
                    && (self.journal_rules < 7
                        || !self.provisional_claim_id(plan.authorization_id)),
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
                    && (self.journal_rules < 7 || !self.provisional_claim_id(plan.rotation_id))
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
            ensure!(
                self.journal_rules < 7 || entry.claim.reservation_id != command.request_id,
                "proposed Claim identity cannot equal its lifecycle command"
            );
            self.check_rotation_entry_for_rotation(entry, Some(plan.rotation_id))?;
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
            let complete_entries = mutable.entries.clone();
            plan.validate_inventory(&complete_entries)?;
            if self.journal_rules == 6 {
                // An old partial plan commits even the tuples whose chunks W
                // never received. A mere high-water floor cannot authenticate
                // those missing owners/aliases. Until explicit historical
                // materialization exists, require every original full-source
                // commitment as an exact prefix, preserving old metadata too.
                for prior in self
                    .rotations
                    .values()
                    .filter(|r| r.source_identity == source)
                {
                    for approval in prior.authorizations.values() {
                        let original = approval.plan();
                        let length = usize::try_from(original.allocated_high_water)?;
                        ensure!(
                            inventory_fingerprint(
                                &original.source,
                                original.allocated_high_water,
                                &complete_entries[..length]
                            )? == original.inventory_fingerprint,
                            "original historical inventory commitment must be recovered exactly"
                        );
                    }
                }
            }
            if self.journal_rules >= 7 {
                ensure!(
                    !self.has_inventory_conflict(&source),
                    "conflicting archive remains quarantined"
                );
                for (id, prior) in self
                    .rotations
                    .iter()
                    .filter(|(_, r)| r.source_identity == source)
                {
                    if *id == plan.rotation_id {
                        continue;
                    }
                    for approval in prior.authorizations.values() {
                        let proved = self
                            .historical_inventory(approval.plan())?
                            .context("original historical inventory data must be materialized")?;
                        ensure!(
                            Self::same_inventory_bindings(proved, &complete_entries),
                            "original Claim, asset key and approved role must remain unchanged"
                        );
                    }
                }
                for entry in &complete_entries {
                    self.check_rotation_entry_for_rotation(entry, Some(plan.rotation_id))?;
                }
            }
            // Every source W Claim is mandatory, even when never published.
            for registered in self
                .claims
                .values()
                .filter(|e| e.statement.root == plan.source)
            {
                let index = usize::try_from(registered.statement.index)?;
                ensure!(
                    complete_entries
                        .get(index)
                        .is_some_and(|e| e.claim == registered.statement),
                    "source inventory omits an original W Claim"
                );
            }
            self.rotations.get_mut(&plan.rotation_id).unwrap().status = RotationStatus::Sealed;
        }
        let admitted = &self.rotations[&plan.rotation_id];
        let promote = if self.journal_rules >= 7 {
            if admitted.status == RotationStatus::Sealed {
                admitted.entries.clone()
            } else {
                vec![]
            }
        } else {
            chunk.entries.clone()
        };
        for entry in &promote {
            if !self.claims.contains_key(&entry.claim.reservation_id) {
                self.bind_claim_candidate(&entry.claim)?;
            }
        }
        // Watched addresses remain even for unverified partial proposals.
        for entry in &chunk.entries {
            self.index_claim_recipient(&entry.claim)?;
        }
        Ok(())
    }
    pub(crate) fn rotation_claim_registration_view(
        &self,
        root: &str,
        rotation_id: Uuid,
        claim_id: Uuid,
    ) -> Result<Option<wallet_mpc_protocol::solana_rotation::RotationClaimRegistrationView>> {
        let Some(rotation) = self.rotations.get(&rotation_id) else {
            return Ok(None);
        };
        ensure!(
            rotation.source_identity == root,
            "rotation provenance belongs to another original Root"
        );
        self.rotation_claim_registrations
            .get(&format!("{rotation_id}:{claim_id}"))
            .map(|proof| {
                ensure!(
                    self.claims.get(&claim_id) == Some(&proof.evidence),
                    "registered rotation evidence link changed"
                );
                Ok(
                    wallet_mpc_protocol::solana_rotation::RotationClaimRegistrationView {
                        rotation_id,
                        command_id: proof.command_id,
                        reservation_id: claim_id,
                        source_fingerprint: proof.source_fingerprint.clone(),
                        evidence_fingerprint: fingerprint(
                            "SOLANA_ROTATION_CLAIM_EVIDENCE_V1",
                            &proof.evidence,
                        )?,
                    },
                )
            })
            .transpose()
    }
    pub(crate) fn register_rotation_claim(
        &mut self,
        command: &Command,
        approvals: &RotationApprovals,
        evidence: &wallet_mpc_protocol::solana_provisioning::Evidence<
            wallet_mpc_protocol::solana_provisioning::Claim,
        >,
        time: Option<u64>,
    ) -> Result<()> {
        ensure!(
            self.journal_rules >= 8,
            "rotation Claim registration requires rules8"
        );
        self.rotation_context(command, approvals, time)?;
        let plan = approvals.plan();
        let original = self
            .rotations
            .get(&plan.rotation_id)
            .context("original sealed rotation required")?;
        ensure!(
            original.status == RotationStatus::Sealed
                && original.business_fingerprint == plan.business_fingerprint()?
                && !self.unresolved_rotation_commitment(&command.root_identity)?,
            "complete resolved sealed source required before public registration"
        );
        evidence.validate_claim()?;
        let claim = &evidence.statement;
        let entry = original
            .entries
            .get(usize::try_from(claim.index)?)
            .context("original sealed source index required")?
            .clone();
        ensure!(
            entry.claim == *claim
                && entry.witness_evidence_fingerprint.is_none()
                && matches!(
                    entry.membership,
                    SourceMembership::Unpublished {}
                        | SourceMembership::LegacyControl { issuance: None }
                ),
            "only exact originally unregistered sealed source may gain readonly public provenance"
        );
        let slot = format!("{}:{}", plan.rotation_id, claim.reservation_id);
        let source_fingerprint = entry.identity()?;
        self.add_rotation_authorization(plan.rotation_id, approvals)?;
        if let Some(registered) = self.claims.get(&claim.reservation_id) {
            ensure!(
                registered == evidence
                    && self
                        .rotation_claim_registrations
                        .get(&slot)
                        .is_some_and(|proof| proof.evidence == *evidence
                            && proof.source_fingerprint == source_fingerprint),
                "original rotation Claim provenance cannot change or adopt existing registration"
            );
            return Ok(());
        }
        self.check_rotation_entry(&entry)?;
        let root = &self.roots[&command.root_identity];
        if let Some(authority) = &evidence.authority {
            let (_, keys) = authority.prepared()?;
            ensure!(
                authority.generation()? == &root.generation
                    && keys == &root.node_keys
                    && self.commands.get(&authority.prepare.value.request_id)
                        == Some(&authority.prepare.value),
                "exact current original Prepare and receipt authority required"
            );
        } else {
            ensure!(
                root.generation.epoch == 0,
                "post-maintenance registration requires current receipt authority"
            );
        }
        let index = format!("{}:{}", command.root_identity, claim.index);
        let owner = claim.owner_slot()?;
        let retry = claim.retry_slot()?;
        ensure!(claim.index == root.next_claim_index && !self.claim_indices.contains_key(&index)
            && !self.claim_owners.contains_key(&owner) && !self.claim_retries.contains_key(&retry)
            && !self.claim_issuances.contains_key(&claim.reservation_id),
            "public registration preserves the original contiguous registered prefix and unissued state");
        self.index_claim_recipient(claim)?;
        self.rotation_claim_registrations.insert(
            slot,
            RotationClaimRegistration {
                command_id: command.request_id,
                source_fingerprint,
                evidence: evidence.clone(),
            },
        );
        self.claims.insert(claim.reservation_id, evidence.clone());
        self.claim_indices.insert(index, claim.reservation_id);
        self.claim_owners.insert(owner, claim.reservation_id);
        self.claim_retries.insert(retry, claim.reservation_id);
        self.roots
            .get_mut(&command.root_identity)
            .unwrap()
            .next_claim_index = claim
            .index
            .checked_add(1)
            .context("claim counter exhausted")?;
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
            self.check_rotation_entry_for_rotation(entry, Some(plan.rotation_id))?;
        }
        // Only an independently acknowledged terminal wire can resolve a
        // SignedPending blocker; the original status/signature is preserved.
        ensure!(
            !self
                .executions
                .iter()
                .any(|(id, e)| e.root_identity == old.source_identity
                    && e.status == ExecutionStatus::SignedPending
                    && !self.finalities.contains_key(id)),
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
