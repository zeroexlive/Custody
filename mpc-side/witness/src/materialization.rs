//! Public recovery of data committed by an already accepted C/P rotation plan.
//! A verified hash establishes archival bindings, never current spending rights.
use crate::state::Snapshot;
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use wallet_mpc_protocol::{
    solana_rotation::{
        inventory_fingerprint, InventoryChunk, InventoryMaterializationStatus,
        InventoryMaterializationView, MigrationSource, RotationPlan,
    },
    witness::{Command, Phase},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InventoryMaterialization {
    pub rotation_id: Uuid,
    pub entries: Vec<MigrationSource>,
    pub chunks: BTreeMap<u64, String>,
    pub status: InventoryMaterializationStatus,
    pub conflict: Option<String>,
}

impl Snapshot {
    pub(crate) fn historical_inventory(
        &self,
        plan: &RotationPlan,
    ) -> Result<Option<&[MigrationSource]>> {
        let length = usize::try_from(plan.allocated_high_water)?;
        let root_id = plan.source.identity()?;
        // These vectors already passed their exact complete hash in a committed
        // Stage/Materialize transition. Replay derives the same proof before
        // installing it; immutable entries cannot change between reads. Avoid
        // revalidating every archived Root/Claim on ordinary private requests.
        for available in self
            .rotations
            .values()
            .filter(|r| r.source_identity == root_id)
        {
            let original = available
                .authorizations
                .values()
                .next()
                .context("original retained plan missing")?
                .plan();
            if available.entries.len() == length
                && original.allocated_high_water == plan.allocated_high_water
                && original.inventory_fingerprint == plan.inventory_fingerprint
            {
                return Ok(Some(&available.entries));
            }
        }
        for available in self
            .inventory_materializations
            .values()
            .filter(|m| m.status == InventoryMaterializationStatus::Verified)
        {
            let original = self.rotations[&available.rotation_id]
                .authorizations
                .values()
                .next()
                .context("original retained plan missing")?
                .plan();
            if original.source == plan.source
                && available.entries.len() == length
                && original.allocated_high_water == plan.allocated_high_water
                && original.inventory_fingerprint == plan.inventory_fingerprint
            {
                return Ok(Some(&available.entries));
            }
        }
        // A longer proved vector may supply an old exact prefix too. That
        // distinct commitment still requires its own full-prefix hash check.
        for available in self
            .rotations
            .values()
            .filter(|r| r.source_identity == root_id)
        {
            let original = available
                .authorizations
                .values()
                .next()
                .context("original retained plan missing")?
                .plan();
            // Equal-length complete vectors have a different known full hash:
            // the exact-match fast path already handled the matching case.
            if available.entries.len() == length
                && original.allocated_high_water == plan.allocated_high_water
            {
                continue;
            }
            if available.entries.len() >= length
                && inventory_fingerprint(
                    &plan.source,
                    plan.allocated_high_water,
                    &available.entries[..length],
                )? == plan.inventory_fingerprint
            {
                return Ok(Some(&available.entries[..length]));
            }
        }
        for available in self
            .inventory_materializations
            .values()
            .filter(|m| m.status == InventoryMaterializationStatus::Verified)
        {
            let original = self.rotations[&available.rotation_id]
                .authorizations
                .values()
                .next()
                .context("original retained plan missing")?
                .plan();
            if original.source == plan.source
                && available.entries.len() > length
                && inventory_fingerprint(
                    &plan.source,
                    plan.allocated_high_water,
                    &available.entries[..length],
                )? == plan.inventory_fingerprint
            {
                return Ok(Some(&available.entries[..length]));
            }
        }
        Ok(None)
    }

    pub(crate) fn has_inventory_conflict(&self, root: &str) -> bool {
        self.inventory_materializations.values().any(|m| {
            m.status == InventoryMaterializationStatus::Conflict
                && self.rotations[&m.rotation_id].source_identity == root
        })
    }

    // These exact C/P-approved fields cannot be inferred from publication state.
    pub(crate) fn same_inventory_bindings(a: &[MigrationSource], b: &[MigrationSource]) -> bool {
        a.iter()
            .zip(b)
            .all(|(a, b)| a.claim == b.claim && a.asset_key == b.asset_key && a.role == b.role)
    }

    pub(crate) fn check_historical_bindings(
        &self,
        plan: &RotationPlan,
        entries: &[MigrationSource],
    ) -> Result<()> {
        use wallet_mpc_protocol::solana_provisioning::{Asset, Claim};
        let mint = |claim: &Claim| match &claim.asset {
            Asset::Native => "SOL".to_owned(),
            Asset::ClassicToken { mint, .. } => mint.clone(),
        };
        // Whole-hash verification already established shape/contiguity and
        // unique aliases. Compare retained immutable statements directly in
        // O(N log N), without re-running per-Claim cryptographic shape checks.
        let by_id: BTreeMap<_, _> = entries
            .iter()
            .map(|e| (e.claim.reservation_id, &e.claim))
            .collect();
        let by_index: BTreeMap<_, _> = entries.iter().map(|e| (e.claim.index, &e.claim)).collect();
        let by_retry: BTreeMap<_, _> = entries
            .iter()
            .map(|e| (e.claim.idempotency_key.as_str(), &e.claim))
            .collect();
        let by_owner: BTreeMap<_, _> = entries
            .iter()
            .map(|e| ((e.claim.owner_ref.as_str(), mint(&e.claim)), &e.claim))
            .collect();
        for known in self
            .claim_candidates
            .values()
            .chain(self.claims.values().map(|e| &e.statement))
        {
            let mut matches = vec![by_id.get(&known.reservation_id).copied()];
            if known.root == plan.source {
                matches.extend([
                    by_index.get(&known.index).copied(),
                    by_retry.get(known.idempotency_key.as_str()).copied(),
                    by_owner
                        .get(&(known.owner_ref.as_str(), mint(known)))
                        .copied(),
                ]);
            }
            ensure!(
                matches
                    .into_iter()
                    .flatten()
                    .all(|original| original == known),
                "historical commitment conflicts with permanently bound allocation aliases"
            );
        }
        for entry in entries {
            ensure!(
                !self.rotation_identity_used(entry.claim.reservation_id)
                    || self.claim_candidates.get(&entry.claim.reservation_id) == Some(&entry.claim)
                    || self
                        .claims
                        .get(&entry.claim.reservation_id)
                        .is_some_and(|e| e.statement == entry.claim),
                "historical commitment conflicts with consumed lifecycle identity"
            );
        }
        let root_id = plan.source.identity()?;
        for old in self
            .rotations
            .values()
            .filter(|r| r.source_identity == root_id)
        {
            for original in old.authorizations.values() {
                if let Some(proved) = self.historical_inventory(original.plan())? {
                    ensure!(
                        Self::same_inventory_bindings(proved, entries),
                        "verified historical Claim, asset key or role bindings conflict"
                    );
                }
            }
        }
        Ok(())
    }

    pub(crate) fn materialization_view(
        &self,
        root: &str,
        id: Uuid,
    ) -> Result<Option<InventoryMaterializationView>> {
        self.inventory_materializations
            .get(&id)
            .map(|m| {
                let original = &self.rotations[&m.rotation_id];
                ensure!(
                    original.source_identity == root,
                    "materialization belongs to another original Root"
                );
                let plan = original
                    .authorizations
                    .values()
                    .next()
                    .context("original plan missing")?
                    .plan();
                Ok(InventoryMaterializationView {
                    materialization_id: id,
                    rotation_id: m.rotation_id,
                    next_index: u64::try_from(m.entries.len())?,
                    allocated_high_water: plan.allocated_high_water,
                    inventory_fingerprint: plan.inventory_fingerprint.clone(),
                    status: m.status.clone(),
                    conflict: m.conflict.clone(),
                })
            })
            .transpose()
    }

    pub(crate) fn materialize_inventory(
        &mut self,
        command: &Command,
        rotation_id: Uuid,
        materialization_id: Uuid,
        chunk: &InventoryChunk,
    ) -> Result<()> {
        ensure!(
            self.journal_rules >= 7,
            "historical materialization requires rules7"
        );
        let old = self
            .rotations
            .get(&rotation_id)
            .context("original admitted rotation required")?;
        let plan = old
            .authorizations
            .values()
            .next()
            .context("original C/P commitment missing")?
            .plan()
            .clone();
        let root = self
            .roots
            .get(&command.root_identity)
            .context("original Root missing")?;
        ensure!(old.source_identity == command.root_identity && root.evidence.statement == plan.source
            && root.phase == Phase::Frozen && root.prepared.is_none()
            && command.request_id != materialization_id,
            "data recovery requires exact unprepared Frozen original Root and separate attempt identity");
        // Archive shape and full hash are independent of old TTL, target liveness,
        // current generation and current publication metadata. Fresh command Life/CAS
        // is authenticated by the normal authority path; no old grant is renewed.
        chunk.validate(&plan)?;
        if !self
            .inventory_materializations
            .contains_key(&materialization_id)
        {
            ensure!(
                chunk.start_index == 0
                    && !self.rotation_identity_used(materialization_id)
                    && !self.provisional_claim_id(materialization_id),
                "new materialization starts at zero with an unused permanent attempt identity"
            );
            self.inventory_materializations.insert(
                materialization_id,
                InventoryMaterialization {
                    rotation_id,
                    entries: vec![],
                    chunks: BTreeMap::new(),
                    status: InventoryMaterializationStatus::Collecting,
                    conflict: None,
                },
            );
        }
        let old = &self.inventory_materializations[&materialization_id];
        ensure!(
            old.rotation_id == rotation_id,
            "original materialization cannot change commitment"
        );
        let identity = chunk.identity(&plan)?;
        if let Some(previous) = old.chunks.get(&chunk.start_index) {
            ensure!(
                *previous == identity,
                "original materialization chunk cannot change"
            );
            return Ok(());
        }
        ensure!(
            old.status == InventoryMaterializationStatus::Collecting
                && u64::try_from(old.entries.len())? == chunk.start_index,
            "next original contiguous materialization chunk required"
        );
        for entry in &chunk.entries {
            ensure!(
                entry.claim.reservation_id != command.request_id
                    && entry.claim.reservation_id != materialization_id,
                "proposal Claim identity cannot equal its command or recovery identity"
            );
            // Proposals reserve UUID transport slots, never owners. Existing
            // consumed identities are inspected only after the whole hash proves
            // the archival data, so an authentic conflict can be retained.
        }
        let m = self
            .inventory_materializations
            .get_mut(&materialization_id)
            .unwrap();
        m.entries.extend_from_slice(&chunk.entries);
        m.chunks.insert(chunk.start_index, identity);
        if u64::try_from(m.entries.len())? == plan.allocated_high_water {
            let entries = m.entries.clone();
            plan.validate_inventory(&entries)?;
            let conflict = self
                .check_historical_bindings(&plan, &entries)
                .err()
                .map(|e| e.to_string());
            let m = self
                .inventory_materializations
                .get_mut(&materialization_id)
                .unwrap();
            m.status = if conflict.is_some() {
                InventoryMaterializationStatus::Conflict
            } else {
                InventoryMaterializationStatus::Verified
            };
            m.conflict = conflict;
            if m.status == InventoryMaterializationStatus::Verified {
                for entry in &entries {
                    self.bind_claim_candidate(&entry.claim)?;
                }
            }
        }
        for entry in &chunk.entries {
            self.index_claim_recipient(&entry.claim)?;
        }
        Ok(())
    }
}
