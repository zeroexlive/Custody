//! Authenticated public terminal-wire facts, separate from private and ledger
//! authority. Original SignedPending records and signature ownership stay intact.
use crate::state::Snapshot;
use anyhow::{ensure, Context, Result};
use wallet_mpc_protocol::{
    dkg::PARTIES,
    solana_finality::{FinalityReady, FinalityReceipt},
    witness::{Command, ExecutionStatus, Phase, Signed},
};
impl Snapshot {
    pub(crate) fn acknowledge_finality(
        &mut self,
        command: &Command,
        reports: &[Signed<FinalityReady>],
        time: Option<u64>,
    ) -> Result<()> {
        ensure!(
            self.journal_rules >= 5 && reports.len() == 3,
            "current rules and all three current source observations required"
        );
        let now = time.context("locked independent finality admission clock required")?;
        let first = &reports[0].value;
        let request = &first.observed.lease.request;
        let plan = first.plan();
        let root = &self.roots[&command.root_identity];
        ensure!(
            command.root_identity == plan.root.identity()?
                && plan.witness_anchor == self.anchor_id
                && command.request_id != plan.observation_id
                && plan.expected_revision == command.expected_revision
                && root.evidence.statement == plan.root
                && root.phase == Phase::Frozen
                && root.prepared.is_none()
                && root.generation == plan.observing_generation
                && root.node_keys == plan.observing_node_keys
                && !self.replacements.contains_key(&command.root_identity)
                && !self.refreshes.contains_key(&command.root_identity)
                && !self
                    .profile_migrations
                    .values()
                    .any(|m| m.pending_root(&command.root_identity).unwrap_or(true)),
            "exact Frozen current source without pending maintenance required"
        );
        let execution = self
            .executions
            .get(&plan.execution_id)
            .context("original signed execution required")?;
        ensure!(execution.root_identity==command.root_identity && execution.status==ExecutionStatus::SignedPending
            && execution.signature.as_deref()==Some(&plan.signature_hex)
            && execution.binding.identity()?==plan.binding_fingerprint
            && execution.package==request.signing_public_key_package
            && !self.finalities.contains_key(&plan.execution_id)
            && !self.rotation_identity_used(plan.observation_id),
            "original unacknowledged SignedPending signature and globally fresh observation identity required");
        let mut contexts = std::collections::BTreeMap::new();
        for (signed, party) in reports.iter().zip(PARTIES) {
            let ready = &signed.value;
            ready.validate(now)?;
            ensure!(ready.party_id==party && signed.key_id==root.node_keys[party]
                && ready.observed.lease.request==*request && ready.observed.observation.fact==first.observed.observation.fact,
                "all three exact current source identities must agree on original terminal wire fact");
            if let Some(pin) = self
                .node_profiles
                .get(&command.root_identity)
                .and_then(|p| p.get(party))
            {
                ensure!(
                    pin.node_key_id == signed.key_id
                        && pin.profile_sha256 == ready.profile_fingerprint,
                    "current finality observer profile provenance mismatch"
                );
            }
            contexts.insert(party.into(), ready.observed.observation.status_context_slot);
        }
        self.finalities.insert(
            plan.execution_id,
            FinalityReceipt {
                observation_id: plan.observation_id,
                witness_anchor: self.anchor_id,
                root_identity: command.root_identity.clone(),
                execution_id: plan.execution_id,
                binding_fingerprint: plan.binding_fingerprint.clone(),
                signature_hex: plan.signature_hex.clone(),
                observing_generation: plan.observing_generation.clone(),
                observing_node_keys: plan.observing_node_keys.clone(),
                status_context_slots: contexts,
                source_revision: command.expected_revision,
                command_id: command.request_id,
                sequence: self
                    .sequence
                    .checked_add(1)
                    .context("finality sequence overflow")?,
                fact: first.observed.observation.fact.clone(),
            },
        );
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
