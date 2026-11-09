//! Public recipient index rebuilt by journal replay. It carries no ownership or
//! spend grant. Admission checks run under the same mutex as lifecycle changes.
use crate::state::Snapshot;
use anyhow::{ensure, Context, Result};
use std::collections::BTreeSet;
use wallet_mpc_protocol::{
    dkg::hex,
    solana_intent::Action,
    solana_provisioning::{Claim, Root},
    solana_seeded::{address, key},
    witness::{Binding, ExecutionStatus, Phase},
};
fn slot(genesis: &str, address: &[u8; 32]) -> String {
    format!("{genesis}:{}", hex(address))
}
impl Snapshot {
    pub(crate) fn index_root_recipient(&mut self, root: &Root) -> Result<()> {
        self.known_recipients
            .entry(slot(&root.genesis_hash, &root.base()?))
            .or_default()
            .insert(root.identity()?);
        Ok(())
    }
    pub(crate) fn index_claim_recipient(&mut self, claim: &Claim) -> Result<()> {
        let account = address(&claim.root.base()?, claim.index, claim.asset.token())?;
        self.known_recipients
            .entry(slot(&claim.root.genesis_hash, &account))
            .or_default()
            .insert(claim.root.identity()?);
        Ok(())
    }
    pub(crate) fn incoming_roots(&self, binding: &Binding) -> Result<BTreeSet<String>> {
        let intent = &binding.authorized.intent;
        let genesis = &intent.claim.root.genesis_hash;
        let mut addresses = vec![];
        match &intent.action {
            Action::NativeTransfer { destination, .. } => addresses.push(key(destination)?),
            Action::ClassicTransfer {
                destination_owner, ..
            } => addresses.push(key(destination_owner)?),
            Action::ClassicSeededTransfer {
                destination_base,
                destination_index,
                ..
            } => {
                let base = key(destination_base)?;
                addresses.push(base);
                addresses.push(address(&base, *destination_index, true)?);
            }
            Action::CreateClassicToken { .. } => {}
        }
        Ok(addresses
            .iter()
            .filter_map(|a| self.known_recipients.get(&slot(genesis, a)))
            .flatten()
            .cloned()
            .collect())
    }
    pub(crate) fn check_live_recipients(&self, binding: &Binding) -> Result<()> {
        for id in self.incoming_roots(binding)? {
            ensure!(
                self.roots
                    .get(&id)
                    .context("indexed original recipient Root missing")?
                    .phase
                    == Phase::Active,
                "known incoming recipient Root must remain Active on every private round"
            );
        }
        Ok(())
    }
    pub(crate) fn has_unsettled_incoming(&self, root: &str) -> Result<bool> {
        for execution in self
            .executions
            .values()
            .filter(|e| e.status != ExecutionStatus::NoSignature)
        {
            if self.incoming_roots(&execution.binding)?.contains(root) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
