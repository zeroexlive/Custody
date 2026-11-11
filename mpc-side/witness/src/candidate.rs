//! Permanent allocation bindings from authenticated manifest entries. These are
//! not registered receipt Evidence, issuance, publication or private permission.
use crate::state::Snapshot;
use anyhow::{ensure, Result};
use wallet_mpc_protocol::solana_provisioning::{Asset, Claim};
fn mint(claim: &Claim) -> &str {
    match &claim.asset {
        Asset::Native => "SOL",
        Asset::ClassicToken { mint, .. } => mint,
    }
}
impl Snapshot {
    pub(crate) fn check_candidate_binding(&self, claim: &Claim) -> Result<()> {
        for original in self.claim_candidates.values() {
            let same_root = original.root == claim.root;
            let collision = original.reservation_id == claim.reservation_id
                || (same_root
                    && (original.index == claim.index
                        || original.idempotency_key == claim.idempotency_key
                        || (original.owner_ref == claim.owner_ref
                            && mint(original) == mint(claim))));
            ensure!(
                !collision || original == claim,
                "original staged allocation aliases and beneficial owner remain permanently bound"
            );
        }
        Ok(())
    }
    pub(crate) fn bind_claim_candidate(&mut self, claim: &Claim) -> Result<()> {
        self.check_candidate_binding(claim)?;
        self.claim_candidates
            .entry(claim.reservation_id)
            .or_insert_with(|| claim.clone());
        Ok(())
    }
}
