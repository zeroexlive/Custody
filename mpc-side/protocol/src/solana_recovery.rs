//! Explicit new-identity, single-share repair followed by distributed refresh.
//! A plan never changes original DKG or Claim receipts and authorizes no signing.
use crate::{dkg::PARTIES, solana_generation::RefreshPlan, witness::hash_text};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Lifecycle authority must approve both this original replacement identity and
/// the exact subsequent refresh plan. Current-generation repair is staging only;
/// the replacement cannot sign until all-three refresh readiness is activated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplacementPlan {
    pub refresh: RefreshPlan,
    pub previous_node_keys: BTreeMap<String, String>,
    pub party_id: String,
    pub recipient_anchor_id: Uuid,
    pub recipient_profile_sha256: String,
    pub repair_session_id: Uuid,
    pub repair_ceremony_id: Uuid,
}
impl ReplacementPlan {
    pub fn validate(&self, now: u64) -> Result<()> {
        self.validate_shape()?;
        self.refresh.validate(now)
    }
    pub fn validate_shape(&self) -> Result<()> {
        self.refresh.validate_shape()?;
        ensure!(
            PARTIES.contains(&self.party_id.as_str())
                && self.previous_node_keys.len() == 3
                && PARTIES.iter().all(|p| self
                    .previous_node_keys
                    .get(*p)
                    .is_some_and(|v| hash_text(v)))
                && self
                    .previous_node_keys
                    .values()
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 3
                && !self.recipient_anchor_id.is_nil()
                && self.recipient_anchor_id != self.refresh.anchor_id
                && hash_text(&self.recipient_profile_sha256)
                && self.recipient_profile_sha256 != "00".repeat(32),
            "exact old roster, replacement party, fresh anchor and profile required"
        );
        let replacement_key = &self.refresh.node_keys[&self.party_id];
        ensure!(
            !self
                .previous_node_keys
                .values()
                .any(|v| v == replacement_key)
                && PARTIES.iter().all(|p| *p == self.party_id
                    || self.previous_node_keys[*p] == self.refresh.node_keys[*p]),
            "replace exactly one identity; both current helper keys must be unchanged"
        );
        let new_ids = [
            self.repair_session_id,
            self.repair_ceremony_id,
            self.refresh.session_id,
            self.refresh.ceremony_id,
        ];
        let original_ids = [
            self.refresh.root.dkg.session_id,
            self.refresh.root.dkg.execution_id,
            self.refresh.previous.ceremony_id,
        ];
        ensure!(
            new_ids
                .iter()
                .all(|id| !id.is_nil() && !original_ids.contains(id))
                && new_ids.into_iter().collect::<BTreeSet<_>>().len() == 4
                && !new_ids.contains(&self.recipient_anchor_id)
                && !original_ids.contains(&self.recipient_anchor_id),
            "separate original, repair, refresh and recipient journal identities required"
        );
        Ok(())
    }
    pub fn identity(&self) -> Result<String> {
        self.validate_shape()?;
        crate::hd::fingerprint("SOLANA_FROST_REPLACEMENT_PLAN_V1", self)
    }
    pub fn helpers(&self) -> Result<Vec<&'static str>> {
        self.validate_shape()?;
        Ok(PARTIES
            .into_iter()
            .filter(|p| *p != self.party_id)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{solana_generation::RefreshStart, witness::hash};

    fn plan() -> ReplacementPlan {
        // Only genuine public Root/package material from the archived fixture;
        // the synthetic replacement below is a shape contract, not approval.
        let original: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/solana-refresh-pre-issuance.json"
        ))
        .unwrap();
        let start: RefreshStart = serde_json::from_value(original["start"].clone()).unwrap();
        let mut refresh = start.plan.value;
        let previous_node_keys = refresh.node_keys.clone();
        refresh
            .node_keys
            .insert("signer-b".into(), hash(b"shape-only-new-recipient"));
        ReplacementPlan {
            refresh,
            previous_node_keys,
            party_id: "signer-b".into(),
            recipient_anchor_id: Uuid::new_v4(),
            recipient_profile_sha256: hash(b"shape-only-profile"),
            repair_session_id: Uuid::new_v4(),
            repair_ceremony_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn replacement_is_one_new_identity_with_both_original_helpers() {
        let p = plan();
        p.validate_shape().unwrap();
        assert_eq!(p.helpers().unwrap(), ["signer-a", "signer-c"]);
        assert_eq!(p.identity().unwrap(), p.clone().identity().unwrap());
        let mut bad = p.clone();
        bad.refresh.node_keys = bad.previous_node_keys.clone();
        assert!(bad.validate_shape().is_err());
        let mut bad = p.clone();
        bad.refresh
            .node_keys
            .insert("signer-c".into(), hash(b"second-replacement"));
        assert!(bad.validate_shape().is_err());
        let mut bad = p.clone();
        bad.refresh
            .node_keys
            .insert("signer-b".into(), p.previous_node_keys["signer-a"].clone());
        assert!(bad.validate_shape().is_err());
        let mut bad = p;
        bad.party_id = "coordinator".into();
        assert!(bad.validate_shape().is_err());
    }

    #[test]
    fn separate_start_requires_original_enrollment_and_blocks_ordinary_refresh() {
        use crate::solana_provisioning::{Evidence, Report};
        use crate::witness::Signed;
        let original: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/solana-refresh-pre-issuance.json"
        ))
        .unwrap();
        let mut ordinary: RefreshStart = serde_json::from_value(original["start"].clone()).unwrap();
        let p = plan();
        let root = p.refresh.root.clone();
        // Synthetic public signatures exercise shape only; they are never
        // supplied as genuine cryptographic authorization or MPC acceptance.
        let evidence = Evidence {
            statement: root.clone(),
            participant_agreement: PARTIES
                .iter()
                .map(|party| Report {
                    statement: root.clone(),
                    party_id: (*party).into(),
                    durable: true,
                    signer_signature: "00".repeat(70),
                })
                .collect(),
        };
        ordinary.frozen.value.replacement = Some(ReplacementReservation {
            command_id: Uuid::new_v4(),
            plan: p.clone(),
            original_evidence: evidence,
        });
        assert!(ordinary.validate_shape().is_err());
        let start = ReplacementStart {
            plan: Signed {
                key_id: ordinary.plan.key_id.clone(),
                value: p,
                signature: "00".repeat(70),
            },
            frozen: ordinary.frozen,
        };
        start.validate_shape().unwrap();
        let mut changed = start.clone();
        changed
            .frozen
            .value
            .replacement
            .as_mut()
            .unwrap()
            .original_evidence
            .statement
            .ownership_scope = "relabelled".into();
        let transplanted = &mut changed
            .frozen
            .value
            .replacement
            .as_mut()
            .unwrap()
            .original_evidence;
        for report in &mut transplanted.participant_agreement {
            report.statement = transplanted.statement.clone();
        }
        transplanted.validate().unwrap(); // Internally coherent, but for another Root.
        assert!(changed.validate_shape().is_err());
        let mut changed = start.clone();
        changed.frozen.value.root.node_keys = changed.plan.value.refresh.node_keys.clone();
        assert!(changed.validate_shape().is_err());
        let mut changed = start;
        changed.frozen.value.replacement = None;
        assert!(changed.validate_shape().is_err());
    }

    #[test]
    fn repair_cannot_reuse_ceremony_or_erase_recipient_provenance() {
        let p = plan();
        for reused in [
            p.refresh.session_id,
            p.refresh.ceremony_id,
            p.refresh.root.dkg.execution_id,
            p.refresh.root.dkg.session_id,
            p.refresh.previous.ceremony_id,
            p.repair_session_id,
            Uuid::nil(),
        ] {
            let mut bad = p.clone();
            bad.repair_ceremony_id = reused;
            assert!(bad.validate_shape().is_err());
        }
        let mut bad = p.clone();
        bad.recipient_profile_sha256 = "00".repeat(32);
        assert!(bad.validate_shape().is_err());
        let mut bad = p;
        bad.recipient_anchor_id = bad.refresh.anchor_id;
        assert!(bad.validate_shape().is_err());
    }
}

/// The witness's permanent reservation, recovered by an own fresh signed query.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplacementReservation {
    pub command_id: Uuid,
    pub plan: ReplacementPlan,
    pub original_evidence: crate::solana_provisioning::Evidence<crate::solana_provisioning::Root>,
}

/// A separate envelope from ordinary RefreshStart. Original-roster refresh must
/// never silently reinterpret a replacement as an ordinary ceremony.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplacementStart {
    pub plan: crate::witness::Signed<ReplacementPlan>,
    pub frozen: crate::witness::Signed<crate::witness::QueryReply>,
}
impl ReplacementStart {
    /// Callers must independently check both pinned signatures, every original
    /// Root receipt against archival pins, and their own still-live original
    /// query before any private operation is consumed.
    pub fn validate_shape(&self) -> Result<()> {
        self.plan.value.validate_shape()?;
        let p = &self.plan.value;
        let view = &self.frozen.value;
        let reservation = view
            .replacement
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("original witness replacement reservation required"))?;
        reservation.original_evidence.validate()?;
        ensure!(
            reservation.original_evidence.statement == p.refresh.root
                && !reservation.command_id.is_nil()
                && reservation.plan == *p
                && view.query.anchor_id == p.refresh.anchor_id
                && view.query.root_identity == p.refresh.root.identity()?
                && view.query.execution_id.is_none()
                && view.query.claim_reservation_id.is_none()
                && hash_text(&view.query.challenge)
                && view.query.challenge != "00".repeat(32)
                && view.root.original == p.refresh.root
                && view.root.generation == p.refresh.previous
                && view.root.public_key_package == p.refresh.previous_public_key_package
                && view.root.node_keys == p.previous_node_keys
                && view.root.phase == crate::witness::Phase::Frozen
                && view.sequence > 0
                && view.root.revision > 0
                && view.lifecycle_key_id.as_ref() == Some(&self.plan.key_id),
            "exact frozen original generation, roster and current replacement authority required"
        );
        Ok(())
    }
}
