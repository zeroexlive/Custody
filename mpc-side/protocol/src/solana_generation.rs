//! Lifecycle authorization for upstream three-party same-key FROST refresh.
//! A serialized plan or prior generation receipt grants no private signing work.
use crate::{
    dkg::PARTIES,
    sign::public_package,
    solana_intent::Generation,
    solana_provisioning::Root,
    witness::{hash, hash_text, Phase, QueryReply, Signed},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshPlan {
    pub anchor_id: Uuid,
    pub root: Root,
    pub previous: Generation,
    pub previous_public_key_package: Vec<u8>,
    pub session_id: Uuid,
    pub ceremony_id: Uuid,
    pub next_epoch: u64,
    pub node_keys: BTreeMap<String, String>,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshStart {
    pub plan: Signed<RefreshPlan>,
    pub frozen: Signed<QueryReply>,
}
impl RefreshStart {
    /// Public agreement only; callers must verify both pinned signatures and
    /// their own still-live original query challenge before consuming a start.
    pub fn validate_shape(&self) -> Result<()> {
        self.plan.value.validate_shape()?;
        let plan = &self.plan.value;
        let view = &self.frozen.value;
        ensure!(
            view.query.anchor_id == plan.anchor_id
                && view.query.root_identity == plan.root.identity()?
                && view.query.execution_id.is_none()
                && view.query.claim_reservation_id.is_none()
                && hash_text(&view.query.challenge)
                && view.query.challenge != "00".repeat(32)
                && view.root.original == plan.root
                && view.root.generation == plan.previous
                && view.root.public_key_package == plan.previous_public_key_package
                && view.root.node_keys == plan.node_keys
                && view.root.phase == Phase::Frozen
                && view.sequence > 0
                && view.root.revision > 0
                && view.lifecycle_key_id.as_ref() == Some(&self.plan.key_id),
            "exact independently frozen generation/lifecycle authority required"
        );
        Ok(())
    }
}
impl RefreshPlan {
    pub fn validate(&self, now: u64) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            now < self.expires_at && self.expires_at - now <= 300,
            "live lifecycle plan required"
        );
        Ok(())
    }
    pub fn validate_shape(&self) -> Result<()> {
        self.root.validate()?;
        ensure!(!self.anchor_id.is_nil() && !self.session_id.is_nil() && !self.ceremony_id.is_nil()
            && !self.previous.ceremony_id.is_nil()
            && self.ceremony_id!=self.previous.ceremony_id && self.ceremony_id!=self.root.dkg.execution_id
            && self.ceremony_id!=self.root.dkg.session_id && self.session_id!=self.ceremony_id
            && self.session_id!=self.root.dkg.execution_id && self.session_id!=self.root.dkg.session_id
            && self.next_epoch==self.previous.epoch.checked_add(1).context("generation exhausted")?
            && self.previous_public_key_package.len()<=4096
            && hash(&self.previous_public_key_package)==self.previous.public_key_package_sha256
            && (self.previous.epoch!=0 || (self.previous.ceremony_id==self.root.dkg.execution_id
                && self.previous_public_key_package==self.root.public_key_package))
            && (self.previous.epoch==0 || self.previous.ceremony_id!=self.root.dkg.execution_id)
            && self.node_keys.len()==3 && PARTIES.iter().all(|p|self.node_keys.get(*p).is_some_and(|k|hash_text(k)))
            && self.node_keys.values().collect::<BTreeSet<_>>().len()==3
            && self.expires_at>0,
            "exact original root, prior generation, roster, ceremony and live lifecycle plan required");
        public_package(
            &self.previous_public_key_package,
            &self.root.group_public_key,
        )?;
        Ok(())
    }
    pub fn identity(&self) -> Result<String> {
        crate::hd::fingerprint("SOLANA_FROST_REFRESH_PLAN_V1", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_signed_frozen_reply_survives_optional_issuance_schema() {
        let original: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/solana-refresh-pre-issuance.json"
        ))
        .unwrap();
        let start: RefreshStart = serde_json::from_value(original["start"].clone()).unwrap();
        start.validate_shape().unwrap();
        assert!(start.frozen.value.claim_issuance.is_none());
        assert_eq!(serde_json::to_value(&start).unwrap(), original["start"]);
        assert_eq!(
            hash(
                &start
                    .plan
                    .signing_message("WITNESS_FROST_REFRESH_PLAN_V1")
                    .unwrap()
            ),
            original["plan_message_sha256"]
        );
        assert_eq!(
            hash(
                &start
                    .frozen
                    .signing_message("WITNESS_QUERY_REPLY_V1")
                    .unwrap()
            ),
            original["frozen_message_sha256"]
        );
    }
}
