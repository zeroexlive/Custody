//! Explicit same-identity profile migration. These are public shape contracts,
//! never proof of durable migration or authority to perform private MPC work.
use crate::{
    dkg::PARTIES,
    sign::public_package,
    solana_intent::Generation,
    solana_provisioning::Root,
    witness::{hash, hash_text, Phase, Query, QueryReply, Signed},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const APPROVAL_DOMAIN: &str = "WITNESS_PROFILE_MIGRATION_APPROVAL_V1";
pub const FENCE_DOMAIN: &str = "WITNESS_PROFILE_MIGRATION_FENCE_V1";
pub const RENEWAL_DOMAIN: &str = "WITNESS_PROFILE_MIGRATION_RENEWAL_V1";

/// A current witness decision, not a profile self-assertion. Original requests
/// omit this optional certificate; a migrated deployment must require it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeProfilePin {
    pub node_key_id: String,
    pub profile_sha256: String,
    pub anchor_id: Uuid,
    pub authority_id: Uuid,
    pub source_fence_sha256: String,
}
impl NodeProfilePin {
    pub fn validate_shape(&self) -> Result<()> {
        ensure!(
            [
                &self.node_key_id,
                &self.profile_sha256,
                &self.source_fence_sha256
            ]
            .iter()
            .all(|s| hash_text(s) && s.as_str() != "00".repeat(32))
                && !self.anchor_id.is_nil()
                && !self.authority_id.is_nil()
                && self.anchor_id != self.authority_id,
            "exact witness node profile provenance required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CohortRoot {
    pub original: Root,
    pub generation: Generation,
    pub public_key_package: Vec<u8>,
    pub node_keys: BTreeMap<String, String>,
}
impl CohortRoot {
    fn validate(&self) -> Result<()> {
        self.original.validate()?;
        ensure!(
            self.public_key_package.len() <= 4096,
            "bounded cohort public package required"
        );
        public_package(&self.public_key_package, &self.original.group_public_key)?;
        ensure!(
            self.generation.public_key_package_sha256 == hash(&self.public_key_package)
                && !self.generation.ceremony_id.is_nil()
                && self.node_keys.len() == 3
                && PARTIES
                    .iter()
                    .all(|p| self.node_keys.get(*p).is_some_and(|k| hash_text(k)))
                && self.node_keys.values().collect::<BTreeSet<_>>().len() == 3,
            "exact original Root, generation/package and three-key cohort required"
        );
        if self.generation.epoch == 0 {
            ensure!(
                self.generation.ceremony_id == self.original.dkg.execution_id
                    && self.public_key_package == self.original.public_key_package,
                "original-generation cohort cannot relabel another package"
            );
        } else {
            ensure!(
                self.generation.ceremony_id != self.original.dkg.execution_id,
                "refreshed cohort requires its own original ceremony identity"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationPlan {
    pub migration_id: Uuid,
    pub witness_anchor: Uuid,
    pub party_id: String,
    pub node_key_id: String,
    pub old_profile_sha256: String,
    pub new_profile_sha256: String,
    pub source_sequence: u64,
    pub source_event_hash: String,
    pub new_anchor_id: Uuid,
    pub new_lifecycle_key_id: String,
    pub cohort: Vec<CohortRoot>,
    pub expires_at: u64,
}
impl MigrationPlan {
    pub fn validate(&self, now: u64) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            now < self.expires_at && self.expires_at - now <= 300,
            "fresh bounded profile migration approval required"
        );
        Ok(())
    }
    pub fn validate_shape(&self) -> Result<()> {
        let hashes = [
            &self.node_key_id,
            &self.old_profile_sha256,
            &self.new_profile_sha256,
            &self.source_event_hash,
            &self.new_lifecycle_key_id,
        ];
        ensure!(
            PARTIES.contains(&self.party_id.as_str())
                && hashes
                    .iter()
                    .all(|s| hash_text(s) && s.as_str() != "00".repeat(32))
                && !self.migration_id.is_nil()
                && !self.witness_anchor.is_nil()
                && !self.new_anchor_id.is_nil()
                && self.new_anchor_id != self.witness_anchor
                && self.new_anchor_id != self.migration_id
                && self.migration_id != self.witness_anchor
                && self.old_profile_sha256 != self.new_profile_sha256
                && self.new_lifecycle_key_id != self.node_key_id
                && self.expires_at > 0
                && !self.cohort.is_empty()
                && self.cohort.len() <= 32,
            "explicit same-identity profile/source/anchor/Life/cohort required"
        );
        self.source_sequence
            .checked_add(1)
            .context("migration source journal exhausted")?;
        let first = &self.cohort[0].original;
        let mut previous = None;
        for root in &self.cohort {
            root.validate()?;
            let id = root.original.identity()?;
            ensure!(
                previous.as_ref().is_none_or(|p| p < &id)
                    && root.original.wallet_class == first.wallet_class
                    && root.original.genesis_hash == first.genesis_hash
                    && root.node_keys.get(&self.party_id) == Some(&self.node_key_id)
                    && ![
                        root.original.dkg.session_id,
                        root.original.dkg.execution_id,
                        root.generation.ceremony_id
                    ]
                    .contains(&self.migration_id)
                    && ![
                        root.original.dkg.session_id,
                        root.original.dkg.execution_id,
                        root.generation.ceremony_id
                    ]
                    .contains(&self.new_anchor_id),
                "strict ordered unique Root cohort must keep original party key/class/network"
            );
            previous = Some(id);
        }
        Ok(())
    }
    pub fn identity(&self) -> Result<String> {
        self.validate_shape()?;
        crate::hd::fingerprint("SOLANA_PROFILE_MIGRATION_PLAN_V1", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationApprovals {
    pub custody: Signed<MigrationPlan>,
    pub policy: Signed<MigrationPlan>,
    pub lifecycle: Signed<MigrationPlan>,
    /// Current authorization must use the OLD CA/role validators and key pins,
    /// not archival receipt verification alone. Preserve these public chains.
    pub custody_certificate_chain_der_hex: Vec<String>,
    pub policy_certificate_chain_der_hex: Vec<String>,
}
fn certificate_chain_shape(chain: &[String]) -> Result<()> {
    ensure!(
        !chain.is_empty()
            && chain.len() <= 5
            && chain.iter().all(|s| s.len() <= 16384
                && crate::sign::decode_hex(s)
                    .is_some_and(|v| !v.is_empty() && crate::dkg::hex(&v) == *s)),
        "bounded canonical authorization certificate chain required"
    );
    Ok(())
}
impl MigrationApprovals {
    pub fn plan(&self) -> &MigrationPlan {
        &self.custody.value
    }
    pub fn validate_shape(&self) -> Result<()> {
        let p = self.plan();
        p.validate_shape()?;
        certificate_chain_shape(&self.custody_certificate_chain_der_hex)?;
        certificate_chain_shape(&self.policy_certificate_chain_der_hex)?;
        ensure!(
            self.policy.value == *p
                && self.lifecycle.value == *p
                && self.lifecycle.key_id == p.new_lifecycle_key_id
                && [
                    &self.custody.key_id,
                    &self.policy.key_id,
                    &self.lifecycle.key_id,
                    &p.node_key_id
                ]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len()
                    == 4,
            "both original independent approvals and exact new Life plan required"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationFence {
    pub approvals: MigrationApprovals,
    pub fenced_at: u64,
}
impl MigrationFence {
    pub fn validate_shape(&self) -> Result<()> {
        self.approvals.validate_shape()?;
        let p = self.approvals.plan();
        ensure!(
            self.fenced_at > 0
                && self.fenced_at < p.expires_at
                && p.expires_at - self.fenced_at <= 300,
            "original migration intent must have been freshly admitted"
        );
        Ok(())
    }
    pub fn identity(&self) -> Result<String> {
        self.validate_shape()?;
        crate::hd::fingerprint("SOLANA_PROFILE_MIGRATION_FENCE_V1", self)
    }
    /// Call under the witness's locked clock, only for its FIRST durable
    /// reservation. A local signature/fenced_at cannot establish admission time.
    /// Signature + current CA/role validation remain separate mandatory checks.
    pub fn validate_first_registration(
        &self,
        now: u64,
        renewal: Option<&RenewalApprovals>,
    ) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            self.fenced_at <= now,
            "migration fence cannot come from the future"
        );
        if let Some(renewal) = renewal {
            renewal.validate_shape(self)?;
            renewal.custody.value.validate(now)
        } else {
            self.approvals.plan().validate(now)
        }
    }
}

/// A local signer timestamp is not independent evidence of timely admission.
/// When first W registration missed original approval expiry, OLD independent
/// approvers must renew this exact immutable fence/target. An already timely
/// W-reserved plan may instead recover from that authority's durable history.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationRenewal {
    pub migration_id: Uuid,
    pub plan_identity: String,
    pub fence_identity: String,
    pub renewal_id: Uuid,
    pub expires_at: u64,
}
impl MigrationRenewal {
    pub fn validate_shape(&self) -> Result<()> {
        ensure!(
            !self.migration_id.is_nil()
                && !self.renewal_id.is_nil()
                && self.migration_id != self.renewal_id
                && hash_text(&self.plan_identity)
                && self.plan_identity != "00".repeat(32)
                && hash_text(&self.fence_identity)
                && self.fence_identity != "00".repeat(32)
                && self.expires_at > 0,
            "fresh exact-fence original dual renewal required"
        );
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            now < self.expires_at && self.expires_at - now <= 300,
            "fresh original dual renewal required"
        );
        Ok(())
    }
    pub fn matches(&self, fence: &MigrationFence) -> Result<()> {
        self.validate_shape()?;
        fence.validate_shape()?;
        let p = fence.approvals.plan();
        ensure!(
            self.migration_id == p.migration_id
                && self.plan_identity == p.identity()?
                && self.fence_identity == fence.identity()?
                && ![p.migration_id, p.new_anchor_id, p.witness_anchor].contains(&self.renewal_id),
            "renewal must preserve exact original intent/target and use a fresh identity"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenewalApprovals {
    pub custody: Signed<MigrationRenewal>,
    pub policy: Signed<MigrationRenewal>,
    pub lifecycle: Signed<MigrationRenewal>,
    pub custody_certificate_chain_der_hex: Vec<String>,
    pub policy_certificate_chain_der_hex: Vec<String>,
}

/// Permanent independently timed witness authority; completion never removes
/// original fence, source snapshot, renewal or per-Root command identities.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationReservation {
    pub fence: Signed<MigrationFence>,
    pub renewal: Option<RenewalApprovals>,
    pub first_command_id: Uuid,
    pub root_commands: BTreeMap<String, Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationQueryPurpose {
    SourceFence,
    SuccessorImport,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationQueryLease {
    pub purpose: MigrationQueryPurpose,
    pub plan_identity: String,
    pub query: Signed<Query>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationSourceHead {
    pub profile: String,
    pub sequence: u64,
    pub event_hash: String,
}

/// Original node's durable terminal intent. Shape is not signature validation,
/// and its local clock never replaces timely independent W first registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAdmission {
    pub fence: Signed<MigrationFence>,
    pub original_head_json: String,
    pub queries: BTreeMap<String, Signed<MigrationQueryLease>>,
    pub frozen: BTreeMap<String, Signed<QueryReply>>,
}
impl SourceAdmission {
    pub fn validate_shape(&self) -> Result<()> {
        self.fence.value.validate_shape()?;
        let p = self.fence.value.approvals.plan();
        ensure!(
            self.original_head_json.len() <= 4096,
            "bounded original signed head required"
        );
        let head: Signed<MigrationSourceHead> = serde_json::from_str(&self.original_head_json)?;
        ensure!(
            head.key_id == p.node_key_id
                && head.value.profile == p.old_profile_sha256
                && head.value.sequence == p.source_sequence
                && head.value.event_hash == p.source_event_hash,
            "retain the exact original signed pre-fence head"
        );
        let identity = p.identity()?;
        ensure!(
            self.fence.key_id == p.node_key_id
                && self.queries.len() == p.cohort.len()
                && self.frozen.len() == p.cohort.len(),
            "exact original migration source cohort evidence required"
        );
        for root in &p.cohort {
            let id = root.original.identity()?;
            let lease = self
                .queries
                .get(&id)
                .context("original own migration query lease missing")?;
            let reply = self
                .frozen
                .get(&id)
                .context("original frozen witness proof missing")?;
            let q = &lease.value;
            let r = &reply.value;
            ensure!(
                lease.key_id == p.node_key_id
                    && q.purpose == MigrationQueryPurpose::SourceFence
                    && q.query.key_id == p.node_key_id
                    && q.plan_identity == identity
                    && q.query.value == r.query
                    && q.query.value.anchor_id == p.witness_anchor
                    && q.query.value.root_identity == id
                    && q.query.value.execution_id.is_none()
                    && q.query.value.claim_reservation_id.is_none()
                    && hash_text(&q.query.value.challenge)
                    && q.query.value.challenge != "00".repeat(32)
                    && q.issued_at <= self.fence.value.fenced_at
                    && self.fence.value.fenced_at < q.expires_at
                    && q.expires_at - q.issued_at <= 15
                    && r.root.phase == Phase::Frozen
                    && r.root.prepared.is_none()
                    && r.root.original == root.original
                    && r.root.generation == root.generation
                    && r.root.public_key_package == root.public_key_package
                    && r.root.node_keys == root.node_keys
                    && r.lifecycle_key_id.as_ref() == Some(&p.new_lifecycle_key_id)
                    && r.refresh.is_none()
                    && r.replacement.is_none()
                    && !r.node_profiles.contains_key(&p.party_id),
                "exact own fresh pre-registration Frozen cohort/current Life evidence required"
            );
        }
        Ok(())
    }
}
/// Successor genesis proves that the independently timed witness reservation
/// actually installed every approved Root pin. Old source leases cannot authorize
/// this step; the original immutable source is separately replayed in full.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorAdmission {
    pub source_head_json: String,
    pub source_fence_sha256: String,
    pub initialized_at: u64,
    pub queries: BTreeMap<String, Signed<MigrationQueryLease>>,
    pub frozen: BTreeMap<String, Signed<QueryReply>>,
}
impl SuccessorAdmission {
    pub fn validate_shape(&self, source: &SourceAdmission) -> Result<()> {
        source.validate_shape()?;
        let p = source.fence.value.approvals.plan();
        ensure!(
            self.source_head_json.len() <= 4096,
            "bounded final source head required"
        );
        let head: Signed<MigrationSourceHead> = serde_json::from_str(&self.source_head_json)?;
        ensure!(
            head.key_id == p.node_key_id
                && head.value.profile == p.old_profile_sha256
                && Some(head.value.sequence) == p.source_sequence.checked_add(1)
                && hash_text(&head.value.event_hash)
                && head.value.event_hash != "00".repeat(32)
                && self.source_fence_sha256 == source.fence.value.identity()?
                && self.initialized_at >= source.fence.value.fenced_at
                && self.queries.len() == p.cohort.len()
                && self.frozen.len() == p.cohort.len(),
            "exact final terminal source and complete successor cohort required"
        );
        let expected = NodeProfilePin {
            node_key_id: p.node_key_id.clone(),
            profile_sha256: p.new_profile_sha256.clone(),
            anchor_id: p.new_anchor_id,
            authority_id: p.migration_id,
            source_fence_sha256: self.source_fence_sha256.clone(),
        };
        expected.validate_shape()?;
        for root in &p.cohort {
            let id = root.original.identity()?;
            let lease = self
                .queries
                .get(&id)
                .context("own successor query lease missing")?;
            let reply = self
                .frozen
                .get(&id)
                .context("installed Frozen cohort proof missing")?;
            let q = &lease.value;
            let r = &reply.value;
            ensure!(lease.key_id == p.node_key_id
                && q.purpose == MigrationQueryPurpose::SuccessorImport
                && q.query.key_id == p.node_key_id
                && q.plan_identity == p.identity()?
                && q.query.value == r.query
                && q.query.value.anchor_id == p.witness_anchor
                && q.query.value.root_identity == id
                && q.query.value.execution_id.is_none()
                && q.query.value.claim_reservation_id.is_none()
                && hash_text(&q.query.value.challenge)
                && q.query.value.challenge != "00".repeat(32)
                && q.issued_at <= self.initialized_at
                && self.initialized_at < q.expires_at
                && q.expires_at - q.issued_at <= 15
                && r.root.phase == Phase::Frozen
                && r.root.prepared.is_none()
                && r.root.original == root.original
                && r.root.generation == root.generation
                && r.root.public_key_package == root.public_key_package
                && r.root.node_keys == root.node_keys
                && r.lifecycle_key_id.as_ref() == Some(&p.new_lifecycle_key_id)
                && r.refresh.is_none()
                && r.replacement.is_none()
                && r.node_profiles.get(&p.party_id) == Some(&expected),
                "fresh own successor queries and every exact installed Frozen Root profile pin required");
        }
        Ok(())
    }
}
impl MigrationReservation {
    pub fn pending_root(&self, root: &str) -> Result<bool> {
        Ok(
            self.root_commands.len() < self.fence.value.approvals.plan().cohort.len()
                && self
                    .fence
                    .value
                    .approvals
                    .plan()
                    .cohort
                    .iter()
                    .any(|r| r.original.identity().is_ok_and(|id| id == root)),
        )
    }
}
impl RenewalApprovals {
    pub fn validate_shape(&self, fence: &MigrationFence) -> Result<()> {
        certificate_chain_shape(&self.custody_certificate_chain_der_hex)?;
        certificate_chain_shape(&self.policy_certificate_chain_der_hex)?;
        self.custody.value.matches(fence)?;
        ensure!(
            self.custody.value == self.policy.value
                && self.custody.value == self.lifecycle.value
                && self.custody.key_id == fence.approvals.custody.key_id
                && self.policy.key_id == fence.approvals.policy.key_id
                && self.lifecycle.key_id == fence.approvals.lifecycle.key_id,
            "renewal requires the same original independent authority identities"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solana_generation::RefreshStart;

    fn plan() -> MigrationPlan {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/solana-refresh-pre-issuance.json"
        ))
        .unwrap();
        let start: RefreshStart = serde_json::from_value(fixture["start"].clone()).unwrap();
        let r = start.frozen.value.root;
        MigrationPlan {
            migration_id: Uuid::new_v4(),
            witness_anchor: start.plan.value.anchor_id,
            party_id: PARTIES[0].into(),
            node_key_id: r.node_keys[PARTIES[0]].clone(),
            old_profile_sha256: hash(b"shape-only old profile"),
            new_profile_sha256: hash(b"shape-only successor profile"),
            source_sequence: 8,
            source_event_hash: hash(b"shape-only old signed journal head"),
            new_anchor_id: Uuid::new_v4(),
            new_lifecycle_key_id: hash(b"shape-only independent Life key"),
            cohort: vec![CohortRoot {
                original: r.original,
                generation: r.generation,
                public_key_package: r.public_key_package,
                node_keys: r.node_keys,
            }],
            expires_at: 200,
        }
    }
    #[test]
    fn exact_same_identity_cohort_and_source_shape() {
        let p = plan();
        p.validate(100).unwrap();
        assert_eq!(p.identity().unwrap(), p.clone().identity().unwrap());
        let mut bad = p.clone();
        bad.new_profile_sha256 = bad.old_profile_sha256.clone();
        assert!(bad.validate_shape().is_err());
        let mut bad = p.clone();
        bad.cohort.push(bad.cohort[0].clone());
        assert!(bad.validate_shape().is_err());
        let mut bad = p.clone();
        bad.node_key_id = hash(b"changed original node key");
        assert!(bad.validate_shape().is_err());
        let mut bad = p.clone();
        bad.source_sequence = u64::MAX;
        assert!(bad.validate_shape().is_err());
        assert!(p.validate(200).is_err());
        assert!(p.validate(0).is_ok());
    }
    #[test]
    fn independent_approval_values_cannot_diverge() {
        let p = plan();
        // Synthetic signatures below test shape only, not crypto acceptance.
        let proof = |key_id: String| Signed {
            key_id,
            value: p.clone(),
            signature: "00".repeat(70),
        };
        let a = MigrationApprovals {
            custody: proof(hash(b"shape custody key")),
            policy: proof(hash(b"shape policy key")),
            lifecycle: proof(p.new_lifecycle_key_id.clone()),
            custody_certificate_chain_der_hex: vec!["01".repeat(64)],
            policy_certificate_chain_der_hex: vec!["02".repeat(64)],
        };
        a.validate_shape().unwrap();
        let mut bad = a.clone();
        bad.policy.value.source_sequence += 1;
        assert!(bad.validate_shape().is_err());
        let mut bad = a.clone();
        bad.policy.key_id = bad.custody.key_id.clone();
        assert!(bad.validate_shape().is_err());
        let f = MigrationFence {
            approvals: a,
            fenced_at: 100,
        };
        f.validate_shape().unwrap();
        f.validate_first_registration(150, None).unwrap();
        // An honestly or dishonestly backdated signer-signed fence is not
        // evidence of timely independent witness admission after expiry.
        assert!(f.validate_first_registration(201, None).is_err());
        let renewal = MigrationRenewal {
            migration_id: p.migration_id,
            plan_identity: p.identity().unwrap(),
            fence_identity: f.identity().unwrap(),
            renewal_id: Uuid::new_v4(),
            expires_at: 250,
        };
        let proof = |key_id: String| Signed {
            key_id,
            value: renewal.clone(),
            signature: "00".repeat(70),
        };
        let renewed = RenewalApprovals {
            custody: proof(f.approvals.custody.key_id.clone()),
            policy: proof(f.approvals.policy.key_id.clone()),
            lifecycle: proof(f.approvals.lifecycle.key_id.clone()),
            custody_certificate_chain_der_hex: vec!["01".repeat(64)],
            policy_certificate_chain_der_hex: vec!["02".repeat(64)],
        };
        f.validate_first_registration(201, Some(&renewed)).unwrap();
        assert!(f.validate_first_registration(250, Some(&renewed)).is_err());
        let mut other = renewed.clone();
        other.policy.value.fence_identity = hash(b"different fence");
        assert!(f.validate_first_registration(201, Some(&other)).is_err());
        assert!(MigrationFence {
            fenced_at: 200,
            ..f
        }
        .validate_shape()
        .is_err());
    }
}
