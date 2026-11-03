//! Pure governed rotation data contracts. These do not grant a private permit,
//! activate a wallet, attest a ledger, establish chain finality or retire a Root.
//! W/state, independent signatures and actual source/target control are separate.
use crate::{
    dkg::PARTIES,
    hd::fingerprint,
    solana_financial::SourceRole,
    solana_intent::Generation,
    solana_provisioning::{Asset, Claim, Root},
    witness::{hash, hash_text, ClaimIssuance, Signed},
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const VERSION: u16 = 1;
pub const PLAN_DOMAIN: &str = "WITNESS_SOLANA_ROTATION_PLAN_V1";
pub const INVENTORY_DOMAIN: &str = "SOLANA_ROTATION_INVENTORY_V1";
pub const MAX_INVENTORY_CHUNK: usize = 32;
pub const MAX_PLAN_BYTES: usize = 256 * 1024;
pub const MAX_CHUNK_BYTES: usize = 128 * 1024;

fn digest(value: &str) -> bool {
    hash_text(value) && value != "00".repeat(32)
}
fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
fn principal(value: &str) -> bool {
    value.strip_prefix("p1:").is_some_and(canonical_uuid)
}
fn asset_key(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 32
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn roster(keys: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        keys.len() == 3
            && PARTIES
                .iter()
                .all(|p| keys.get(*p).is_some_and(|v| digest(v)))
            && keys.values().collect::<BTreeSet<_>>().len() == 3,
        "exact three distinct original party identities required"
    );
    Ok(())
}
fn generation(root: &Root, value: &Generation) -> Result<()> {
    ensure!(
        !value.ceremony_id.is_nil() && digest(&value.public_key_package_sha256),
        "explicit current generation reference required"
    );
    if value.epoch == 0 {
        ensure!(
            value.ceremony_id == root.dkg.execution_id
                && value.public_key_package_sha256 == hash(&root.public_key_package),
            "epoch zero must be the exact original DKG marker"
        );
    } else {
        ensure!(
            ![
                root.dkg.session_id,
                root.dkg.execution_id,
                root.dkg.keyset_id
            ]
            .contains(&value.ceremony_id),
            "maintenance generation cannot reuse original DKG identities"
        );
    }
    Ok(())
}

/// The stored financial-membership publication state, not current Root liveness
/// or private permission. A retired Root can retain its original ACTIVE record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinancialPublication {
    Pending,
    Active,
}

/// Describes prior membership, not an instruction to create/activate one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum SourceMembership {
    Unpublished {},
    LegacyControl {},
    Financial {
        issuance: ClaimIssuance,
        publication: FinancialPublication,
    },
}

/// A read-only declaration for the original reserved address/owner. Control-only
/// and unpublished entries do not acquire ordinary financial wallet authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationSource {
    pub claim: Claim,
    pub asset_key: String,
    pub role: SourceRole,
    pub membership: SourceMembership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_evidence_fingerprint: Option<String>,
}
impl MigrationSource {
    pub fn validate_shape(&self) -> Result<()> {
        self.claim.validate()?;
        ensure!(
            canonical_uuid(&self.claim.root.ownership_scope)
                && principal(&self.claim.owner_ref)
                && asset_key(&self.asset_key)
                && self
                    .witness_evidence_fingerprint
                    .as_deref()
                    .is_none_or(digest),
            "original tenant, beneficial owner, asset and archival proof identity required"
        );
        if let SourceMembership::Financial { issuance, .. } = &self.membership {
            ensure!(
                issuance.reservation_id == self.claim.reservation_id
                    && !issuance.issuance_id.is_nil()
                    && !issuance.command_id.is_nil()
                    && issuance.issuance_id != issuance.command_id
                    && issuance.issuance_id != self.claim.reservation_id
                    && issuance.command_id != self.claim.reservation_id
                    && issuance.initialization_execution_id.is_some() == self.claim.asset.token()
                    && issuance
                        .initialization_execution_id
                        .is_none_or(|id| !id.is_nil()
                            && id != issuance.issuance_id
                            && id != issuance.command_id
                            && id != self.claim.reservation_id)
                    && self.witness_evidence_fingerprint.is_some(),
                "exact prior issuance identity required; membership is not inferred from a balance"
            );
        }
        Ok(())
    }
    pub fn validate_movement_source(&self) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            self.witness_evidence_fingerprint.is_some(),
            "unregistered source remains inventory only, never a private movement permission"
        );
        Ok(())
    }
    pub fn identity(&self) -> Result<String> {
        self.validate_shape()?;
        fingerprint("SOLANA_ROTATION_SOURCE_V1", self)
    }
}

/// The complete finite reserved namespace, including unpublished entries. It is
/// transported in bounded chunks; the digest alone proves neither completeness
/// against a live database nor actual control of its entries.
pub fn inventory_fingerprint(
    root: &Root,
    allocated_high_water: u64,
    entries: &[MigrationSource],
) -> Result<String> {
    root.validate()?;
    ensure!(
        allocated_high_water <= (1u64 << 63)
            && u64::try_from(entries.len())? == allocated_high_water,
        "complete finite allocated inventory required"
    );
    let (mut ids, mut owners, mut retries) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for (index, entry) in entries.iter().enumerate() {
        entry.validate_shape()?;
        ensure!(
            entry.claim.root == *root
                && entry.claim.index == u64::try_from(index)?
                && ids.insert(entry.claim.reservation_id)
                && owners.insert(entry.claim.owner_slot()?)
                && retries.insert(entry.claim.retry_slot()?),
            "inventory cannot skip/reorder/reassign original indices, owners or aliases"
        );
    }
    fingerprint(
        INVENTORY_DOMAIN,
        &(root.identity()?, allocated_high_water, entries),
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RotationDestination {
    pub treasury: MigrationSource,
}
impl RotationDestination {
    pub fn validate_shape(&self, target: &Root) -> Result<()> {
        self.treasury.validate_movement_source()?;
        ensure!(
            self.treasury.claim.root == *target
                && self.treasury.role == SourceRole::TenantTreasury
                && matches!(
                    self.treasury.membership,
                    SourceMembership::Financial {
                        publication: FinancialPublication::Active,
                        ..
                    }
                ),
            "governed destination must be this target Root's previously issued treasury"
        );
        Ok(())
    }
}

/// An exact independently approved transition. Source admission, historical-key
/// disjointness, target liveness, incoming executions and cycles are W/state
/// checks; this pure shape validation cannot establish any of them.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RotationPlan {
    pub version: u16,
    pub rotation_id: Uuid,
    /// Fresh approval attempt; the business/rotation identity remains stable.
    pub authorization_id: Uuid,
    pub witness_anchor: Uuid,
    pub source: Root,
    pub source_generation: Generation,
    pub source_node_keys: BTreeMap<String, String>,
    pub target: Root,
    pub target_generation: Generation,
    pub target_node_keys: BTreeMap<String, String>,
    pub allocated_high_water: u64,
    pub inventory_fingerprint: String,
    pub destinations: Vec<RotationDestination>,
    pub max_fee_per_movement_lamports: u64,
    /// Cumulative approved fees, including failed finalized attempts. Renewal
    /// cannot replenish this; explicit governed replanning preserves old holds.
    pub total_fee_budget_lamports: u64,
    pub retained_root_gas_lamports: u64,
    pub retained_classic_rent_lamports: u64,
    pub expires_at: u64,
}
impl RotationPlan {
    pub fn validate_shape(&self) -> Result<()> {
        self.source.validate()?;
        self.target.validate()?;
        roster(&self.source_node_keys)?;
        roster(&self.target_node_keys)?;
        generation(&self.source, &self.source_generation)?;
        generation(&self.target, &self.target_generation)?;
        let ids = [
            self.rotation_id,
            self.authorization_id,
            self.witness_anchor,
            self.source.dkg.keyset_id,
            self.source.dkg.session_id,
            self.source.dkg.execution_id,
            self.target.dkg.keyset_id,
            self.target.dkg.session_id,
            self.target.dkg.execution_id,
        ];
        ensure!(
            self.version == VERSION && ids.iter().all(|id| !id.is_nil())
                && ids.iter().collect::<BTreeSet<_>>().len() == ids.len()
                && canonical_uuid(&self.source.ownership_scope)
                && self.source.ownership_scope == self.target.ownership_scope
                && self.source.genesis_hash == self.target.genesis_hash
                && self.source.chain_id == self.target.chain_id
                && self.source.wallet_class == self.target.wallet_class
                && self.source.group_public_key != self.target.group_public_key
                && self.source_node_keys.values().all(|k| !self.target_node_keys.values().any(|t| t == k))
                && self.allocated_high_water <= (1u64 << 63)
                && digest(&self.inventory_fingerprint)
                && !self.destinations.is_empty() && self.destinations.len() <= MAX_INVENTORY_CHUNK
                && self.max_fee_per_movement_lamports > 0 && self.total_fee_budget_lamports > 0
                && self.expires_at > 0,
            "distinct fresh-DKG cohorts and exact tenant/network/class/inventory/fee authority required"
        );
        let mut markers: BTreeSet<_> = ids.into_iter().collect();
        for context in [&self.source_generation, &self.target_generation] {
            if context.epoch > 0 {
                ensure!(
                    markers.insert(context.ceremony_id),
                    "current generation cannot reuse another lifecycle/context identity"
                );
            }
        }
        let (mut assets, mut namespaces, mut claims) =
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for destination in &self.destinations {
            destination.validate_shape(&self.target)?;
            let source = &destination.treasury;
            let namespace = match &source.claim.asset {
                Asset::Native => "SOL".to_string(),
                Asset::ClassicToken { mint, .. } => mint.clone(),
            };
            ensure!(
                assets.insert(&source.asset_key)
                    && namespaces.insert(namespace)
                    && claims.insert(source.claim.reservation_id),
                "one immutable treasury destination per exact asset namespace required"
            );
        }
        ensure!(
            serde_json::to_vec(&serde_json::to_value(self)?)?.len() <= MAX_PLAN_BYTES,
            "rotation plan exceeds bounded approval envelope"
        );
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            now < self.expires_at && self.expires_at - now <= 300,
            "fresh independent rotation approvals required"
        );
        Ok(())
    }
    pub fn identity(&self) -> Result<String> {
        self.validate_shape()?;
        fingerprint(PLAN_DOMAIN, self)
    }
    /// Stable business target/inventory. Renewal or maintenance requires new
    /// signed context and W admission, never mutation of an existing attempt.
    pub fn business_fingerprint(&self) -> Result<String> {
        self.validate_shape()?;
        fingerprint(
            "SOLANA_ROTATION_BUSINESS_V1",
            &(
                self.version,
                self.rotation_id,
                self.witness_anchor,
                &self.source,
                &self.target,
                self.allocated_high_water,
                &self.inventory_fingerprint,
                &self.destinations,
                self.max_fee_per_movement_lamports,
                self.total_fee_budget_lamports,
                self.retained_root_gas_lamports,
                self.retained_classic_rent_lamports,
            ),
        )
    }
    /// Typed data selection only; no source control, target liveness or private
    /// permission follows from finding a destination in the approved plan.
    pub fn destination_for<'a>(
        &'a self,
        source: &MigrationSource,
    ) -> Result<&'a RotationDestination> {
        self.validate_shape()?;
        source.validate_shape()?;
        ensure!(
            source.claim.root == self.source,
            "wrong original source Root"
        );
        self.destinations
            .iter()
            .find(|target| {
                target.treasury.asset_key == source.asset_key
                    && target.treasury.claim.asset == source.claim.asset
            })
            .ok_or_else(|| {
                anyhow::anyhow!("exact source asset/key/mint/decimals has no governed target")
            })
    }
    pub fn validate_inventory(&self, entries: &[MigrationSource]) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            inventory_fingerprint(&self.source, self.allocated_high_water, entries)?
                == self.inventory_fingerprint,
            "different allocated inventory"
        );
        for entry in entries {
            self.destination_for(entry)?;
        }
        Ok(())
    }
}

/// Bounded transport of a complete manifest. The W state must accept only the
/// next contiguous chunk, preserve every old chunk and verify the final whole
/// inventory fingerprint before granting any migration permission.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InventoryChunk {
    pub business_fingerprint: String,
    pub start_index: u64,
    pub entries: Vec<MigrationSource>,
}
impl InventoryChunk {
    pub fn validate(&self, plan: &RotationPlan) -> Result<()> {
        plan.validate_shape()?;
        ensure!(
            self.business_fingerprint == plan.business_fingerprint()?
                && !self.entries.is_empty()
                && self.entries.len() <= MAX_INVENTORY_CHUNK
                && self
                    .start_index
                    .checked_add(u64::try_from(self.entries.len())?)
                    .is_some_and(|end| end <= plan.allocated_high_water),
            "bounded contiguous chunk of the exact original rotation business required"
        );
        let (mut ids, mut owners, mut retries) =
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        for (offset, entry) in self.entries.iter().enumerate() {
            entry.validate_shape()?;
            ensure!(
                entry.claim.root == plan.source
                    && entry.claim.index == self.start_index + u64::try_from(offset)?
                    && ids.insert(entry.claim.reservation_id)
                    && owners.insert(entry.claim.owner_slot()?)
                    && retries.insert(entry.claim.retry_slot()?),
                "chunk cannot reorder or substitute original reserved aliases"
            );
            plan.destination_for(entry)?;
        }
        ensure!(
            serde_json::to_vec(&serde_json::to_value(self)?)?.len() <= MAX_CHUNK_BYTES,
            "inventory chunk exceeds bounded public transport envelope"
        );
        Ok(())
    }
    pub fn identity(&self, plan: &RotationPlan) -> Result<String> {
        self.validate(plan)?;
        fingerprint("SOLANA_ROTATION_CHUNK_V1", self)
    }
}

/// Detached machine/Policy approvals of the same exact plan. Shape checks are
/// not signature verification: W must authenticate both roles independently,
/// then authenticate the separate Lifecycle command under its installed pin.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RotationApprovals {
    pub custody: Signed<RotationPlan>,
    pub policy: Signed<RotationPlan>,
    pub custody_certificate_chain_der_hex: Vec<String>,
    pub policy_certificate_chain_der_hex: Vec<String>,
}
impl RotationApprovals {
    pub fn plan(&self) -> &RotationPlan {
        &self.custody.value
    }
    pub fn validate_shape(&self) -> Result<()> {
        self.plan().validate_shape()?;
        ensure!(
            self.custody.value == self.policy.value
                && digest(&self.custody.key_id)
                && digest(&self.policy.key_id)
                && self.custody.key_id != self.policy.key_id,
            "independent Custody and Policy must approve the identical rotation plan"
        );
        for proof in [&self.custody, &self.policy] {
            ensure!(
                crate::sign::decode_hex(&proof.signature)
                    .is_some_and(|bytes| (8..=80).contains(&bytes.len())
                        && crate::dkg::hex(&bytes) == proof.signature),
                "bounded canonical detached approval signature required"
            );
        }
        for chain in [
            &self.custody_certificate_chain_der_hex,
            &self.policy_certificate_chain_der_hex,
        ] {
            ensure!(
                !chain.is_empty()
                    && chain.len() <= 5
                    && chain.iter().all(|leaf| leaf.len() <= 32768
                        && crate::sign::decode_hex(leaf).is_some_and(
                            |bytes| !bytes.is_empty() && crate::dkg::hex(&bytes) == *leaf
                        )),
                "bounded canonical public approval chains required"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixtures() -> (
        Root,
        BTreeMap<String, String>,
        Root,
        BTreeMap<String, String>,
    ) {
        // Public statements only; all authorization/issuance IDs below are
        // synthetic shape fixtures and are not MPC or retirement acceptance.
        let value: Value =
            serde_json::from_str(include_str!("../tests/fixtures/solana-rotation-roots.json"))
                .unwrap();
        (
            serde_json::from_value(value["source"]["root"].clone()).unwrap(),
            serde_json::from_value(value["source"]["node_keys"].clone()).unwrap(),
            serde_json::from_value(value["target"]["root"].clone()).unwrap(),
            serde_json::from_value(value["target"]["node_keys"].clone()).unwrap(),
        )
    }
    fn original(root: &Root) -> Generation {
        Generation {
            epoch: 0,
            ceremony_id: root.dkg.execution_id,
            public_key_package_sha256: hash(&root.public_key_package),
        }
    }
    fn source(root: Root, index: u64) -> MigrationSource {
        MigrationSource {
            claim: Claim {
                root,
                reservation_id: Uuid::new_v4(),
                owner_ref: format!("p1:{}", Uuid::new_v4()),
                idempotency_key: Uuid::new_v4().to_string(),
                index,
                asset: Asset::Native,
            },
            asset_key: "SOL".into(),
            role: SourceRole::CustomerDeposit,
            membership: SourceMembership::Unpublished {},
            witness_evidence_fingerprint: None,
        }
    }
    fn financial(mut value: MigrationSource) -> MigrationSource {
        value.witness_evidence_fingerprint = Some("11".repeat(32));
        value.membership = SourceMembership::Financial {
            publication: FinancialPublication::Active,
            issuance: ClaimIssuance {
                reservation_id: value.claim.reservation_id,
                issuance_id: Uuid::new_v4(),
                command_id: Uuid::new_v4(),
                initialization_execution_id: None,
            },
        };
        value
    }
    fn plan() -> RotationPlan {
        let (a, a_keys, b, b_keys) = fixtures();
        let inventory = vec![source(a.clone(), 0)];
        let mut treasury = financial(source(b.clone(), 0));
        treasury.role = SourceRole::TenantTreasury;
        RotationPlan {
            version: VERSION,
            rotation_id: Uuid::new_v4(),
            authorization_id: Uuid::new_v4(),
            witness_anchor: Uuid::new_v4(),
            source_generation: original(&a),
            source: a.clone(),
            source_node_keys: a_keys,
            target_generation: original(&b),
            target: b,
            target_node_keys: b_keys,
            allocated_high_water: 1,
            inventory_fingerprint: inventory_fingerprint(&a, 1, &inventory).unwrap(),
            destinations: vec![RotationDestination { treasury }],
            max_fee_per_movement_lamports: 20_000,
            total_fee_budget_lamports: 100_000,
            retained_root_gas_lamports: 1_000_000,
            retained_classic_rent_lamports: 0,
            expires_at: 1200,
        }
    }

    #[test]
    fn inventory_covers_unpublished_original_indices_without_granting_movement() {
        let (root, _, _, _) = fixtures();
        let a = source(root.clone(), 0);
        let b = source(root.clone(), 1);
        let entries = vec![a.clone(), b.clone()];
        let identity = inventory_fingerprint(&root, 2, &entries).unwrap();
        assert!(a.validate_movement_source().is_err());
        assert!(inventory_fingerprint(&root, 1, &entries).is_err());
        assert!(inventory_fingerprint(&root, 2, &[b.clone(), a.clone()]).is_err());
        assert!(inventory_fingerprint(&root, 2, &[a.clone(), a.clone()]).is_err());
        let mut changed = entries.clone();
        changed[0].membership = SourceMembership::LegacyControl {};
        assert_ne!(identity, inventory_fingerprint(&root, 2, &changed).unwrap());
        assert!(changed[0].validate_movement_source().is_err());
        changed[0].witness_evidence_fingerprint = Some("22".repeat(32));
        changed[0].validate_movement_source().unwrap(); // Shape only, not a W grant.
        assert_ne!(identity, inventory_fingerprint(&root, 2, &changed).unwrap());
        changed = entries;
        changed[1].claim.owner_ref = a.claim.owner_ref;
        assert!(inventory_fingerprint(&root, 2, &changed).is_err());
    }

    #[test]
    fn source_membership_requires_original_issuance_and_token_initialization() {
        let (root, _, _, _) = fixtures();
        let value = financial(source(root.clone(), 0));
        value.validate_shape().unwrap();
        let mut altered = value.clone();
        if let SourceMembership::Financial { issuance, .. } = &mut altered.membership {
            issuance.reservation_id = Uuid::new_v4();
        }
        assert!(altered.validate_shape().is_err());
        altered = value.clone();
        altered.claim.owner_ref = "arbitrary-owner".into();
        assert!(altered.validate_shape().is_err());
        altered = value.clone();
        altered.witness_evidence_fingerprint = None;
        assert!(altered.validate_shape().is_err());
        altered = value;
        altered.claim.asset = Asset::ClassicToken {
            mint: root.genesis_hash,
            decimals: 6,
        };
        assert!(altered.validate_shape().is_err());
        if let SourceMembership::Financial { issuance, .. } = &mut altered.membership {
            issuance.initialization_execution_id = Some(Uuid::new_v4());
        }
        altered.validate_shape().unwrap();
    }

    #[test]
    fn exact_plan_has_short_fresh_approvals_and_domain_separated_identity() {
        let value = plan();
        value.validate(1000).unwrap();
        assert!(value.validate(1200).is_err());
        assert!(value.validate(899).is_err());
        let mut changed = value.clone();
        changed.max_fee_per_movement_lamports += 1;
        assert_ne!(value.identity().unwrap(), changed.identity().unwrap());
        changed = value.clone();
        changed.retained_root_gas_lamports += 1;
        assert_ne!(value.identity().unwrap(), changed.identity().unwrap());
        let encoded = serde_json::to_value(&value).unwrap();
        let mut unknown = encoded.clone();
        unknown["activate_financial_wallet"] = json!(true);
        assert!(serde_json::from_value::<RotationPlan>(unknown).is_err());
        let restored: RotationPlan = serde_json::from_value(encoded).unwrap();
        assert_eq!(value, restored);
    }

    #[test]
    fn wrong_tenant_network_ids_roster_and_destination_fail_closed() {
        let value = plan();
        for fault in 0..14 {
            let mut changed = value.clone();
            match fault {
                0 => changed.rotation_id = Uuid::nil(),
                1 => changed.rotation_id = changed.target.dkg.keyset_id,
                2 => changed.target.ownership_scope = Uuid::new_v4().to_string(),
                3 => changed.target.genesis_hash = bs58::encode([91u8; 32]).into_string(),
                4 => changed.target.dkg.session_id = changed.source.dkg.session_id,
                5 => changed
                    .source_node_keys
                    .remove("signer-a")
                    .map(drop)
                    .unwrap(),
                6 => changed.target_node_keys = changed.source_node_keys.clone(),
                7 => changed.inventory_fingerprint = "00".repeat(32),
                8 => changed.max_fee_per_movement_lamports = 0,
                9 => changed.destinations[0].treasury.role = SourceRole::CustomerDeposit,
                10 => changed.destinations[0].treasury.claim.root = changed.source.clone(),
                11 => changed.destinations.push(changed.destinations[0].clone()),
                12 => changed.source_generation.ceremony_id = Uuid::new_v4(),
                13 => changed.target_generation.public_key_package_sha256 = "33".repeat(32),
                _ => unreachable!(),
            }
            assert!(
                changed.validate_shape().is_err(),
                "accepted mutation {fault}"
            );
        }
    }
    #[test]
    fn detached_plan_approvals_cannot_substitute_role_or_business_fields() {
        let value = plan();
        let mut approval = RotationApprovals {
            custody: Signed {
                key_id: "11".repeat(32),
                value: value.clone(),
                signature: "30".repeat(8),
            },
            policy: Signed {
                key_id: "22".repeat(32),
                value,
                signature: "30".repeat(8),
            },
            custody_certificate_chain_der_hex: vec!["01".into()],
            policy_certificate_chain_der_hex: vec!["02".into()],
        };
        // These deliberately synthetic bytes establish only bounded shape,
        // never authentic authority, chain trust, grant or retirement evidence.
        approval.validate_shape().unwrap();
        let original = approval.clone();
        approval.policy.key_id = approval.custody.key_id.clone();
        assert!(approval.validate_shape().is_err());
        approval = original.clone();
        approval.policy.value.retained_root_gas_lamports += 1;
        assert!(approval.validate_shape().is_err());
        approval = original.clone();
        approval.policy.signature.push('A');
        assert!(approval.validate_shape().is_err());
        approval = original;
        approval.custody_certificate_chain_der_hex.clear();
        assert!(approval.validate_shape().is_err());
    }
    #[test]
    fn current_context_ids_are_separate_from_stable_rotation_business() {
        let original = plan();
        let mut renewed = original.clone();
        renewed.authorization_id = Uuid::new_v4();
        renewed.expires_at += 30;
        renewed.source_generation = Generation {
            epoch: 1,
            ceremony_id: Uuid::new_v4(),
            public_key_package_sha256: "44".repeat(32),
        };
        renewed.validate_shape().unwrap();
        assert_eq!(
            original.business_fingerprint().unwrap(),
            renewed.business_fingerprint().unwrap()
        );
        assert_ne!(original.identity().unwrap(), renewed.identity().unwrap());
        for forbidden in [
            renewed.rotation_id,
            renewed.authorization_id,
            renewed.witness_anchor,
            renewed.target.dkg.session_id,
            renewed.target.dkg.execution_id,
            renewed.target.dkg.keyset_id,
            renewed.source.dkg.keyset_id,
        ] {
            let mut invalid = renewed.clone();
            invalid.source_generation.ceremony_id = forbidden;
            assert!(invalid.validate_shape().is_err());
        }
        renewed.target_generation = Generation {
            epoch: 1,
            ceremony_id: renewed.source_generation.ceremony_id,
            public_key_package_sha256: "55".repeat(32),
        };
        assert!(renewed.validate_shape().is_err());
        let mut changed = original.clone();
        changed.max_fee_per_movement_lamports += 1;
        assert_ne!(
            original.business_fingerprint().unwrap(),
            changed.business_fingerprint().unwrap()
        );
    }

    #[test]
    fn malformed_proof_and_unknown_membership_never_become_a_control_grant() {
        let (root, _, _, _) = fixtures();
        let original = source(root, 0);
        for malformed in [
            "".into(),
            "00".repeat(32),
            "AA".repeat(32),
            "1".repeat(63),
            "not-hex".into(),
        ] {
            let mut invalid = original.clone();
            invalid.witness_evidence_fingerprint = Some(malformed);
            assert!(invalid.validate_shape().is_err());
        }
        let mut unknown = serde_json::to_value(&original).unwrap();
        unknown["membership"] = json!({"kind":"Unpublished", "activate_financial_mode":true});
        assert!(serde_json::from_value::<MigrationSource>(unknown).is_err());
        let mut financial = financial(original);
        if let SourceMembership::Financial { issuance, .. } = &mut financial.membership {
            issuance.initialization_execution_id = Some(Uuid::new_v4());
        }
        assert!(financial.validate_shape().is_err()); // Native cannot claim SPL initialization.
    }

    #[test]
    fn each_original_alias_is_unique_independently_of_index_order() {
        let (root, _, _, _) = fixtures();
        let original = vec![source(root.clone(), 0), source(root.clone(), 1)];
        inventory_fingerprint(&root, 2, &original).unwrap();
        for fault in 0..3 {
            let mut invalid = original.clone();
            match fault {
                0 => invalid[1].claim.reservation_id = invalid[0].claim.reservation_id,
                1 => invalid[1].claim.owner_ref = invalid[0].claim.owner_ref.clone(),
                2 => invalid[1].claim.idempotency_key = invalid[0].claim.idempotency_key.clone(),
                _ => unreachable!(),
            }
            assert!(inventory_fingerprint(&root, 2, &invalid).is_err());
        }
    }

    #[test]
    fn complete_inventory_and_destination_selection_bind_label_mint_and_decimals() {
        let mut value = plan();
        let mut token = source(value.source.clone(), 0);
        token.asset_key = "SPL-TEST".into();
        token.claim.asset = Asset::ClassicToken {
            mint: value.source.genesis_hash.clone(),
            decimals: 6,
        };
        let mut target = financial(source(value.target.clone(), 0));
        target.asset_key = token.asset_key.clone();
        target.claim.asset = token.claim.asset.clone();
        target.role = SourceRole::TenantTreasury;
        if let SourceMembership::Financial { issuance, .. } = &mut target.membership {
            issuance.initialization_execution_id = Some(Uuid::new_v4());
        }
        value.destinations = vec![RotationDestination { treasury: target }];
        value.inventory_fingerprint =
            inventory_fingerprint(&value.source, 1, &[token.clone()]).unwrap();
        value.validate_inventory(&[token.clone()]).unwrap();
        assert!(token.validate_movement_source().is_err());
        value.destination_for(&token).unwrap(); // Data selection is not permission.
        for fault in 0..3 {
            let mut invalid = token.clone();
            match fault {
                0 => invalid.asset_key = "another-label".into(),
                1 => {
                    if let Asset::ClassicToken { decimals, .. } = &mut invalid.claim.asset {
                        *decimals = 9;
                    }
                }
                2 => {
                    if let Asset::ClassicToken { mint, .. } = &mut invalid.claim.asset {
                        *mint = bs58::encode([93u8; 32]).into_string();
                    }
                }
                _ => unreachable!(),
            }
            assert!(value.destination_for(&invalid).is_err());
            assert!(value.validate_inventory(&[invalid]).is_err());
        }
    }
    #[test]
    fn issued_pending_sources_remain_pending_and_are_not_valid_target_treasuries() {
        let mut value = plan();
        let mut pending = financial(source(value.source.clone(), 0));
        if let SourceMembership::Financial { publication, .. } = &mut pending.membership {
            *publication = FinancialPublication::Pending;
        }
        pending.validate_movement_source().unwrap(); // Read-only governed source declaration.
        assert!(matches!(
            pending.membership,
            SourceMembership::Financial {
                publication: FinancialPublication::Pending,
                ..
            }
        ));
        if let SourceMembership::Financial { publication, .. } =
            &mut value.destinations[0].treasury.membership
        {
            *publication = FinancialPublication::Pending;
        }
        assert!(value.validate_shape().is_err());
    }

    #[test]
    fn chunk_transport_is_bounded_contiguous_and_does_not_erase_unpublished_entries() {
        let mut value = plan();
        let entries: Vec<_> = (0..33)
            .map(|index| source(value.source.clone(), index))
            .collect();
        value.allocated_high_water = 33;
        value.inventory_fingerprint = inventory_fingerprint(&value.source, 33, &entries).unwrap();
        let chunk = InventoryChunk {
            business_fingerprint: value.business_fingerprint().unwrap(),
            start_index: 0,
            entries: entries[..32].to_vec(),
        };
        chunk.validate(&value).unwrap();
        let tail = InventoryChunk {
            business_fingerprint: chunk.business_fingerprint.clone(),
            start_index: 32,
            entries: entries[32..].to_vec(),
        };
        tail.validate(&value).unwrap();
        assert_ne!(
            chunk.identity(&value).unwrap(),
            tail.identity(&value).unwrap()
        );
        value.validate_inventory(&entries).unwrap();
        let mut invalid = chunk.clone();
        invalid.entries.push(entries[32].clone());
        assert!(invalid.validate(&value).is_err());
        invalid = chunk.clone();
        invalid.start_index = 1;
        assert!(invalid.validate(&value).is_err());
        invalid = chunk;
        invalid.entries.clear();
        assert!(invalid.validate(&value).is_err());
        let mut renewed = value.clone();
        renewed.authorization_id = Uuid::new_v4();
        renewed.expires_at += 10;
        tail.validate(&renewed).unwrap(); // Same business; W must still authorize the fresh context.
    }

    #[test]
    fn renewal_does_not_replenish_fees_or_change_retained_asset_budgets() {
        let original = plan();
        let mut changed = original.clone();
        changed.total_fee_budget_lamports += 1;
        assert_ne!(
            original.business_fingerprint().unwrap(),
            changed.business_fingerprint().unwrap()
        );
        changed = original.clone();
        changed.retained_classic_rent_lamports += 1;
        assert_ne!(
            original.business_fingerprint().unwrap(),
            changed.business_fingerprint().unwrap()
        );
        changed = original;
        changed.total_fee_budget_lamports = 0;
        assert!(changed.validate_shape().is_err());
    }
}
