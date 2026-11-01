//! Versioned financial identity and explicit irreversible Root activation.
//! These proofs never establish chain settlement or attest live ledger contents.
use crate::{
    dkg::PARTIES,
    solana_intent::{BusinessOperation, Generation, Intent},
    solana_provisioning::Root,
    witness::{hash_text, Signed},
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const VERSION: u16 = 1;
pub const MODE_DOMAIN: &str = "WITNESS_SOLANA_FINANCIAL_MODE_V1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceRole {
    CustomerDeposit,
    TenantTreasury,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialBinding {
    pub version: u16,
    pub reservation_id: Uuid,
    pub tenant_id: Uuid,
    pub reservation_owner_ref: String,
    pub source_owner_ref: String,
    pub source_role: SourceRole,
    pub operation_type: BusinessOperation,
    pub operation_id: u64,
    pub approval_id: Uuid,
    pub asset_key: String,
}
fn principal(value: &str) -> bool {
    value
        .strip_prefix("p1:")
        .and_then(|s| Uuid::parse_str(s).ok().map(|id| (s, id)))
        .is_some_and(|(s, id)| !id.is_nil() && id.to_string() == s)
}
impl FinancialBinding {
    pub fn validate(&self, intent: &Intent) -> Result<()> {
        ensure!(
            self.version == VERSION
                && !self.reservation_id.is_nil()
                && !self.approval_id.is_nil()
                && self.reservation_id != self.approval_id
                && !self.tenant_id.is_nil()
                && self.tenant_id.to_string() == intent.claim.root.ownership_scope
                && principal(&self.reservation_owner_ref)
                && principal(&self.source_owner_ref)
                && self.source_owner_ref == intent.claim.owner_ref
                && self.operation_type == intent.operation_type
                && self.operation_id == intent.operation_id
                && self.asset_key == intent.asset_key,
            "exact financial reservation, tenant, source and operation identity required"
        );
        match self.operation_type {
            BusinessOperation::Withdrawal => ensure!(
                self.source_role == SourceRole::TenantTreasury,
                "financial withdrawal requires explicitly approved tenant treasury source"
            ),
            BusinessOperation::Sweep | BusinessOperation::Provision => ensure!(
                self.reservation_owner_ref == self.source_owner_ref,
                "non-withdrawal operation cannot silently substitute another reservation owner"
            ),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialModePlan {
    pub version: u16,
    pub activation_id: Uuid,
    pub witness_anchor: Uuid,
    pub root: Root,
    pub generation: Generation,
    pub node_keys: BTreeMap<String, String>,
    pub expires_at: u64,
}
impl FinancialModePlan {
    pub fn validate_shape(&self) -> Result<()> {
        self.root.validate()?;
        ensure!(
            self.version == VERSION
                && !self.activation_id.is_nil()
                && !self.witness_anchor.is_nil()
                && self.activation_id != self.witness_anchor
                && !self.generation.ceremony_id.is_nil()
                && hash_text(&self.generation.public_key_package_sha256)
                && self.node_keys.len() == 3
                && PARTIES
                    .iter()
                    .all(|p| self.node_keys.get(*p).is_some_and(|key| hash_text(key)))
                && self.node_keys.values().collect::<BTreeSet<_>>().len() == 3
                && self.expires_at > 0,
            "explicit original Root/generation/roster financial activation required"
        );
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            now < self.expires_at && self.expires_at - now <= 300,
            "fresh independently approved financial activation required"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialModeApprovals {
    pub custody: Signed<FinancialModePlan>,
    pub policy: Signed<FinancialModePlan>,
    pub custody_certificate_chain_der_hex: Vec<String>,
    pub policy_certificate_chain_der_hex: Vec<String>,
}
impl FinancialModeApprovals {
    pub fn plan(&self) -> &FinancialModePlan {
        &self.custody.value
    }
    pub fn validate_shape(&self) -> Result<()> {
        self.plan().validate_shape()?;
        ensure!(
            self.policy.value == self.custody.value && self.policy.key_id != self.custody.key_id,
            "independent custody and policy must approve the same financial activation"
        );
        for chain in [
            &self.custody_certificate_chain_der_hex,
            &self.policy_certificate_chain_der_hex,
        ] {
            ensure!(
                !chain.is_empty()
                    && chain.len() <= 5
                    && chain.iter().all(|s| s.len() <= 16384
                        && crate::sign::decode_hex(s)
                            .is_some_and(|b| !b.is_empty() && crate::dkg::hex(&b) == *s)),
                "bounded canonical current authorization chains required"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialRootMode {
    pub version: u16,
    pub activation_id: Uuid,
    pub command_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sign::CustodyAuthorization, witness::AuthorizedIntent};
    fn intent() -> Intent {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/solana-seeded-intent-sdk.json"
        ))
        .unwrap();
        let mut value = f["cases"][0]["intent"].clone();
        value["claim"]["root"] = f["root"].clone();
        let mut i: Intent = serde_json::from_value(value).unwrap();
        i.operation_type = BusinessOperation::Withdrawal;
        i
    }
    fn binding(i: &Intent) -> FinancialBinding {
        FinancialBinding {
            version: VERSION,
            reservation_id: Uuid::new_v4(),
            tenant_id: Uuid::parse_str(&i.claim.root.ownership_scope).unwrap(),
            reservation_owner_ref: format!("p1:{}", Uuid::new_v4()),
            source_owner_ref: i.claim.owner_ref.clone(),
            source_role: SourceRole::TenantTreasury,
            operation_type: i.operation_type.clone(),
            operation_id: i.operation_id,
            approval_id: Uuid::new_v4(),
            asset_key: i.asset_key.clone(),
        }
    }
    #[test]
    fn financial_identity_distinguishes_source_owner_and_binds_stable_business() {
        let i = intent();
        let proof = CustodyAuthorization {
            certificate_chain_der_hex: vec![],
            signature_der_hex: String::new(),
        };
        let mut a = AuthorizedIntent {
            intent: i.clone(),
            payload_hex: String::new(),
            claim_evidence: crate::solana_provisioning::Evidence {
                statement: i.claim.clone(),
                participant_agreement: vec![],
            },
            custody_authorization: proof.clone(),
            operator_authorization: proof,
        };
        let original = serde_json::json!({
            "tenant":i.claim.root.ownership_scope,"owner":i.claim.owner_ref,
            "chain":i.claim.root.chain_id,"genesis":i.claim.root.genesis_hash,
            "class":i.claim.root.wallet_class,"asset":i.claim.asset,"asset_key":i.asset_key,
            "original_root":i.claim.root.identity().unwrap(),"reservation":i.claim.reservation_id,
            "financial_source":i.financial_source,"operation_type":i.operation_type,
            "operation_id":i.operation_id,"action":i.action});
        assert!(serde_json::to_value(&i).unwrap().get("financial").is_none());
        assert_eq!(
            a.business_fingerprint().unwrap(),
            crate::hd::fingerprint("WITNESS_BUSINESS_INTENT_V1", &original).unwrap()
        );
        a.intent.financial = Some(binding(&i));
        a.intent
            .financial
            .as_ref()
            .unwrap()
            .validate(&a.intent)
            .unwrap();
        assert_ne!(
            a.intent.financial.as_ref().unwrap().reservation_owner_ref,
            i.claim.owner_ref
        );
        let stable = a.business_fingerprint().unwrap();
        a.intent.session_id = Uuid::new_v4();
        a.intent.crypto_execution_id = Uuid::new_v4();
        a.intent.attempt_id += 1;
        a.intent.generation.epoch += 1;
        a.intent.generation.ceremony_id = Uuid::new_v4();
        assert_eq!(a.business_fingerprint().unwrap(), stable);
        a.intent.financial.as_mut().unwrap().approval_id = Uuid::new_v4();
        assert_ne!(a.business_fingerprint().unwrap(), stable);
    }
    #[test]
    fn even_mode_off_financial_values_cannot_mismatch_parent_identity() {
        let i = intent();
        let original = binding(&i);
        original.validate(&i).unwrap();
        for field in 0..6 {
            let mut f = original.clone();
            match field {
                0 => f.tenant_id = Uuid::new_v4(),
                1 => f.source_owner_ref = format!("p1:{}", Uuid::new_v4()),
                2 => f.operation_id += 1,
                3 => f.asset_key = "OTHER".into(),
                4 => f.reservation_owner_ref = "p1:bad".into(),
                _ => f.source_role = SourceRole::CustomerDeposit,
            }
            assert!(f.validate(&i).is_err());
        }
    }
}
