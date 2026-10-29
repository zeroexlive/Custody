//! Typed original intent and wire checks only. No signer route, receipt trust,
//! epoch freshness, business approval or nonce/signing permission is granted.
use crate::{
    dkg::hex,
    sign::public_package,
    solana_provisioning::{Asset, Claim},
    solana_seeded::{key, validate, Operation},
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const VERSION: &str = "solana_seeded_intent_v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Generation {
    /// Requested signing-generation reference, independent of Root's DKG marker.
    /// A matching reference/package does not establish epoch freshness.
    pub epoch: u64,
    pub ceremony_id: Uuid,
    pub public_key_package_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BusinessOperation {
    Withdrawal,
    Sweep,
    Provision,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Action {
    NativeTransfer {
        destination: String,
        amount: u64,
    },
    CreateClassicToken {
        rent_lamports: u64,
    },
    ClassicTransfer {
        destination_owner: String,
        amount: u64,
        create_ata: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub version: String,
    pub claim: Claim,
    pub generation: Generation,
    pub session_id: Uuid,
    pub crypto_execution_id: Uuid,
    pub attempt_id: u64,
    pub operation_id: u64,
    pub operation_type: BusinessOperation,
    pub asset_key: String,
    /// The customer account, distinct from the base signing/fee authority.
    pub financial_source: String,
    pub fee_payer: String,
    pub rent_payer: Option<String>,
    pub action: Action,
    pub recent_blockhash: String,
    pub last_valid_block_height: u64,
    pub policy_version: u64,
    pub expected_fee_lamports: u64,
    pub expected_rent_lamports: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub message_fingerprint: String,
}

/// Trusted local policy input, deliberately not deserializable from a request.
pub struct ValidationPolicy {
    pub genesis_hash: String,
    pub version: u64,
    pub max_fee_lamports: u64,
    pub max_rent_lamports: u64,
    pub max_lifetime_seconds: u64,
}

impl Intent {
    /// Structural checks do not establish caller or current-generation authority.
    /// Future signer code must FIRST authenticate/reopen its original local
    /// approval and obtain a fresh independent witness/round permit before nonce
    /// work. Passing this pure verifier cannot substitute for those checks.
    pub fn validate_shape_and_wire(
        &self,
        raw: &[u8],
        active_public_package: &[u8],
        now: u64,
        policy: &ValidationPolicy,
    ) -> Result<()> {
        self.claim.validate()?;
        let root = &self.claim.root;
        let tenant = Uuid::parse_str(&root.ownership_scope)?;
        let owner = self
            .claim
            .owner_ref
            .strip_prefix("p1:")
            .ok_or_else(|| anyhow::anyhow!("canonical principal owner reference required"))?;
        let principal = Uuid::parse_str(owner)?;
        let base = bs58::encode(root.base()?).into_string();
        ensure!(
            !tenant.is_nil()
                && tenant.to_string() == root.ownership_scope
                && !principal.is_nil()
                && principal.to_string() == owner
                && self.version == VERSION
                && !self.session_id.is_nil()
                && !self.crypto_execution_id.is_nil()
                && self.session_id != self.crypto_execution_id
                && self.crypto_execution_id != root.dkg.execution_id
                && self.session_id != root.dkg.session_id
                && self.attempt_id > 0
                && self.operation_id > 0
                && !self.asset_key.is_empty()
                && self.asset_key.trim() == self.asset_key
                && self.asset_key.chars().count() <= 32
                && !self.asset_key.chars().any(char::is_control)
                && self.financial_source == self.claim.address()?
                && self.fee_payer == base,
            "original tenant/principal/operation/source identity mismatch"
        );
        ensure!(active_public_package.len() <= 4096, "active package bounds");
        public_package(active_public_package, &root.group_public_key)?;
        ensure!(
            !self.generation.ceremony_id.is_nil()
                && self.generation.public_key_package_sha256
                    == hex(&Sha256::digest(active_public_package))
                && (self.generation.epoch != 0
                    || (active_public_package == root.public_key_package
                        && self.generation.ceremony_id == root.dkg.execution_id))
                && (self.generation.epoch == 0
                    || self.generation.ceremony_id != root.dkg.execution_id),
            "active generation/package reference mismatch"
        );
        ensure!(
            policy.version > 0
                && self.policy_version == policy.version
                && root.genesis_hash == policy.genesis_hash
                && key(&self.recent_blockhash)? != [0; 32]
                && self.last_valid_block_height > 0
                && self.issued_at <= now
                && now < self.expires_at
                && self.issued_at < self.expires_at
                && self.expires_at - self.issued_at <= policy.max_lifetime_seconds
                && self.expected_fee_lamports > 0
                && self.expected_fee_lamports <= policy.max_fee_lamports
                && self.expected_rent_lamports <= policy.max_rent_lamports
                && self.message_fingerprint == hex(&Sha256::digest(raw)),
            "network/time/policy/message binding mismatch"
        );
        let op = match (&self.action, &self.claim.asset) {
            (
                Action::NativeTransfer {
                    destination,
                    amount,
                },
                Asset::Native,
            ) => {
                ensure!(
                    self.operation_type != BusinessOperation::Provision
                        && self.rent_payer.is_none()
                        && self.expected_rent_lamports == 0,
                    "native spending/rent shape"
                );
                Operation::Native {
                    destination: key(destination)?,
                    amount: *amount,
                }
            }
            (Action::CreateClassicToken { rent_lamports }, Asset::ClassicToken { mint, .. }) => {
                ensure!(
                    self.operation_type == BusinessOperation::Provision
                        && self.rent_payer.as_ref() == Some(&base)
                        && *rent_lamports == self.expected_rent_lamports,
                    "original token provisioning/rent shape"
                );
                Operation::CreateToken {
                    mint: key(mint)?,
                    rent: *rent_lamports,
                }
            }
            (
                Action::ClassicTransfer {
                    destination_owner,
                    amount,
                    create_ata,
                },
                Asset::ClassicToken { mint, decimals },
            ) => {
                ensure!(
                    self.operation_type != BusinessOperation::Provision
                        && ((!create_ata
                            && self.rent_payer.is_none()
                            && self.expected_rent_lamports == 0)
                            || (*create_ata && self.rent_payer.as_ref() == Some(&base))),
                    "original token spending/rent shape"
                );
                Operation::Token {
                    mint: key(mint)?,
                    destination_owner: key(destination_owner)?,
                    amount: *amount,
                    decimals: *decimals,
                    create_ata: *create_ata,
                }
            }
            _ => anyhow::bail!("original claim asset/action mismatch"),
        };
        validate(
            raw,
            root.base()?,
            self.claim.index,
            key(&self.recent_blockhash)?,
            &op,
        )
    }

    /// Exact original custody machine proof input. Signature verification is a
    /// separate boundary; this method neither signs nor authorizes an operation.
    pub fn custody_message(&self, payload_hex: &str) -> Result<Vec<u8>> {
        ensure!(
            !payload_hex.is_empty() && payload_hex.len() <= 2 * (1232 - 65),
            "original encoded payload bounds"
        );
        let raw = crate::sign::decode_hex(payload_hex)
            .ok_or_else(|| anyhow::anyhow!("invalid original payload encoding"))?;
        ensure!(
            !raw.is_empty()
                && raw.len() + 65 <= 1232
                && hex(&raw) == payload_hex
                && self.message_fingerprint == hex(&Sha256::digest(&raw)),
            "canonical original payload/fingerprint required"
        );
        let mut result = b"Wallet-MPC/CUSTODY_SOLANA_SEEDED_INTENT_V1\0".to_vec();
        result.extend(serde_json::to_vec(&serde_json::json!({
            "intent": self, "payload_hex": payload_hex,
        }))?);
        Ok(result)
    }
}
