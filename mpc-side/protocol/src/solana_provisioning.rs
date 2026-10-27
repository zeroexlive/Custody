//! Original FROST-backed, operator-scoped seeded account approvals. A receipt is
//! not an on-chain SPL initialization, tenant login, or signing authorization.
use crate::{
    dkg::{hex, DkgRequest, PARTIES},
    hd::fingerprint,
    sign::{decode_hex, public_package, CustodyAuthorization},
    solana_seeded::{address, key, seed},
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const VERSION: &str = "solana_seeded_v1";

fn text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.chars().count() <= limit
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub dkg: DkgRequest,
    pub group_public_key: String,
    pub public_key_package: Vec<u8>,
    pub ownership_scope: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub purpose: String,
    pub wallet_class: String,
    pub derivation_version: String,
    /// Original DKG marker only, never a current-epoch or anti-rollback proof.
    pub generation: u64,
}
impl Root {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.dkg.is_frost()
                && self.dkg.scope == "SOLANA"
                && text(&self.ownership_scope, 64)
                && self.chain_id == "SOL"
                && key(&self.genesis_hash)? != [0; 32]
                && self.purpose == "DEPOSIT"
                && self.wallet_class == "HOT"
                && self.derivation_version == VERSION
                && self.generation == 0,
            "invalid original seeded root namespace"
        );
        ensure!(
            self.public_key_package.len() <= 4096,
            "public package bounds"
        );
        public_package(&self.public_key_package, &self.group_public_key)?;
        let bytes = decode_hex(&self.group_public_key).unwrap_or_default();
        ensure!(
            hex(&bytes) == self.group_public_key,
            "noncanonical root key"
        );
        address(&self.base()?, 0, false)?;
        Ok(())
    }
    pub fn base(&self) -> Result<[u8; 32]> {
        decode_hex(&self.group_public_key)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid original public key"))
    }
    pub fn identity(&self) -> Result<String> {
        self.validate()?;
        fingerprint("SOLANA_SEEDED_ROOT_V1", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Asset {
    Native,
    ClassicToken { mint: String, decimals: u8 },
}
impl Asset {
    pub fn token(&self) -> bool {
        matches!(self, Self::ClassicToken { .. })
    }
    pub fn validate(&self) -> Result<()> {
        if let Self::ClassicToken { mint, decimals } = self {
            ensure!(
                key(mint)? != [0; 32] && *decimals <= 18,
                "invalid classic mint"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub root: Root,
    pub reservation_id: Uuid,
    // Existing global ledger owner reference within the authenticated deployment
    // scope. This does not establish an external tenant/customer principal.
    pub owner_ref: String,
    pub idempotency_key: String,
    pub index: u64,
    pub asset: Asset,
}
impl Claim {
    pub fn validate(&self) -> Result<()> {
        self.root.validate()?;
        self.asset.validate()?;
        ensure!(
            !self.reservation_id.is_nil()
                && text(&self.owner_ref, 64)
                && text(&self.idempotency_key, 128),
            "invalid immutable account claim"
        );
        seed(self.index, self.asset.token())?;
        Ok(())
    }
    pub fn address(&self) -> Result<String> {
        self.validate()?;
        Ok(
            bs58::encode(address(&self.root.base()?, self.index, self.asset.token())?)
                .into_string(),
        )
    }
    pub fn owner_slot(&self) -> Result<String> {
        // Decimals cannot create a second namespace for the same mint.
        let mint = match &self.asset {
            Asset::Native => "SOL",
            Asset::ClassicToken { mint, .. } => mint,
        };
        fingerprint(
            "SOLANA_SEEDED_OWNER_V1",
            &(self.root.identity()?, &self.owner_ref, mint),
        )
    }
    pub fn retry_slot(&self) -> Result<String> {
        fingerprint(
            "SOLANA_SEEDED_RETRY_V1",
            &(self.root.identity()?, &self.idempotency_key),
        )
    }
}

pub fn authorization_message<T: Serialize>(kind: &str, statement: &T) -> Result<Vec<u8>> {
    let domain = match kind {
        "root" => b"Wallet-MPC/CUSTODY_SOLANA_ROOT_V1\0".as_slice(),
        "claim" => b"Wallet-MPC/CUSTODY_SOLANA_CLAIM_V1\0".as_slice(),
        _ => anyhow::bail!("invalid seeded authorization domain"),
    };
    Ok([
        domain,
        &serde_json::to_vec(&serde_json::to_value(statement)?)?,
    ]
    .concat())
}
pub fn receipt_message<T: Serialize>(kind: &str, statement: &T, party: &str) -> Result<Vec<u8>> {
    ensure!(PARTIES.contains(&party), "invalid receipt party");
    let domain = match kind {
        "root" => b"Wallet-MPC/SIGNER_SOLANA_ROOT_V1\0".as_slice(),
        "claim" => b"Wallet-MPC/SIGNER_SOLANA_CLAIM_V1\0".as_slice(),
        _ => anyhow::bail!("invalid seeded receipt domain"),
    };
    Ok([
        domain,
        &serde_json::to_vec(&serde_json::json!({
            "statement": statement, "party_id": party, "durable": true,
        }))?,
    ]
    .concat())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval<T> {
    pub statement: T,
    pub custody_authorization: CustodyAuthorization,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Report<T> {
    pub statement: T,
    pub party_id: String,
    pub durable: bool,
    pub signer_signature: String,
}

/// Transport agreement only. Custody must independently verify every detached
/// signature against operator-pinned archival signer keys before accepting it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence<T> {
    pub statement: T,
    pub participant_agreement: Vec<Report<T>>,
}
impl<T: PartialEq> Evidence<T> {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.participant_agreement.len() == 3,
            "incomplete seeded agreement"
        );
        for (report, party) in self.participant_agreement.iter().zip(PARTIES) {
            ensure!(
                report.statement == self.statement
                    && report.party_id == party
                    && report.durable
                    && decode_hex(&report.signer_signature)
                        .is_some_and(|s| (8..=80).contains(&s.len())),
                "inconsistent original seeded receipt"
            );
        }
        Ok(())
    }
}
