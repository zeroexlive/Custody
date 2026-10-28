//! Public contracts for the independent generation/replay authority. Neither a
//! serialized value nor an epoch certificate is a private-operation permit.
use crate::{
    dkg::{hex, PARTIES},
    hd::fingerprint,
    sign::{decode_hex, CustodyAuthorization},
    solana_intent::{Action, BusinessOperation, Generation, Intent, ValidationPolicy},
    solana_provisioning::{Claim, Evidence, Root},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub fn message<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>> {
    ensure!(
        domain.starts_with("WITNESS_") || domain == "OPERATOR_SEEDED_SPEND_V1",
        "authority domain"
    );
    Ok([
        format!("Wallet-MPC/{domain}\0").as_bytes(),
        &serde_json::to_vec(&serde_json::to_value(value)?)?,
    ]
    .concat())
}
pub fn hash(value: &[u8]) -> String {
    hex(&Sha256::digest(value))
}
pub fn hash_text(value: &str) -> bool {
    decode_hex(value).is_some_and(|v| v.len() == 32 && hex(&v) == value)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub key_id: String,
    pub value: T,
    pub signature: String,
}
impl<T: Serialize> Signed<T> {
    pub fn unsigned_message(domain: &str, key_id: &str, value: &T) -> Result<Vec<u8>> {
        ensure!(hash_text(key_id), "identity key fingerprint");
        message(domain, &serde_json::json!({"key_id":key_id,"value":value}))
    }
    pub fn signing_message(&self, domain: &str) -> Result<Vec<u8>> {
        Self::unsigned_message(domain, &self.key_id, &self.value)
    }
    pub fn signature_bytes(&self) -> Result<Vec<u8>> {
        let bytes = decode_hex(&self.signature).context("signature encoding")?;
        ensure!(
            (8..=80).contains(&bytes.len()) && hex(&bytes) == self.signature,
            "signature bounds"
        );
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedIntent {
    pub intent: Intent,
    pub payload_hex: String,
    pub claim_evidence: Evidence<Claim>,
    pub custody_authorization: CustodyAuthorization,
    pub operator_authorization: CustodyAuthorization,
}
impl AuthorizedIntent {
    pub fn operator_message(&self) -> Result<Vec<u8>> {
        // Distinct from the online custody machine domain, with the same exact
        // full typed payload. Independent approval cannot be inferred from mTLS.
        self.intent.custody_message(&self.payload_hex)?;
        message(
            "OPERATOR_SEEDED_SPEND_V1",
            &serde_json::json!({
                "intent":self.intent,"payload_hex":self.payload_hex,
            }),
        )
    }
    pub fn identity(&self) -> Result<String> {
        fingerprint("WITNESS_INTENT_V1", &(&self.intent, &self.payload_hex))
    }
    /// Global logical operation across roots, attempts and signing generations.
    pub fn operation_key(&self) -> Result<String> {
        fingerprint(
            "WITNESS_LOGICAL_OPERATION_V1",
            &(
                &self.intent.claim.root.ownership_scope,
                &self.intent.operation_type,
                self.intent.operation_id,
            ),
        )
    }
    pub fn business_fingerprint(&self) -> Result<String> {
        let i = &self.intent;
        fingerprint(
            "WITNESS_BUSINESS_INTENT_V1",
            &serde_json::json!({
                "tenant": i.claim.root.ownership_scope, "owner":i.claim.owner_ref,
                "chain":i.claim.root.chain_id,"genesis":i.claim.root.genesis_hash,
                "class":i.claim.root.wallet_class,"asset":i.claim.asset,"asset_key":i.asset_key,
            "original_root":i.claim.root.identity()?,"reservation":i.claim.reservation_id,
            "financial_source":i.financial_source,
                "operation_type":i.operation_type,"operation_id":i.operation_id,"action":i.action,
            }),
        )
    }
    pub fn attempt_key(&self) -> Result<String> {
        fingerprint(
            "WITNESS_ATTEMPT_V1",
            &(
                &self.intent.claim.root.ownership_scope,
                self.intent.attempt_id,
            ),
        )
    }
    /// Agave deduplicates the exact message even when FROST produces another
    /// signature. One such chain execution cannot back two financial operations.
    pub fn wire_key(&self) -> Result<String> {
        fingerprint(
            "WITNESS_SOLANA_WIRE_V1",
            &(
                &self.intent.claim.root.genesis_hash,
                &self.intent.message_fingerprint,
            ),
        )
    }
    pub fn validate_shape(
        &self,
        package: &[u8],
        now: u64,
        policy: &ValidationPolicy,
    ) -> Result<Vec<u8>> {
        self.claim_evidence.validate()?;
        ensure!(
            self.claim_evidence.statement == self.intent.claim,
            "original claim agreement"
        );
        self.intent.custody_message(&self.payload_hex)?;
        let bytes = decode_hex(&self.payload_hex).context("payload encoding")?;
        self.intent
            .validate_shape_and_wire(&bytes, package, now, policy)?;
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub authorized: AuthorizedIntent,
    pub selected_signers: Vec<String>,
}
impl Binding {
    pub fn identity(&self) -> Result<String> {
        ensure!(
            self.selected_signers.len() == 2
                && self.selected_signers[0] < self.selected_signers[1]
                && self
                    .selected_signers
                    .iter()
                    .all(|p| PARTIES.contains(&p.as_str())),
            "threshold pair"
        );
        fingerprint(
            "WITNESS_EXECUTION_V1",
            &(self.authorized.identity()?, &self.selected_signers),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PermitRequest {
    pub anchor_id: Uuid,
    pub binding: Binding,
    pub party_id: String,
    pub round: u16,
    pub challenge: String,
    pub expires_at: u64,
    pub signing_package: Option<Vec<u8>>,
}
impl PermitRequest {
    pub fn validate(&self, now: u64) -> Result<()> {
        self.binding.identity()?;
        ensure!(
            !self.anchor_id.is_nil()
                && self.binding.selected_signers.contains(&self.party_id)
                && [1, 2].contains(&self.round)
                && hash_text(&self.challenge)
                && self.challenge != "00".repeat(32)
                && now < self.expires_at
                && self.expires_at - now <= 15
                && ((self.round == 1 && self.signing_package.is_none())
                    || (self.round == 2
                        && self
                            .signing_package
                            .as_ref()
                            .is_some_and(|p| !p.is_empty() && p.len() <= 8192))),
            "invalid fresh party/round challenge"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    pub request: PermitRequest,
    pub sequence: u64,
    pub root_revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicRound {
    pub anchor_id: Uuid,
    pub execution_id: Uuid,
    pub binding_fingerprint: String,
    pub party_id: String,
    pub round: u16,
    pub commitments: Option<Vec<u8>>,
    pub signature_share: Option<Vec<u8>>,
    pub signing_package: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerationReady {
    pub root_identity: String,
    pub previous_generation: Generation,
    pub generation: Generation,
    pub public_key_package: Vec<u8>,
    pub party_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum CommandAction {
    Enroll {
        evidence: Box<Evidence<Root>>,
        node_keys: BTreeMap<String, String>,
    },
    RegisterClaim {
        evidence: Box<Evidence<Claim>>,
    },
    Freeze,
    CloseNoSignature {
        execution_id: Uuid,
    },
    Prepare {
        ready: Vec<Signed<GenerationReady>>,
        node_keys: BTreeMap<String, String>,
    },
    Activate,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub anchor_id: Uuid,
    pub request_id: Uuid,
    pub root_identity: String,
    pub expected_revision: u64,
    pub expires_at: u64,
    pub action: CommandAction,
}
impl Command {
    pub fn validate(&self, now: u64) -> Result<()> {
        ensure!(
            !self.anchor_id.is_nil()
                && !self.request_id.is_nil()
                && hash_text(&self.root_identity)
                && now < self.expires_at
                && self.expires_at - now <= 300,
            "lifecycle command bounds"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub anchor_id: Uuid,
    pub root_identity: String,
    pub challenge: String,
    pub execution_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_reservation_id: Option<Uuid>,
}

/// Immutable financial intent. A native/token transfer cannot be relabelled as
/// account creation; preserve this distinction when adding reconciliation.
pub fn provisioning(binding: &Binding) -> bool {
    binding.authorized.intent.operation_type == BusinessOperation::Provision
        && matches!(
            binding.authorized.intent.action,
            Action::CreateClassicToken { .. }
        )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    Active,
    Frozen,
    Prepared,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionStatus {
    Open,
    NoSignature,
    SignedPending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootView {
    pub original: Root,
    pub revision: u64,
    pub phase: Phase,
    pub generation: Generation,
    pub public_key_package: Vec<u8>,
    pub node_keys: std::collections::BTreeMap<String, String>,
    pub prepared: Option<Generation>,
    pub next_claim_index: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionView {
    pub binding_fingerprint: String,
    pub status: ExecutionStatus,
    pub signature: Option<String>,
    pub reports: std::collections::BTreeMap<String, Signed<PublicRound>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryReply {
    pub query: Query,
    pub sequence: u64,
    pub root: RootView,
    pub execution: Option<ExecutionView>,
    pub abandoned: bool,
    pub claim: Option<Evidence<Claim>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub anchor_id: Uuid,
    pub sequence: u64,
    pub value_fingerprint: String,
}
