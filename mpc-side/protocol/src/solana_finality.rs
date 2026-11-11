//! Public verification of an already W-accepted signed wire. These contracts do
//! not authorize signing, release a hold, settle a ledger or infer NoSignature.
//! Plan/view/Ready validation checks content and time. Runtime must independently
//! authenticate Life, both own queries, both pinned W replies and each outer
//! current-party report; shape validation never establishes those authorities.
use crate::{
    dkg::{hex, PARTIES},
    hd::fingerprint,
    sign::{decode_hex, public_package},
    solana_intent::{Generation, ValidationPolicy},
    solana_provisioning::Root,
    witness::{hash, hash_text, Binding, ExecutionStatus, Phase, QueryReply, Signed},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const VERSION: u16 = 1;
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;
pub const MAX_READY_BYTES: usize = 256 * 1024;
pub const PLAN_DOMAIN: &str = "WITNESS_SOLANA_FINALITY_PLAN_V1";
pub const REPORT_DOMAIN: &str = "WITNESS_SOLANA_FINALITY_READY_V1";
fn digest(v: &str) -> bool {
    hash_text(v) && v != "00".repeat(32)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalityPlan {
    pub version: u16,
    pub observation_id: Uuid,
    pub witness_anchor: Uuid,
    pub root: Root,
    pub observing_generation: Generation,
    pub observing_node_keys: BTreeMap<String, String>,
    pub expected_revision: u64,
    pub execution_id: Uuid,
    pub binding_fingerprint: String,
    pub signature_hex: String,
    pub expires_at: u64,
}
impl FinalityPlan {
    pub fn validate_shape(&self) -> Result<()> {
        self.root.validate()?;
        let ids = [
            self.observation_id,
            self.witness_anchor,
            self.execution_id,
            self.root.dkg.keyset_id,
            self.root.dkg.session_id,
            self.root.dkg.execution_id,
        ];
        ensure!(
            self.version == VERSION
                && ids.iter().all(|v| !v.is_nil())
                && ids[1..].iter().all(|old| *old != self.observation_id)
                && digest(&self.binding_fingerprint)
                && self.expires_at > 0
                && self.observing_node_keys.len() == 3
                && PARTIES
                    .iter()
                    .all(|p| self.observing_node_keys.get(*p).is_some_and(|k| digest(k)))
                && self
                    .observing_node_keys
                    .values()
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 3
                && !self.observing_generation.ceremony_id.is_nil()
                && digest(&self.observing_generation.public_key_package_sha256),
            "exact source finality context required"
        );
        let signature = decode_hex(&self.signature_hex).context("original signature encoding")?;
        ensure!(
            signature.len() == 64 && hex(&signature) == self.signature_hex,
            "canonical original signature required"
        );
        if self.observing_generation.epoch == 0 {
            ensure!(
                self.observing_generation.ceremony_id == self.root.dkg.execution_id
                    && self.observing_generation.public_key_package_sha256
                        == hash(&self.root.public_key_package),
                "exact original observing generation required"
            );
        }
        Ok(())
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            now < self.expires_at && self.expires_at - now <= 300,
            "fresh Life finality plan required"
        );
        Ok(())
    }
    pub fn validate_view(&self, view: &QueryReply) -> Result<()> {
        self.validate_shape()?;
        public_package(&view.root.public_key_package, &self.root.group_public_key)?;
        ensure!(
            hash(&view.root.public_key_package)
                == self.observing_generation.public_key_package_sha256,
            "current public observing package must match the signed generation"
        );
        let execution = view
            .execution
            .as_ref()
            .context("original accepted execution required")?;
        ensure!(
            !view.abandoned
                && view.query.anchor_id == self.witness_anchor
                && view.query.root_identity == self.root.identity()?
                && view.query.execution_id == Some(self.execution_id)
                && view.query.candidate_claim.is_none()
                && view.root.original == self.root
                && view.root.phase == Phase::Frozen
                && view.root.prepared.is_none()
                && view.root.generation == self.observing_generation
                && view.root.node_keys == self.observing_node_keys
                && view.root.revision == self.expected_revision
                && view.refresh.is_none()
                && view.replacement.is_none()
                && execution.finality.is_none()
                && execution.status == ExecutionStatus::SignedPending
                && execution.binding_fingerprint == self.binding_fingerprint
                && execution.signature.as_deref() == Some(&self.signature_hex),
            "exact Frozen current source and original SignedPending wire required"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalityRequest {
    pub authorization: Signed<FinalityPlan>,
    pub binding: Binding,
    pub signing_public_key_package: Vec<u8>,
}
impl FinalityRequest {
    pub fn plan(&self) -> &FinalityPlan {
        &self.authorization.value
    }
    /// Historical CONTENT verification, not fresh private authorization. The
    /// actual W proof must independently establish prior admission of this exact
    /// binding/signature. Archived intent/CA expiry never creates a new permit.
    pub fn validate_archived_wire(&self) -> Result<Vec<u8>> {
        ensure!(
            serde_json::to_vec(&serde_json::to_value(self)?)?.len() <= MAX_REQUEST_BYTES,
            "bounded public finality request required"
        );
        let plan = self.plan();
        plan.validate_shape()?;
        self.authorization.signature_bytes()?;
        ensure!(
            digest(&self.authorization.key_id),
            "explicit Life identity required"
        );
        let i = &self.binding.authorized.intent;
        ensure!(
            i.claim.root == plan.root
                && i.crypto_execution_id == plan.execution_id
                && self.binding.identity()? == plan.binding_fingerprint,
            "original accepted binding required"
        );
        self.binding
            .authorized
            .intent
            .custody_message(&self.binding.authorized.payload_hex)?;
        let payload = decode_hex(&self.binding.authorized.payload_hex)
            .context("original payload encoding")?;
        // Reuse the unchanged complete wire verifier at its original admission
        // interval solely for content consistency. This is not a live clock.
        i.validate_shape_and_wire(
            &payload,
            &self.signing_public_key_package,
            i.issued_at,
            &ValidationPolicy {
                genesis_hash: i.claim.root.genesis_hash.clone(),
                version: i.policy_version,
                max_fee_lamports: i.expected_fee_lamports,
                max_rent_lamports: i.expected_rent_lamports,
                max_lifetime_seconds: 300,
            },
        )?;
        let package = public_package(
            &self.signing_public_key_package,
            &plan.root.group_public_key,
        )?;
        let signature =
            frost_ed25519::Signature::deserialize(&decode_hex(&plan.signature_hex).unwrap())?;
        package.verifying_key().verify(&payload, &signature)?;
        let mut wire = vec![1];
        wire.extend_from_slice(&signature.serialize()?);
        wire.extend_from_slice(&payload);
        ensure!(
            wire.len() <= 1232,
            "bounded original one-signature wire required"
        );
        Ok(wire)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum FinalityOutcome {
    Succeeded {},
    Failed { error_fingerprint: String },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalityFact {
    pub transaction_slot: u64,
    pub wire_fingerprint: String,
    pub message_fingerprint: String,
    pub metadata_fingerprint: String,
    pub fee_lamports: u64,
    pub outcome: FinalityOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalityObservation {
    pub fact: FinalityFact,
    /// Different node reads need not observe the same finalized RPC bank.
    pub status_context_slot: u64,
}
impl FinalityObservation {
    pub fn verify_rpc(
        request: &FinalityRequest,
        statuses: &Value,
        transaction: &Value,
        rpc_genesis: &str,
    ) -> Result<Self> {
        ensure!(
            rpc_genesis == request.plan().root.genesis_hash,
            "independently pinned RPC genesis mismatch"
        );
        let wire = request.validate_archived_wire()?;
        let status_context_slot = statuses["context"]["slot"]
            .as_u64()
            .context("finalized status context missing")?;
        let values = statuses["value"]
            .as_array()
            .context("signature status list missing")?;
        ensure!(
            values.len() == 1,
            "exact one original signature status required"
        );
        let status = &values[0];
        let slot = status["slot"].as_u64().context("signature slot missing")?;
        ensure!(
            slot > 0
                && status_context_slot >= slot
                && status["confirmationStatus"] == "finalized"
                && status.get("confirmations").is_some_and(Value::is_null)
                && status.get("err").is_some()
                && transaction["slot"].as_u64() == Some(slot),
            "actual consistent finalized status/transaction required"
        );
        let encoded = transaction["transaction"]
            .as_array()
            .context("canonical encoded transaction missing")?;
        ensure!(
            encoded.len() == 2 && encoded[1] == "base64",
            "canonical base64 transaction required"
        );
        let encoded_text = encoded[0]
            .as_str()
            .context("encoded original wire missing")?;
        ensure!(
            encoded_text.len() <= 1644,
            "bounded base64 transaction required"
        );
        let raw = base64::decode(encoded_text).context("original transaction base64")?;
        ensure!(
            base64::encode(&raw) == encoded_text,
            "canonical transaction base64 required"
        );
        ensure!(
            raw == wire,
            "RPC wire differs from original W-accepted signature/message"
        );
        let meta = &transaction["meta"];
        ensure!(
            meta.is_object() && meta.get("err") == status.get("err"),
            "finalized outcome mismatch"
        );
        let fee = meta["fee"]
            .as_u64()
            .context("integer finalized fee missing")?;
        ensure!(
            fee == request.binding.authorized.intent.expected_fee_lamports,
            "actual fee differs from original quote"
        );
        let before = meta["preBalances"]
            .as_array()
            .context("original pre-balances missing")?;
        let after = meta["postBalances"]
            .as_array()
            .context("original post-balances missing")?;
        ensure!(
            !before.is_empty()
                && before.len() == after.len()
                && before.len() <= 256
                && before.iter().chain(after.iter()).all(|v| v.is_u64()),
            "bounded integer balance metadata required"
        );
        // The unchanged archive verifier has already validated the complete
        // canonical legacy message, including its account table/flags.
        let message = &wire[65..];
        let mut at = 3usize;
        let mut account_count = 0usize;
        for shift in [0, 7, 14] {
            let b = *message.get(at).context("account count missing")?;
            at += 1;
            account_count |= usize::from(b & 127) << shift;
            if b & 128 == 0 {
                break;
            }
        }
        ensure!(
            before.len() == account_count,
            "balance metadata differs from original account table"
        );
        if !meta["err"].is_null() {
            for (index, (pre, post)) in before.iter().zip(after).enumerate() {
                let expected = if index == 0 {
                    pre.as_u64()
                        .unwrap()
                        .checked_sub(fee)
                        .context("failed payer fee underflow")?
                } else {
                    pre.as_u64().unwrap()
                };
                ensure!(post.as_u64()==Some(expected),"failed finalized wire must roll back all principal/rent except original payer fee");
            }
            ensure!(
                meta["preTokenBalances"] == meta["postTokenBalances"],
                "failed finalized token principal must be unchanged"
            );
        }
        for name in ["preTokenBalances", "postTokenBalances", "innerInstructions"] {
            ensure!(
                meta.get(name)
                    .is_some_and(|v| v.is_null() || v.as_array().is_some_and(|a| a.len() <= 256)),
                "bounded explicit original optional metadata required"
            );
        }
        if let crate::solana_intent::Action::NativeTransfer {
            destination,
            amount,
        } = &request.binding.authorized.intent.action
        {
            ensure!(
                meta["preTokenBalances"] == meta["postTokenBalances"]
                    && meta["innerInstructions"]
                        .as_array()
                        .is_none_or(Vec::is_empty),
                "native wire cannot alter token principal or invoke inner instructions"
            );
            let mut deltas = vec![0i128; account_count];
            deltas[0] -= i128::from(fee);
            if meta["err"].is_null() {
                let keys = &message[at..at + account_count * 32];
                let source =
                    crate::solana_seeded::key(&request.binding.authorized.intent.financial_source)?;
                let target = crate::solana_seeded::key(destination)?;
                let source_index = keys
                    .chunks_exact(32)
                    .position(|k| k == source)
                    .context("original native source missing")?;
                let target_index = keys
                    .chunks_exact(32)
                    .position(|k| k == target)
                    .context("original native recipient missing")?;
                deltas[source_index] -= i128::from(*amount);
                deltas[target_index] += i128::from(*amount);
            }
            ensure!(
                before
                    .iter()
                    .zip(after)
                    .zip(deltas)
                    .all(|((a, b), expected)| i128::from(b.as_u64().unwrap())
                        - i128::from(a.as_u64().unwrap())
                        == expected),
                "native finalized principal/fee metadata differs from original exact wire"
            );
        }
        let outcome = if meta["err"].is_null() {
            FinalityOutcome::Succeeded {}
        } else {
            ensure!(
                meta["err"].is_object() || meta["err"].is_string(),
                "invalid finalized error"
            );
            FinalityOutcome::Failed {
                error_fingerprint: fingerprint("SOLANA_FINALITY_ERROR_V1", &meta["err"])?,
            }
        };
        let normalized = json!({"err":meta["err"],"fee":fee,"preBalances":before,"postBalances":after,
            "preTokenBalances":meta["preTokenBalances"],"postTokenBalances":meta["postTokenBalances"],"innerInstructions":meta["innerInstructions"]});
        Ok(Self {
            fact: FinalityFact {
                transaction_slot: slot,
                wire_fingerprint: hash(&wire),
                message_fingerprint: request
                    .binding
                    .authorized
                    .intent
                    .message_fingerprint
                    .clone(),
                metadata_fingerprint: fingerprint("SOLANA_FINALITY_METADATA_V1", &normalized)?,
                fee_lamports: fee,
                outcome,
            },
            status_context_slot,
        })
    }
}

#[cfg(test)]
mod tests;

/// Durable public query lease. It contains no FROST nonce or private permit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalityLease {
    pub request: FinalityRequest,
    pub query: Signed<crate::witness::Query>,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl FinalityLease {
    pub fn validate_shape(&self, party: &str) -> Result<()> {
        self.request.validate_archived_wire()?;
        let plan = self.request.plan();
        plan.validate(self.issued_at)?;
        let q = &self.query.value;
        ensure!(
            PARTIES.contains(&party)
                && self.query.key_id == plan.observing_node_keys[party]
                && q.anchor_id == plan.witness_anchor
                && q.root_identity == plan.root.identity()?
                && q.execution_id == Some(plan.execution_id)
                && q.claim_reservation_id.is_none()
                && q.candidate_claim.is_none()
                && digest(&q.challenge)
                && self.issued_at.checked_add(15) == Some(self.expires_at)
                && self.expires_at <= plan.expires_at,
            "exact bounded own public finality query required"
        );
        self.query.signature_bytes()?;
        Ok(())
    }
    pub fn validate_proof(&self, proof: &QueryReply, party: &str, now: u64) -> Result<()> {
        self.validate_shape(party)?;
        self.request.plan().validate(now)?;
        ensure!(
            self.issued_at <= now
                && now < self.expires_at
                && proof.query == self.query.value
                && proof.lifecycle_key_id.as_deref() == Some(&self.request.authorization.key_id),
            "fresh own finality query echo required"
        );
        self.request.plan().validate_view(proof)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedFinality {
    pub lease: FinalityLease,
    pub initial_witness: Signed<QueryReply>,
    pub observation: FinalityObservation,
    pub final_query: Signed<crate::witness::Query>,
    pub observed_at: u64,
}
impl ObservedFinality {
    pub fn validate_shape(&self, party: &str) -> Result<()> {
        self.lease
            .validate_proof(&self.initial_witness.value, party, self.observed_at)?;
        let q = &self.final_query.value;
        let original = &self.lease.query.value;
        ensure!(
            self.final_query.key_id == self.lease.query.key_id
                && q.anchor_id == original.anchor_id
                && q.root_identity == original.root_identity
                && q.execution_id == original.execution_id
                && q.claim_reservation_id.is_none()
                && q.candidate_claim.is_none()
                && digest(&q.challenge)
                && q.challenge != original.challenge,
            "independent own post-observation query required"
        );
        self.final_query.signature_bytes()?;
        self.observation.validate_shape(&self.lease.request)
    }
}
impl FinalityObservation {
    pub fn validate_shape(&self, request: &FinalityRequest) -> Result<()> {
        let wire = request.validate_archived_wire()?;
        let f = &self.fact;
        ensure!(
            f.transaction_slot > 0
                && self.status_context_slot >= f.transaction_slot
                && f.wire_fingerprint == hash(&wire)
                && f.message_fingerprint == request.binding.authorized.intent.message_fingerprint
                && digest(&f.metadata_fingerprint)
                && f.fee_lamports == request.binding.authorized.intent.expected_fee_lamports,
            "exact terminal wire/fee/metadata reference required"
        );
        if let FinalityOutcome::Failed { error_fingerprint } = &f.outcome {
            ensure!(
                digest(error_fingerprint),
                "explicit finalized failure identity required"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalityReady {
    pub party_id: String,
    pub observed: ObservedFinality,
    pub final_witness: Signed<QueryReply>,
    pub profile_fingerprint: String,
    pub reported_at: u64,
}
impl FinalityReady {
    pub fn plan(&self) -> &FinalityPlan {
        self.observed.lease.request.plan()
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        ensure!(
            serde_json::to_vec(&serde_json::to_value(self)?)?.len() <= MAX_READY_BYTES,
            "three bounded Ready reports must fit the unchanged witness event limit"
        );
        let party = &self.party_id;
        self.observed.validate_shape(party)?;
        let lease = &self.observed.lease;
        ensure!(
            self.observed.observed_at <= self.reported_at
                && self.reported_at <= now
                && now < lease.expires_at
                && digest(&self.profile_fingerprint)
                && self.final_witness.value.query == self.observed.final_query.value
                && self.final_witness.value.lifecycle_key_id.as_deref()
                    == Some(&lease.request.authorization.key_id),
            "fresh exact post-observation source context required"
        );
        self.plan().validate(now)?;
        self.plan().validate_view(&self.final_witness.value)?;
        if let Some(pin) = self.final_witness.value.node_profiles.get(party) {
            pin.validate_shape()?;
            ensure!(
                pin.node_key_id == self.plan().observing_node_keys[party]
                    && pin.profile_sha256 == self.profile_fingerprint,
                "exact current observer profile required"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityCompletion {
    pub observation_id: Uuid,
    pub witness: Signed<QueryReply>,
}

/// Public immutable W acknowledgement, embedded in its signed query. It is not
/// settlement and never changes the old SignedPending status/signature/aliases.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalityReceipt {
    pub observation_id: Uuid,
    pub witness_anchor: Uuid,
    pub root_identity: String,
    pub execution_id: Uuid,
    pub binding_fingerprint: String,
    pub signature_hex: String,
    pub observing_generation: Generation,
    pub observing_node_keys: BTreeMap<String, String>,
    pub status_context_slots: BTreeMap<String, u64>,
    pub source_revision: u64,
    pub command_id: Uuid,
    pub sequence: u64,
    pub fact: FinalityFact,
}
