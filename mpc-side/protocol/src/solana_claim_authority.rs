//! Public Claim approvals under an explicitly prepared current receipt roster.
//!
//! Shape checks do not authenticate a Lifecycle signature, certificate, fresh
//! witness response, committed generation or durable registration. Callers must
//! verify those independently before accepting any receipt or creating a wallet.

use crate::{
    dkg::{hex, PARTIES},
    hd::fingerprint,
    sign::{decode_hex, public_package, CustodyAuthorization},
    solana_intent::Generation,
    solana_provisioning::{Claim, Root},
    witness::{
        hash, hash_text, Command, CommandAction, GenerationReady, Phase, Query, QueryReply, Signed,
    },
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: u16 = 1;

pub type PreparedClaimRoster<'a> = (&'a [Signed<GenerationReady>], &'a BTreeMap<String, String>);

/// The original public Prepare command authorizes exactly these three keys.
/// Public DER leaves are checked against those key IDs, never trusted as CAs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimAuthority {
    pub version: u16,
    pub prepare: Box<Signed<Command>>,
    pub node_certificates_der_hex: BTreeMap<String, String>,
}

impl ClaimAuthority {
    pub fn prepared(&self) -> Result<PreparedClaimRoster<'_>> {
        match &self.prepare.value.action {
            CommandAction::Prepare { ready, node_keys } => Ok((ready, node_keys)),
            _ => anyhow::bail!("original Lifecycle Prepare required for current Claim authority"),
        }
    }

    pub fn generation(&self) -> Result<&Generation> {
        self.prepared()?
            .0
            .first()
            .map(|ready| &ready.value.generation)
            .context("all-three current generation readiness required")
    }

    pub fn validate_shape(&self, root: &Root) -> Result<()> {
        root.validate()?;
        let command = &self.prepare.value;
        ensure!(
            self.version == VERSION
                && !command.anchor_id.is_nil()
                && !command.request_id.is_nil()
                && command.expires_at > 0
                && command.root_identity == root.identity()?
                && hash_text(&self.prepare.key_id),
            "exact original Root and archival Lifecycle command required"
        );
        self.prepare.signature_bytes()?;
        let (ready, keys) = self.prepared()?;
        ensure!(
            ready.len() == 3 && keys.len() == 3 && self.node_certificates_der_hex.len() == 3,
            "three distinct exact current receipt identities required"
        );
        let mut seen = BTreeSet::from([self.prepare.key_id.as_str()]);
        let first = &ready[0].value;
        ensure!(
            first.generation.epoch > 0
                && first.previous_generation.epoch.checked_add(1) == Some(first.generation.epoch)
                && !first.generation.ceremony_id.is_nil()
                && first.generation.ceremony_id != first.previous_generation.ceremony_id
                && first.generation.ceremony_id != root.dkg.execution_id
                && first.generation.ceremony_id != root.dkg.session_id
                && hash_text(&first.previous_generation.public_key_package_sha256)
                && !first.previous_generation.ceremony_id.is_nil()
                && first.public_key_package.len() <= 4096
                && first.generation.public_key_package_sha256 == hash(&first.public_key_package),
            "exact prepared next generation and public package required"
        );
        public_package(&first.public_key_package, &root.group_public_key)?;
        ensure!(
            first.previous_generation.epoch != 0
                || (first.previous_generation.ceremony_id == root.dkg.execution_id
                    && first.previous_generation.public_key_package_sha256
                        == hash(&root.public_key_package)),
            "original-generation predecessor must retain the original DKG marker/package"
        );
        for (report, party) in ready.iter().zip(PARTIES) {
            let key = keys.get(party).context("missing current receipt party")?;
            let certificate = self
                .node_certificates_der_hex
                .get(party)
                .context("missing current receipt public certificate")?;
            let bytes = decode_hex(certificate).context("public certificate encoding")?;
            ensure!(
                hash_text(key)
                    && seen.insert(key.as_str())
                    && report.key_id == *key
                    && report.value.party_id == party
                    && report.value.root_identity == command.root_identity
                    && report.value.previous_generation == first.previous_generation
                    && report.value.generation == first.generation
                    && report.value.public_key_package == first.public_key_package
                    && (128..=16384).contains(&bytes.len())
                    && hex(&bytes) == *certificate,
                "current receipt key/readiness/certificate disagreement"
            );
            report.signature_bytes()?;
        }
        Ok(())
    }

    pub fn identity(&self, root: &Root) -> Result<String> {
        self.validate_shape(root)?;
        fingerprint("SOLANA_CURRENT_CLAIM_AUTHORITY_V1", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CurrentClaimApproval {
    pub statement: Claim,
    pub authority: ClaimAuthority,
    pub issued_at: u64,
    pub expires_at: u64,
    pub custody_authorization: CustodyAuthorization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<Box<crate::solana_rotation::RotationApprovals>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimQueryLease {
    pub approval: CurrentClaimApproval,
    pub query: Signed<Query>,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl ClaimQueryLease {
    pub fn validate_shape(&self, party: &str) -> Result<()> {
        ensure!(
            PARTIES.contains(&party),
            "current Claim query party required"
        );
        self.approval.validate_live(self.issued_at)?;
        let claim = &self.approval.statement;
        let authority = &self.approval.authority;
        let (_, keys) = authority.prepared()?;
        let query = &self.query.value;
        ensure!(
            self.expires_at.checked_sub(self.issued_at) == Some(15)
                && query.anchor_id == authority.prepare.value.anchor_id
                && query.root_identity == claim.root.identity()?
                && query.claim_reservation_id == Some(claim.reservation_id)
                && query.execution_id.is_none()
                && query.candidate_claim.as_deref() == Some(claim)
                && hash_text(&query.challenge)
                && query.challenge != "00".repeat(32)
                && self.query.key_id == keys[party],
            "exact independently durable current Claim challenge required"
        );
        self.query.signature_bytes()?;
        Ok(())
    }

    pub fn validate_new_report(&self, reply: &QueryReply, party: &str, now: u64) -> Result<()> {
        self.validate_shape(party)?;
        self.approval.validate_live(now)?;
        let authority = &self.approval.authority;
        let (ready, keys) = authority.prepared()?;
        let claim = &self.approval.statement;
        let availability = reply
            .claim_availability
            .as_ref()
            .context("original alias occupancy proof required")?;
        let phase_authorized = if let Some(approvals) = &self.approval.rotation {
            let plan = approvals.plan();
            let source_identity = plan.source.identity()?;
            let target_identity = plan.target.identity()?;
            let business_fingerprint = plan.business_fingerprint()?;
            reply.root.phase == Phase::Frozen
                && reply.root.rotation.as_ref().is_some_and(|view| {
                    view.status == crate::solana_rotation::RotationStatus::Sealed
                        && view.rotation_id == plan.rotation_id
                        && view.source_identity == source_identity
                        && view.target_identity == target_identity
                        && view.business_fingerprint == business_fingerprint
                        && view.allocated_high_water == plan.allocated_high_water
                        && view.next_index == plan.allocated_high_water
                        && view.inventory_fingerprint == plan.inventory_fingerprint
                })
        } else {
            reply.root.phase == Phase::Active
        };
        ensure!(
            self.issued_at <= now
                && now < self.expires_at
                && reply.query == self.query.value
                && reply.sequence > 0
                && reply.execution.is_none()
                && !reply.abandoned
                && reply.root.original == claim.root
                && phase_authorized
                && reply.root.prepared.is_none()
                && reply.refresh.is_none()
                && reply.replacement.is_none()
                && reply.root.generation == *authority.generation()?
                && reply.root.public_key_package == ready[0].value.public_key_package
                && reply.root.node_keys == *keys
                && reply.root.next_claim_index == claim.index
                && reply.generation_authority.as_deref() == Some(authority.prepare.as_ref())
                && reply.lifecycle_key_id.as_deref() == Some(authority.prepare.key_id.as_str())
                && reply.claim.is_none()
                && reply.claim_issuance.is_none()
                && availability.reservation_id == claim.reservation_id
                && availability.index.is_none()
                && availability.owner.is_none()
                && availability.retry.is_none(),
            "fresh Active current generation and unused original aliases required for a new report"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentClaimControl {
    pub approval: CurrentClaimApproval,
    pub witness: Option<Signed<QueryReply>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentClaimGrant {
    pub lease_challenge: String,
    pub witness: Signed<QueryReply>,
    pub report: crate::solana_provisioning::Report<Claim>,
    pub granted_at: u64,
}

impl CurrentClaimApproval {
    pub fn message(&self) -> Result<Vec<u8>> {
        let ordinary = authorization_message(
            &self.authority,
            &self.statement,
            self.issued_at,
            self.expires_at,
        )?;
        if let Some(approvals) = &self.rotation {
            approvals.validate_shape()?;
            let plan = approvals.plan();
            plan.validate(self.issued_at)?; // Archived recovery uses this original time too.
            let (_, keys) = self.authority.prepared()?;
            ensure!(
                plan.source == self.statement.root
                    && plan.source_generation == *self.authority.generation()?
                    && plan.source_node_keys == *keys
                    && self.statement.index < plan.allocated_high_water,
                "exact original source and current public rotation Claim authority required"
            );
            canonical_message(
                b"Wallet-MPC/CUSTODY_SOLANA_ROTATION_CLAIM_V1\0",
                serde_json::json!({"statement":self.statement,"authority":self.authority,
                    "issued_at":self.issued_at,"expires_at":self.expires_at,"rotation":approvals}),
            )
        } else {
            Ok(ordinary)
        }
    }

    pub fn validate_live(&self, now: u64) -> Result<()> {
        self.message()?;
        if let Some(approvals) = &self.rotation {
            approvals.plan().validate(now)?;
        }
        ensure!(
            self.issued_at <= now && now < self.expires_at,
            "current Claim Custody approval expired or not yet valid"
        );
        Ok(())
    }
}

fn canonical_message(domain: &[u8], value: serde_json::Value) -> Result<Vec<u8>> {
    Ok([domain, &serde_json::to_vec(&value)?].concat())
}

pub fn authorization_message(
    authority: &ClaimAuthority,
    claim: &Claim,
    issued_at: u64,
    expires_at: u64,
) -> Result<Vec<u8>> {
    claim.validate()?;
    authority.validate_shape(&claim.root)?;
    ensure!(
        issued_at > 0
            && expires_at
                .checked_sub(issued_at)
                .is_some_and(|ttl| (1..=300).contains(&ttl)),
        "bounded explicit current Claim Custody approval lifetime required"
    );
    canonical_message(
        b"Wallet-MPC/CUSTODY_SOLANA_CURRENT_CLAIM_V1\0",
        serde_json::json!({"statement":claim,"authority":authority,"issued_at":issued_at,"expires_at":expires_at}),
    )
}

pub fn receipt_message(authority: &ClaimAuthority, claim: &Claim, party: &str) -> Result<Vec<u8>> {
    ensure!(
        PARTIES.contains(&party),
        "exact current receipt party required"
    );
    claim.validate()?;
    authority.validate_shape(&claim.root)?;
    canonical_message(
        b"Wallet-MPC/SIGNER_SOLANA_CURRENT_CLAIM_V1\0",
        serde_json::json!({
            "statement":claim,"authority":authority,"party_id":party,"durable":true,
        }),
    )
}

/// Authenticate archival public authority through caller-owned pinned crypto.
/// Freshness, profile/source fences and W registration remain separate gates.
pub fn verify_authority<L, N>(
    authority: &ClaimAuthority,
    root: &Root,
    lifecycle_key_id: &str,
    verify_lifecycle: L,
    verify_node: N,
) -> Result<()>
where
    L: Fn(&[u8], &[u8]) -> Result<()>,
    N: Fn(&[u8], &str, &str, &[u8], &[u8]) -> Result<()>,
{
    authority.validate_shape(root)?;
    ensure!(
        authority.prepare.key_id == lifecycle_key_id,
        "independently pinned Lifecycle receipt authority required"
    );
    verify_lifecycle(
        &authority.prepare.signing_message("WITNESS_COMMAND_V1")?,
        &authority.prepare.signature_bytes()?,
    )?;
    let (ready, keys) = authority.prepared()?;
    for (report, party) in ready.iter().zip(PARTIES) {
        let der = decode_hex(&authority.node_certificates_der_hex[party])
            .context("current receipt certificate encoding")?;
        verify_node(
            &der,
            party,
            &keys[party],
            &report.signing_message("WITNESS_GENERATION_READY_V1")?,
            &report.signature_bytes()?,
        )?;
    }
    Ok(())
}

pub fn verify_evidence<L, N>(
    evidence: &crate::solana_provisioning::Evidence<Claim>,
    lifecycle_key_id: &str,
    verify_lifecycle: L,
    verify_node: N,
) -> Result<()>
where
    L: Fn(&[u8], &[u8]) -> Result<()>,
    N: Fn(&[u8], &str, &str, &[u8], &[u8]) -> Result<()>,
{
    evidence.validate_claim()?;
    let authority = evidence
        .authority
        .as_ref()
        .context("explicit current Claim authority required")?;
    verify_authority(
        authority,
        &evidence.statement.root,
        lifecycle_key_id,
        &verify_lifecycle,
        &verify_node,
    )?;
    let (_, keys) = authority.prepared()?;
    for (report, party) in evidence.participant_agreement.iter().zip(PARTIES) {
        let der = decode_hex(&authority.node_certificates_der_hex[party])
            .context("current receipt certificate encoding")?;
        let signature =
            decode_hex(&report.signer_signature).context("current Claim receipt encoding")?;
        ensure!(
            hex(&signature) == report.signer_signature,
            "canonical current Claim receipt required"
        );
        verify_node(
            &der,
            party,
            &keys[party],
            &receipt_message(authority, &evidence.statement, party)?,
            &signature,
        )?;
    }
    Ok(())
}
