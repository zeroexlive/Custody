//! Local independent approval verification. The witness is a second boundary;
//! its permission never substitutes for the signer's own policy verification.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use wallet_mpc_protocol::{
    dkg::PARTIES,
    sign::{decode_hex, CustodyAuthorization},
    solana_intent::ValidationPolicy,
    solana_provisioning::receipt_message,
    witness::{hash_text, AuthorizedIntent},
};
use wallet_mpc_transport::{CustodyRequestVerifier, PinnedIdentity, AUTHORITY_ROLES, ROLES};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub genesis_hash: String,
    pub genesis_artifact_sha256: String,
    pub policy_version: u64,
    pub max_fee_lamports: u64,
    pub max_rent_lamports: u64,
    pub max_lifetime_seconds: u64,
    pub custody_ca: String,
    pub custody_certificate: String,
    pub policy_ca: String,
    pub policy_certificate: String,
    pub receipt_certificates: BTreeMap<String, Vec<String>>,
}
pub(super) struct Policy {
    pub limits: ValidationPolicy,
    custody: CustodyRequestVerifier,
    custody_key: PinnedIdentity,
    operator: CustodyRequestVerifier,
    operator_key: PinnedIdentity,
    receipts: BTreeMap<String, Vec<PinnedIdentity>>,
}
fn proof(
    verifier: &CustodyRequestVerifier,
    pin: &PinnedIdentity,
    msg: &[u8],
    auth: &CustodyAuthorization,
) -> Result<()> {
    let chain = auth
        .certificate_chain_der_hex
        .iter()
        .map(|s| decode_hex(s).context("certificate encoding"))
        .collect::<Result<Vec<_>>>()?;
    let sig = decode_hex(&auth.signature_der_hex).context("proof encoding")?;
    verifier.verify(msg, &chain, &sig)?;
    pin.verify(msg, &sig)
}
impl Policy {
    pub(super) fn current_claim_approval(
        &self,
        class: &str,
        approval: &wallet_mpc_protocol::solana_claim_authority::CurrentClaimApproval,
        lifecycle: &PinnedIdentity,
        time: u64,
        live: bool,
    ) -> Result<()> {
        ensure!(
            approval.statement.root.wallet_class == class,
            "current Claim approval requires exact custody class"
        );
        approval.validate_live(time)?;
        wallet_mpc_protocol::solana_claim_authority::verify_authority(
            &approval.authority,
            &approval.statement.root,
            &lifecycle.key_id,
            |message, signature| lifecycle.verify(message, signature),
            |der, role, expected, message, signature| {
                wallet_mpc_transport::verify_bound_public_identity(
                    der, role, &ROLES, expected, message, signature,
                )
            },
        )?;
        let message = approval.message()?;
        if live {
            proof(
                &self.custody,
                &self.custody_key,
                &message,
                &approval.custody_authorization,
            )
        } else {
            self.custody_key.verify(
                &message,
                &decode_hex(&approval.custody_authorization.signature_der_hex)
                    .context("archival current Claim Custody signature")?,
            )
        }
    }

    pub(super) fn migration_approvals(
        &self,
        approvals: &wallet_mpc_protocol::solana_profile_migration::MigrationApprovals,
        lifecycle: &PinnedIdentity,
        live: bool,
    ) -> Result<()> {
        use wallet_mpc_protocol::solana_profile_migration::APPROVAL_DOMAIN;
        approvals.validate_shape()?;
        ensure!(
            approvals.custody.key_id == self.custody_key.key_id
                && approvals.policy.key_id == self.operator_key.key_id
                && approvals.lifecycle.key_id == lifecycle.key_id,
            "original independent current authority keys and exact new Life required"
        );
        for (pin, signed) in [
            (&self.custody_key, &approvals.custody),
            (&self.operator_key, &approvals.policy),
            (lifecycle, &approvals.lifecycle),
        ] {
            pin.verify(
                &signed.signing_message(APPROVAL_DOMAIN)?,
                &signed.signature_bytes()?,
            )?;
        }
        if live {
            proof(
                &self.custody,
                &self.custody_key,
                &approvals.custody.signing_message(APPROVAL_DOMAIN)?,
                &CustodyAuthorization {
                    certificate_chain_der_hex: approvals.custody_certificate_chain_der_hex.clone(),
                    signature_der_hex: approvals.custody.signature.clone(),
                },
            )?;
            proof(
                &self.operator,
                &self.operator_key,
                &approvals.policy.signing_message(APPROVAL_DOMAIN)?,
                &CustodyAuthorization {
                    certificate_chain_der_hex: approvals.policy_certificate_chain_der_hex.clone(),
                    signature_der_hex: approvals.policy.signature.clone(),
                },
            )?;
        }
        Ok(())
    }
    pub(super) fn approval_key_ids(&self) -> [&str; 2] {
        [&self.custody_key.key_id, &self.operator_key.key_id]
    }
    pub fn new(class: &str, c: &PolicyConfig) -> Result<Self> {
        ensure!(
            ["HOT", "WARM", "COLD"].contains(&class)
                && hash_text(&c.genesis_artifact_sha256)
                && wallet_mpc_protocol::solana_seeded::key(&c.genesis_hash)? != [0; 32]
                && !["5eykt4Us", "EtWTRABZ", "4uhcVJyU"]
                    .iter()
                    .any(|v| c.genesis_hash.starts_with(v))
                && c.policy_version > 0
                && c.max_fee_lamports > 0
                && c.max_lifetime_seconds > 0
                && c.max_lifetime_seconds <= 300,
            "isolated protected policy required"
        );
        let custody_key = PinnedIdentity::new(&c.custody_certificate, "custody", &ROLES)?;
        let role = format!("policy-{}", class.to_lowercase());
        let operator_key = PinnedIdentity::new(&c.policy_certificate, &role, &AUTHORITY_ROLES)?;
        ensure!(
            custody_key.key_id != operator_key.key_id,
            "independent business approval required"
        );
        ensure!(
            c.receipt_certificates.len() == 3,
            "original receipt roster required"
        );
        let mut seen = BTreeSet::from([custody_key.key_id.clone(), operator_key.key_id.clone()]);
        let mut receipts = BTreeMap::new();
        for p in PARTIES {
            let mut ring = vec![];
            for path in c
                .receipt_certificates
                .get(p)
                .context("missing original party pins")?
            {
                let pin = PinnedIdentity::new(path, p, &ROLES)?;
                ensure!(
                    seen.insert(pin.key_id.clone()),
                    "receipt/authority identity sharing"
                );
                ring.push(pin);
            }
            ensure!(!ring.is_empty(), "empty original receipt keyring");
            receipts.insert(p.into(), ring);
        }
        Ok(Self {
            limits: ValidationPolicy {
                genesis_hash: c.genesis_hash.clone(),
                version: c.policy_version,
                max_fee_lamports: c.max_fee_lamports,
                max_rent_lamports: c.max_rent_lamports,
                max_lifetime_seconds: c.max_lifetime_seconds,
            },
            custody: CustodyRequestVerifier::for_role(&c.custody_ca, "custody", &ROLES)?,
            custody_key,
            operator: CustodyRequestVerifier::for_role(&c.policy_ca, &role, &AUTHORITY_ROLES)?,
            operator_key,
            receipts,
        })
    }
    pub fn verify_root(
        &self,
        evidence: &wallet_mpc_protocol::solana_provisioning::Evidence<
            wallet_mpc_protocol::solana_provisioning::Root,
        >,
    ) -> Result<()> {
        evidence.validate()?;
        evidence.statement.validate()?;
        for (report, party) in evidence.participant_agreement.iter().zip(PARTIES) {
            let message = receipt_message("root", &evidence.statement, party)?;
            let signature =
                decode_hex(&report.signer_signature).context("root receipt encoding")?;
            ensure!(
                self.receipts[party]
                    .iter()
                    .any(|pin| pin.verify(&message, &signature).is_ok()),
                "original Root receipt unverifiable against archival pins"
            );
        }
        Ok(())
    }
    pub fn verify(
        &self,
        class: &str,
        a: &AuthorizedIntent,
        package: &[u8],
        now: u64,
        lifecycle: Option<&PinnedIdentity>,
    ) -> Result<()> {
        ensure!(
            a.intent.claim.root.wallet_class == class,
            "wrong protected custody class"
        );
        a.validate_shape(package, now, &self.limits)?;
        if a.claim_evidence.authority.is_some() {
            let life =
                lifecycle.context("current Claim evidence requires explicit Lifecycle pin")?;
            wallet_mpc_protocol::solana_claim_authority::verify_evidence(
                &a.claim_evidence,
                &life.key_id,
                |message, signature| life.verify(message, signature),
                |der, role, expected, message, signature| {
                    wallet_mpc_transport::verify_bound_public_identity(
                        der, role, &ROLES, expected, message, signature,
                    )
                },
            )?;
        } else {
            for (report, p) in a.claim_evidence.participant_agreement.iter().zip(PARTIES) {
                let message = receipt_message("claim", &a.intent.claim, p)?;
                let sig = decode_hex(&report.signer_signature).context("claim receipt encoding")?;
                ensure!(
                    self.receipts[p]
                        .iter()
                        .any(|pin| pin.verify(&message, &sig).is_ok()),
                    "original receipt unverifiable"
                );
            }
        }
        proof(
            &self.custody,
            &self.custody_key,
            &a.intent.custody_message(&a.payload_hex)?,
            &a.custody_authorization,
        )?;
        proof(
            &self.operator,
            &self.operator_key,
            &a.operator_message()?,
            &a.operator_authorization,
        )
    }
}
