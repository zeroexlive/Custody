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
    pub fn verify(
        &self,
        class: &str,
        a: &AuthorizedIntent,
        package: &[u8],
        now: u64,
    ) -> Result<()> {
        ensure!(
            a.intent.claim.root.wallet_class == class,
            "wrong protected custody class"
        );
        a.validate_shape(package, now, &self.limits)?;
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
