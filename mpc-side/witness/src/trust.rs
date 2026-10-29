use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::PARTIES,
    sign::{decode_hex, CustodyAuthorization},
    solana_intent::ValidationPolicy,
    solana_provisioning::{receipt_message, Claim, Evidence, Root},
    solana_seeded::key,
    witness::{hash_text, AuthorizedIntent, Signed},
};
use wallet_mpc_transport::{
    CustodyRequestVerifier, PinnedIdentity, ReceiptIdentity, TlsConfig, AUTHORITY_ROLES, ROLES,
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
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
    pub node_certificates: BTreeMap<String, Vec<String>>,
    pub receipt_certificates: BTreeMap<String, Vec<String>>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    pub environment: String,
    pub anchor_id: Uuid,
    pub directory: PathBuf,
    pub bind: std::net::SocketAddr,
    pub tls_ca: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub archived_witness_certificates: Vec<String>,
    pub lifecycle_certificate: String,
    pub profiles: BTreeMap<String, ProfileConfig>,
}
impl AuthorityConfig {
    pub fn tls(&self) -> TlsConfig {
        TlsConfig {
            ca: self.tls_ca.clone(),
            cert: self.tls_cert.clone(),
            key: self.tls_key.clone(),
        }
    }
}
pub(crate) struct ProfileTrust {
    pub policy: ValidationPolicy,
    custody: CustodyRequestVerifier,
    custody_key: PinnedIdentity,
    operator: CustodyRequestVerifier,
    operator_key: PinnedIdentity,
    pub nodes: BTreeMap<String, BTreeMap<String, PinnedIdentity>>,
    receipts: BTreeMap<String, BTreeMap<String, PinnedIdentity>>,
}
pub(crate) struct Trust {
    pub identity: ReceiptIdentity,
    pub witness_keys: BTreeMap<String, PinnedIdentity>,
    pub lifecycle: PinnedIdentity,
    pub profiles: BTreeMap<String, ProfileTrust>,
}

fn keyring(
    paths: &BTreeMap<String, Vec<String>>,
) -> Result<BTreeMap<String, BTreeMap<String, PinnedIdentity>>> {
    ensure!(
        paths.len() == 3
            && PARTIES
                .iter()
                .all(|p| paths.get(*p).is_some_and(|v| !v.is_empty())),
        "all party certificate pins required"
    );
    let mut seen = BTreeSet::new();
    let mut result = BTreeMap::new();
    for party in PARTIES {
        let mut ring = BTreeMap::new();
        for path in &paths[party] {
            let pin = PinnedIdentity::new(path, party, &AUTHORITY_ROLES)?;
            ensure!(
                seen.insert(pin.key_id.clone()),
                "node keys must be independent and unambiguous"
            );
            ring.insert(pin.key_id.clone(), pin);
        }
        result.insert(party.to_owned(), ring);
    }
    Ok(result)
}
fn proof(
    verifier: &CustodyRequestVerifier,
    pin: &PinnedIdentity,
    message: &[u8],
    auth: &CustodyAuthorization,
) -> Result<()> {
    let chain = auth
        .certificate_chain_der_hex
        .iter()
        .map(|v| decode_hex(v).context("certificate encoding"))
        .collect::<Result<Vec<_>>>()?;
    let signature = decode_hex(&auth.signature_der_hex).context("proof signature encoding")?;
    verifier.verify(message, &chain, &signature)?;
    // Live authority uses only the current explicitly pinned key, never an
    // archival receipt key just because its certificate remains time-valid.
    pin.verify(message, &signature)
}
impl Trust {
    pub fn new(config: &AuthorityConfig) -> Result<Self> {
        ensure!(
            config.environment == "isolated-development-v1"
                && !config.anchor_id.is_nil()
                && config.directory.is_absolute()
                && config.bind.ip().is_loopback(),
            "isolated explicit authority configuration required"
        );
        let identity = ReceiptIdentity::for_role(&config.tls(), "witness", &AUTHORITY_ROLES)?;
        let lifecycle =
            PinnedIdentity::new(&config.lifecycle_certificate, "lifecycle", &AUTHORITY_ROLES)?;
        let mut witness_keys = BTreeMap::new();
        for path in
            std::iter::once(&config.tls_cert).chain(config.archived_witness_certificates.iter())
        {
            let p = PinnedIdentity::new(path, "witness", &AUTHORITY_ROLES)?;
            ensure!(
                witness_keys.insert(p.key_id.clone(), p).is_none(),
                "duplicate witness archive identity"
            );
        }
        ensure!(
            witness_keys.contains_key(&identity.key_id()),
            "current witness pin required"
        );
        let mut separate = BTreeMap::<String, String>::new();
        for id in witness_keys.keys() {
            separate.insert(id.clone(), "witness".into());
        }
        ensure!(
            separate
                .insert(lifecycle.key_id.clone(), "lifecycle".into())
                .is_none(),
            "separate lifecycle authority required"
        );
        let mut profiles = BTreeMap::new();
        ensure!(
            !config.profiles.is_empty(),
            "protected class policy required"
        );
        for (class, p) in &config.profiles {
            ensure!(
                ["HOT", "WARM", "COLD"].contains(&class.as_str())
                    && key(&p.genesis_hash)? != [0; 32]
                    && !["5eykt4Us", "EtWTRABZ", "4uhcVJyU"]
                        .iter()
                        .any(|prefix| p.genesis_hash.starts_with(prefix))
                    && hash_text(&p.genesis_artifact_sha256)
                    && p.policy_version > 0
                    && p.max_fee_lamports > 0
                    && p.max_lifetime_seconds > 0
                    && p.max_lifetime_seconds <= 300,
                "reviewed isolated class/network policy required"
            );
            let custody_key = PinnedIdentity::new(&p.custody_certificate, "custody", &ROLES)?;
            let policy_role = format!("policy-{}", class.to_lowercase());
            let operator_key =
                PinnedIdentity::new(&p.policy_certificate, &policy_role, &AUTHORITY_ROLES)?;
            for (id, name) in [
                (&custody_key.key_id, "custody"),
                (&operator_key.key_id, "policy"),
            ] {
                ensure!(
                    separate
                        .insert(id.clone(), format!("{class}:{name}"))
                        .is_none(),
                    "independent class/approval credentials required"
                );
            }
            let nodes = keyring(&p.node_certificates)?;
            let receipts = keyring(&p.receipt_certificates)?;
            for (party, ring) in nodes.iter().chain(receipts.iter()) {
                for id in ring.keys() {
                    let owner = format!("{class}:{party}");
                    ensure!(
                        separate.get(id).is_none_or(|old| old == &owner),
                        "class/node/authority keys cannot be shared"
                    );
                    separate.insert(id.clone(), owner);
                }
            }
            profiles.insert(
                class.clone(),
                ProfileTrust {
                    policy: ValidationPolicy {
                        genesis_hash: p.genesis_hash.clone(),
                        version: p.policy_version,
                        max_fee_lamports: p.max_fee_lamports,
                        max_rent_lamports: p.max_rent_lamports,
                        max_lifetime_seconds: p.max_lifetime_seconds,
                    },
                    custody: CustodyRequestVerifier::for_role(&p.custody_ca, "custody", &ROLES)?,
                    custody_key,
                    operator: CustodyRequestVerifier::for_role(
                        &p.policy_ca,
                        &policy_role,
                        &AUTHORITY_ROLES,
                    )?,
                    operator_key,
                    nodes,
                    receipts,
                },
            );
        }
        Ok(Self {
            identity,
            witness_keys,
            lifecycle,
            profiles,
        })
    }
    pub fn profile(&self, class: &str) -> Result<&ProfileTrust> {
        self.profiles.get(class).context("class policy unavailable")
    }
    pub fn check_signed<T: serde::Serialize>(
        &self,
        signed: &Signed<T>,
        domain: &str,
        pin: &PinnedIdentity,
    ) -> Result<()> {
        ensure!(
            signed.key_id == pin.key_id,
            "current authority identity mismatch"
        );
        pin.verify(&signed.signing_message(domain)?, &signed.signature_bytes()?)
    }
    pub fn check_node<T: serde::Serialize>(
        &self,
        class: &str,
        party: &str,
        signed: &Signed<T>,
        domain: &str,
    ) -> Result<()> {
        let p = self
            .profile(class)?
            .nodes
            .get(party)
            .and_then(|ring| ring.get(&signed.key_id))
            .context("untrusted class node key")?;
        self.check_signed(signed, domain, p)
    }
    pub fn root_evidence(&self, e: &Evidence<Root>) -> Result<()> {
        e.statement.validate()?;
        e.validate()?;
        let p = self.profile(&e.statement.wallet_class)?;
        ensure!(
            p.policy.genesis_hash == e.statement.genesis_hash,
            "root network differs from protected pin"
        );
        for (r, party) in e.participant_agreement.iter().zip(PARTIES) {
            let sig = decode_hex(&r.signer_signature).context("root receipt signature")?;
            let msg = receipt_message("root", &e.statement, party)?;
            ensure!(
                p.receipts[party]
                    .values()
                    .any(|pin| pin.verify(&msg, &sig).is_ok()),
                "unverifiable original root receipt"
            );
        }
        Ok(())
    }
    pub fn claim_evidence(&self, e: &Evidence<Claim>) -> Result<()> {
        e.statement.validate()?;
        e.validate()?;
        let p = self.profile(&e.statement.root.wallet_class)?;
        for (r, party) in e.participant_agreement.iter().zip(PARTIES) {
            let sig = decode_hex(&r.signer_signature).context("claim receipt signature")?;
            let msg = receipt_message("claim", &e.statement, party)?;
            ensure!(
                p.receipts[party]
                    .values()
                    .any(|pin| pin.verify(&msg, &sig).is_ok()),
                "unverifiable original claim receipt"
            );
        }
        Ok(())
    }
    pub fn authorized(&self, a: &AuthorizedIntent, package: &[u8], now: u64) -> Result<()> {
        let p = self.profile(&a.intent.claim.root.wallet_class)?;
        a.validate_shape(package, now, &p.policy)?;
        self.claim_evidence(&a.claim_evidence)?;
        proof(
            &p.custody,
            &p.custody_key,
            &a.intent.custody_message(&a.payload_hex)?,
            &a.custody_authorization,
        )?;
        proof(
            &p.operator,
            &p.operator_key,
            &a.operator_message()?,
            &a.operator_authorization,
        )
    }
    pub fn sign<T: serde::Serialize>(&self, domain: &str, value: T) -> Result<Signed<T>> {
        let key_id = self.identity.key_id();
        let signature = self
            .identity
            .sign(&Signed::unsigned_message(domain, &key_id, &value)?)?;
        Ok(Signed {
            key_id,
            value,
            signature: wallet_mpc_protocol::dkg::hex(&signature),
        })
    }
}
