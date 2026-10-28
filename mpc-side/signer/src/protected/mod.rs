//! Explicit protected deployment. Its independent public execution anchor and
//! mandatory profile survive restoration of any private-share backup.
mod journal;
mod network;
mod policy;
use crate::{dkg::DkgService, solana_provisioning, SignerConfig};
use anyhow::{ensure, Context, Result};
use frost_ed25519 as frost;
pub use policy::PolicyConfig;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::{identifier, PARTIES},
    sign::decode_hex,
    witness::{hash, Acknowledgement, Binding, Permit, PermitRequest, PublicRound, Signed},
};
use wallet_mpc_transport::{
    solana_rpc::SolanaRpc, AuthorityClient, PinnedIdentity, ReceiptIdentity, TlsConfig,
    AUTHORITY_ROLES,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub environment: String,
    pub class: String,
    pub anchor_directory: PathBuf,
    pub witness_anchor: Uuid,
    pub bind: SocketAddr,
    pub signer: SignerConfig,
    pub tls: TlsConfig,
    pub peer_targets: Vec<(String, SocketAddr, String)>,
    pub witness_tls: TlsConfig,
    pub witness_address: SocketAddr,
    pub witness_server_name: String,
    pub witness_certificate: String,
    pub rpc_address: SocketAddr,
    pub policy: PolicyConfig,
}
impl Profile {
    pub fn load(path: &Path) -> Result<(Self, String)> {
        let raw = fs::read(path)?;
        let p: Self = serde_json::from_slice(&raw)?;
        ensure!(
            p.environment == "isolated-development-protected-v1"
                && ["HOT", "WARM", "COLD"].contains(&p.class.as_str())
                && !p.witness_anchor.is_nil()
                && p.anchor_directory.is_absolute()
                && p.signer.storage_directory.is_absolute()
                && p.bind.ip().is_loopback()
                && p.witness_address.ip().is_loopback()
                && p.peer_targets.iter().all(|(_, a, _)| a.ip().is_loopback()),
            "isolated explicit protected profile required"
        );
        p.signer.validate()?;
        ensure!(
            p.signer.certificate_identity == format!("spiffe://wallet-mpc/{}", p.signer.party_id),
            "protected certificate identity mismatch"
        );
        ensure!(
            p.signer.supported_algorithms == ["FROST_ED25519"],
            "protected Solana deployment must be dedicated to FROST"
        );
        fs::create_dir_all(&p.signer.storage_directory)?;
        fs::create_dir_all(&p.anchor_directory)?;
        let storage = fs::canonicalize(&p.signer.storage_directory)?;
        let anchor = fs::canonicalize(&p.anchor_directory)?;
        ensure!(
            !anchor.starts_with(&storage) && !storage.starts_with(&anchor),
            "public protected anchor must be outside private-share backups"
        );
        let mut materials = BTreeMap::new();
        for f in [
            path.to_path_buf(),
            p.signer.wrapping_key_path.clone(),
            PathBuf::from(&p.tls.key),
            PathBuf::from(&p.witness_tls.key),
        ] {
            let canonical = fs::canonicalize(&f)?;
            ensure!(
                !canonical.starts_with(&storage) && !canonical.starts_with(&anchor),
                "protected credentials/profile must be outside both backup journals"
            );
        }
        for f in [
            &p.tls.ca,
            &p.tls.cert,
            &p.witness_tls.ca,
            &p.witness_tls.cert,
            &p.witness_certificate,
            &p.policy.custody_ca,
            &p.policy.custody_certificate,
            &p.policy.policy_ca,
            &p.policy.policy_certificate,
        ]
        .into_iter()
        .chain(p.policy.receipt_certificates.values().flatten())
        {
            materials.insert(f.clone(), hash(&fs::read(f)?));
        }
        let fingerprint = hash(&serde_json::to_vec(
            &serde_json::json!({"profile":p,"public_trust_material":materials}),
        )?);
        Ok((p, fingerprint))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub binding: Binding,
    pub round: u16,
    pub signing_package: Option<Vec<u8>>,
}
struct Active {
    key: frost::keys::KeyPackage,
    nonces: frost::round1::SigningNonces,
    commitments: frost::round1::SigningCommitments,
    binding: String,
}
struct Local {
    journal: journal::Journal,
    active: BTreeMap<Uuid, Active>,
}
pub struct Service {
    profile: Profile,
    policy: policy::Policy,
    identity: ReceiptIdentity,
    own: PinnedIdentity,
    witness: PinnedIdentity,
    client: Option<AuthorityClient>,
    rpc: SolanaRpc,
    dkg: Arc<DkgService>,
    provisioning: Arc<solana_provisioning::Service>,
    local: Mutex<Local>,
}
pub fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
impl Service {
    pub fn open(
        profile: Profile,
        fingerprint: String,
        dkg: Arc<DkgService>,
        provisioning: Arc<solana_provisioning::Service>,
        initialize: bool,
    ) -> Result<Arc<Self>> {
        let party = &profile.signer.party_id;
        let identity = ReceiptIdentity::new(&profile.tls, party)?;
        let own = PinnedIdentity::new(&profile.tls.cert, party, &AUTHORITY_ROLES)?;
        let witness =
            PinnedIdentity::new(&profile.witness_certificate, "witness", &AUTHORITY_ROLES)?;
        let outgoing = PinnedIdentity::new(&profile.witness_tls.cert, party, &AUTHORITY_ROLES)?;
        ensure!(
            own.key_id == outgoing.key_id && witness.key_id != own.key_id,
            "separate witness and exact protected node identity required"
        );
        let policy = policy::Policy::new(&profile.class, &profile.policy)?;
        // COLD only exports end-to-end signed challenges for manual courier;
        // this process never creates a witness network client in that class.
        let client = if profile.class == "COLD" {
            None
        } else {
            Some(AuthorityClient::new(
                &profile.witness_tls,
                party,
                profile.witness_address,
                profile.witness_server_name.clone(),
                &profile.witness_certificate,
            )?)
        };
        let journal = journal::Journal::open(
            &profile.anchor_directory,
            fingerprint,
            &identity,
            &own,
            &witness,
            party,
            initialize,
        )?;
        let rpc = SolanaRpc::new(profile.rpc_address)?;
        Ok(Arc::new(Self {
            profile,
            policy,
            identity,
            own,
            witness,
            client,
            rpc,
            dkg,
            provisioning,
            local: Mutex::new(Local {
                journal,
                active: BTreeMap::new(),
            }),
        }))
    }
    fn append(&self, local: &mut Local, change: journal::Change) -> Result<()> {
        local.journal.append(
            change,
            &self.identity,
            &self.own,
            &self.witness,
            &self.profile.signer.party_id,
        )
    }
    fn package<'a>(&self, b: &'a Binding) -> Result<&'a [u8]> {
        // Later refreshed generations are loaded from separate immutable
        // encrypted generation records. Never reinterpret the original share.
        ensure!(
            b.authorized.intent.generation.epoch == 0,
            "refreshed generation loader is not integrated"
        );
        Ok(&b.authorized.intent.claim.root.public_key_package)
    }
    fn valid_control(&self, c: &Control) -> Result<()> {
        c.binding.identity()?;
        ensure!(
            c.binding
                .selected_signers
                .contains(&self.profile.signer.party_id)
                && [1, 2].contains(&c.round)
                && ((c.round == 1 && c.signing_package.is_none())
                    || (c.round == 2
                        && c.signing_package
                            .as_ref()
                            .is_some_and(|p| !p.is_empty() && p.len() <= 8192))),
            "original protected round control required"
        );
        Ok(())
    }
    pub async fn recover(&self, c: &Control) -> Result<Option<Signed<PublicRound>>> {
        self.valid_control(c)?;
        let local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "protected history uncertain");
        let key = journal::slot(c.binding.authorized.intent.crypto_execution_id, c.round);
        if let Some(r) = local.journal.records.reports.get(&key) {
            let request = &local.journal.records.requests[&key].value;
            ensure!(
                request.binding.identity()? == c.binding.identity()?
                    && request.signing_package == c.signing_package,
                "original public recovery binding mismatch"
            );
            return Ok(Some(r.clone()));
        }
        Ok(None)
    }
    pub async fn challenge(&self, c: Control) -> Result<Signed<PermitRequest>> {
        self.valid_control(&c)?;
        let package = self.package(&c.binding)?;
        self.provisioning
            .require_approved(&c.binding.authorized.intent.claim)
            .await?;
        self.policy
            .verify(&self.profile.class, &c.binding.authorized, package, now()?)?;
        let mut local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "protected history uncertain");
        let id = c.binding.authorized.intent.crypto_execution_id;
        let key = journal::slot(id, c.round);
        if let Some(original) = local.journal.records.requests.get(&key) {
            ensure!(
                original.value.binding.identity()? == c.binding.identity()?
                    && original.value.signing_package == c.signing_package,
                "original challenge cannot change"
            );
            original.value.validate(now()?)?;
            return Ok(original.clone());
        }
        if c.round == 1 {
            ensure!(
                local.active.len() < 32,
                "too many protected active executions"
            );
        }
        if c.round == 2 {
            let active = local
                .active
                .get(&id)
                .context("private nonces unavailable; retain unresolved original execution")?;
            self.check_signing_package(&c.binding, c.signing_package.as_ref().unwrap(), active)?;
        }
        let mut challenge = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut challenge);
        let request = journal::sign(
            &self.identity,
            "WITNESS_PERMIT_REQUEST_V1",
            PermitRequest {
                anchor_id: self.profile.witness_anchor,
                binding: c.binding,
                party_id: self.profile.signer.party_id.clone(),
                round: c.round,
                challenge: wallet_mpc_protocol::dkg::hex(&challenge),
                expires_at: now()?.checked_add(15).context("time overflow")?,
                signing_package: c.signing_package,
            },
        )?;
        request.value.validate(now()?)?;
        self.append(
            &mut local,
            journal::Change::Request {
                request: Box::new(request.clone()),
            },
        )?;
        Ok(request)
    }
    fn check_signing_package(
        &self,
        b: &Binding,
        bytes: &[u8],
        active: &Active,
    ) -> Result<frost::SigningPackage> {
        let package = frost::SigningPackage::deserialize(bytes)?;
        ensure!(
            package.serialize()? == bytes
                && package.message()
                    == &decode_hex(&b.authorized.payload_hex).context("payload")?
                && package.signing_commitments().len() == 2
                && active.binding == b.identity()?,
            "original canonical signing package required"
        );
        for p in PARTIES {
            ensure!(
                package
                    .signing_commitments()
                    .contains_key(&identifier(p).context("fixed party")?)
                    == b.selected_signers.iter().any(|s| s == p),
                "signing pair disagreement"
            );
        }
        ensure!(
            package.signing_commitment(active.key.identifier()) == Some(active.commitments),
            "original local nonce commitment mismatch"
        );
        Ok(package)
    }
    pub async fn apply(&self, permit: Signed<Permit>) -> Result<Signed<PublicRound>> {
        journal::verify(&self.witness, "WITNESS_PERMIT_V1", &permit)?;
        let request = &permit.value.request;
        request.validate(now()?)?;
        ensure!(
            request.anchor_id == self.profile.witness_anchor
                && request.party_id == self.profile.signer.party_id,
            "original witness/party mismatch"
        );
        let b = &request.binding;
        let package = self.package(b)?;
        let mut local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "protected history uncertain");
        let id = b.authorized.intent.crypto_execution_id;
        let key = journal::slot(id, request.round);
        ensure!(
            local
                .journal
                .records
                .requests
                .get(&key)
                .is_some_and(|r| r.value == *request),
            "witness response does not answer original signer challenge"
        );
        if let Some(report) = local.journal.records.reports.get(&key) {
            return Ok(report.clone());
        }
        ensure!(
            !local.journal.records.consumed.contains_key(&key),
            "private permission already consumed; recover original public outcome only"
        );
        if request.round == 1 {
            // Several admitted challenges may race while the witness RPC is
            // awaited. Enforce the limit again under the private-work lock.
            ensure!(
                local.active.len() < 32,
                "protected active execution capacity reached"
            );
        }
        self.provisioning
            .require_approved(&b.authorized.intent.claim)
            .await?;
        self.policy
            .verify(&self.profile.class, &b.authorized, package, now()?)?;
        let payload = decode_hex(&b.authorized.payload_hex).context("payload encoding")?;
        network::verify(&self.rpc, &b.authorized.intent, &payload).await?;
        let key_package = if request.round == 1 {
            Some(
                self.dkg
                    .original_seeded_key(&b.authorized.intent.claim.root)
                    .await?,
            )
        } else {
            None
        };
        let signing_package = if request.round == 2 {
            Some(self.check_signing_package(
                b,
                request.signing_package.as_ref().context("R2 package")?,
                local.active.get(&id).context("private nonces lost")?,
            )?)
        } else {
            None
        };
        self.append(
            &mut local,
            journal::Change::Consume {
                permit: Box::new(permit.clone()),
            },
        )?;
        // No awaited operation or disk write may occur between this final time/
        // intent check and the synchronous upstream private operation.
        let time = now()?;
        request.validate(time)?;
        b.authorized
            .validate_shape(package, time, &self.policy.limits)?;
        let mut active = None;
        let (commitments, signature_share) = if let Some(key) = key_package {
            let (nonces, commitments) =
                frost::round1::commit(key.signing_share(), &mut rand_core::OsRng);
            let bytes = commitments.serialize()?;
            active = Some(Active {
                key,
                nonces,
                commitments,
                binding: b.identity()?,
            });
            (Some(bytes), None)
        } else {
            let active = local
                .active
                .remove(&id)
                .context("private nonces unavailable")?;
            let share = frost::round2::sign(
                signing_package.as_ref().unwrap(),
                &active.nonces,
                &active.key,
            )?;
            (None, Some(share.serialize()))
        };
        let report = journal::sign(
            &self.identity,
            "WITNESS_PUBLIC_ROUND_V1",
            PublicRound {
                anchor_id: request.anchor_id,
                execution_id: id,
                binding_fingerprint: b.identity()?,
                party_id: self.profile.signer.party_id.clone(),
                round: request.round,
                commitments,
                signature_share,
                signing_package: request.signing_package.clone(),
            },
        )?;
        self.append(
            &mut local,
            journal::Change::Result {
                report: Box::new(report.clone()),
            },
        )?;
        if let Some(active) = active {
            local.active.insert(id, active);
        }
        Ok(report)
    }
    pub async fn automatic(&self, c: Control) -> Result<Signed<PublicRound>> {
        let client = self
            .client
            .as_ref()
            .context("COLD requires an explicit signed challenge/manual courier round trip")?;
        let report = if let Some(report) = self.recover(&c).await? {
            report
        } else {
            let request = self.challenge(c).await?;
            let response = client
                .request("/v1/witness/permit", serde_json::to_vec(&request)?)
                .await?;
            let permit: Signed<Permit> = serde_json::from_slice(&response)?;
            self.apply(permit).await?
        };
        // Sending public results also checks the active witness TLS key before
        // the body leaves the process. Result delivery is safely repeatable.
        let response = client
            .request("/v1/witness/record", serde_json::to_vec(&report)?)
            .await?;
        let ack: Signed<Acknowledgement> = serde_json::from_slice(&response)?;
        journal::verify(&self.witness, "WITNESS_ACK_V1", &ack)?;
        ensure!(
            ack.value.anchor_id == self.profile.witness_anchor
                && ack.value.value_fingerprint
                    == hash(&report.signing_message("WITNESS_PUBLIC_ROUND_V1")?),
            "original public result acknowledgement mismatch"
        );
        Ok(report)
    }
}
