//! Typed protected HOT signing. Public records only; no private MPC material,
//! broadcasting, lifecycle key, policy key or automatic Unknown retry. Created
//! claims durable intent, not authorization: the supplied signed W view has no
//! timestamp. Backend must own/consume its query lease, and original nodes/W
//! independently authorize every private round. Completed verifies the aggregate
//! with upstream FROST; missing public W records still require courier redelivery
//! and fresh execution reconciliation before any backend financial consumption.
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::{identifier, PARTIES},
    sign::{decode_hex, public_package},
    solana_financial::VERSION,
    solana_intent::{BusinessOperation, ValidationPolicy},
    witness::{Binding, Phase, PublicRound, QueryReply, Signed},
};
use wallet_mpc_storage::{atomic_create_secret, atomic_replace_state, confirm_parent_durability};
use wallet_mpc_transport::{PinnedIdentity, SignerClient, AUTHORITY_ROLES};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub environment: String,
    pub directory: PathBuf,
    pub witness_anchor: Uuid,
    pub witness_certificate: String,
    #[serde(default)]
    pub archived_witness_certificates: Vec<String>,
    pub node_certificates: BTreeMap<String, Vec<String>>,
    pub genesis_hash: String,
    pub policy_version: u64,
    pub max_fee_lamports: u64,
    pub max_rent_lamports: u64,
    pub max_lifetime_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub binding: Binding,
    pub witness: Signed<QueryReply>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Created,
    InProgress,
    ReconciliationRequired,
    Completed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub request: Request,
    pub status: Status,
    pub round1: BTreeMap<String, Signed<PublicRound>>,
    pub signing_package: Option<Vec<u8>>,
    pub round2: BTreeMap<String, Signed<PublicRound>>,
    pub signature_hex: Option<String>,
    pub error_code: Option<String>,
}
struct Local {
    jobs: BTreeMap<Uuid, Session>,
    poisoned: bool,
}
pub struct Service {
    config: Config,
    witness: PinnedIdentity,
    witness_archive: BTreeMap<String, PinnedIdentity>,
    nodes: BTreeMap<String, BTreeMap<String, PinnedIdentity>>,
    peers: SignerClient,
    local: Mutex<Local>,
    serial: std::sync::Mutex<()>,
    uncertain: AtomicBool,
    _lock: File,
}
fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
fn verify<T: Serialize>(pin: &PinnedIdentity, domain: &str, signed: &Signed<T>) -> Result<()> {
    ensure!(
        pin.key_id == signed.key_id,
        "exact original public signer identity required"
    );
    pin.verify(&signed.signing_message(domain)?, &signed.signature_bytes()?)
}
impl Service {
    pub fn open(config: Config, peers: SignerClient) -> Result<Arc<Self>> {
        ensure!(
            config.environment == "isolated-development-protected-coordinator-v1"
                && config.directory.is_absolute()
                && !config.witness_anchor.is_nil()
                && config.policy_version > 0
                && config.max_fee_lamports > 0
                && config.max_lifetime_seconds > 0
                && config.max_lifetime_seconds <= 300,
            "explicit isolated protected coordinator configuration required"
        );
        fs::create_dir_all(&config.directory)?;
        let meta = fs::symlink_metadata(&config.directory)?;
        ensure!(
            meta.is_dir() && meta.uid() == unsafe { libc::geteuid() },
            "protected public store owner/path mismatch"
        );
        fs::set_permissions(&config.directory, fs::Permissions::from_mode(0o700))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(config.directory.join("coordinator.lock"))?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "protected store already owned"
        );
        let witness =
            PinnedIdentity::new(&config.witness_certificate, "witness", &AUTHORITY_ROLES)?;
        let mut archive = BTreeMap::new();
        for file in &config.archived_witness_certificates {
            let pin = PinnedIdentity::new(file, "witness", &AUTHORITY_ROLES)?;
            ensure!(
                pin.key_id != witness.key_id && archive.insert(pin.key_id.clone(), pin).is_none(),
                "duplicate archived witness pin"
            );
        }
        let mut nodes = BTreeMap::new();
        ensure!(
            config.node_certificates.len() == 3,
            "three original node pin rings required"
        );
        for party in PARTIES {
            let mut ring = BTreeMap::new();
            for path in config
                .node_certificates
                .get(party)
                .context("missing node public pin ring")?
            {
                let pin = PinnedIdentity::new(path, party, &AUTHORITY_ROLES)?;
                ensure!(
                    ring.insert(pin.key_id.clone(), pin).is_none(),
                    "duplicate node public pin"
                );
            }
            ensure!(!ring.is_empty(), "empty node public pin ring");
            nodes.insert(party.into(), ring);
        }
        let service = Arc::new(Self {
            config,
            witness,
            witness_archive: archive,
            nodes,
            peers,
            local: Mutex::new(Local {
                jobs: BTreeMap::new(),
                poisoned: false,
            }),
            serial: std::sync::Mutex::new(()),
            uncertain: AtomicBool::new(false),
            _lock: lock,
        });
        // No service is exposed until every public record has been verified and
        // uncertain executions have been durably converted to public recovery.
        let mut jobs = BTreeMap::new();
        for entry in fs::read_dir(&service.config.directory)? {
            let path = entry?.path();
            if path.file_name().and_then(|v| v.to_str()) == Some("coordinator.lock") {
                continue;
            }
            if path
                .extension()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("tmp-"))
            {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|v| v.to_str())
                .and_then(|v| Uuid::parse_str(v).ok())
                .context("unexpected protected coordinator history entry")?;
            ensure!(
                path.file_name().and_then(|v| v.to_str()) == Some(format!("{id}.json").as_str()),
                "noncanonical protected history entry"
            );
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            ensure!(
                file.metadata()
                    .is_ok_and(|m| m.is_file() && m.len() <= 1024 * 1024),
                "bounded original public job required"
            );
            let mut bytes = vec![];
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 1024 * 1024, "public job grew beyond bounds");
            let mut session: Session = serde_json::from_slice(&bytes)?;
            ensure!(
                session.request.binding.authorized.intent.session_id == id,
                "original public job identity mismatch"
            );
            service.validate_session(&session)?;
            if session.status == Status::InProgress {
                session.status = Status::ReconciliationRequired;
                session.error_code = Some("COORDINATOR_RESTART".into());
                atomic_replace_state(&path, &serde_json::to_vec(&session)?)?;
            }
            confirm_parent_durability(&path)?;
            service.check_aliases(&jobs, &session.request)?;
            ensure!(
                jobs.insert(id, session).is_none(),
                "duplicate protected job identity"
            );
        }
        service
            .local
            .try_lock()
            .map_err(|_| anyhow::anyhow!("initial public store busy"))?
            .jobs = jobs;
        Ok(service)
    }
    fn validate_request(&self, request: &Request, live: bool) -> Result<()> {
        let binding = &request.binding;
        binding.identity()?;
        let i = &binding.authorized.intent;
        let view = &request.witness.value;
        let pin = if live || request.witness.key_id == self.witness.key_id {
            &self.witness
        } else {
            self.witness_archive
                .get(&request.witness.key_id)
                .context("unknown original witness public key")?
        };
        verify(pin, "WITNESS_QUERY_REPLY_V1", &request.witness)?;
        let financial = i
            .financial
            .as_ref()
            .context("protected financial operation requires typed reservation")?;
        financial.validate(i)?;
        let mode = view
            .root
            .financial_mode
            .as_ref()
            .context("independent financial Root activation required")?;
        ensure!(
            mode.version == VERSION
                && !mode.activation_id.is_nil()
                && !mode.command_id.is_nil()
                && view.query.anchor_id == self.config.witness_anchor
                && view.query.root_identity == i.claim.root.identity()?
                && view.query.execution_id == Some(i.crypto_execution_id)
                && view.query.claim_reservation_id == Some(i.claim.reservation_id)
                && wallet_mpc_protocol::witness::hash_text(&view.query.challenge)
                && view.query.challenge != "00".repeat(32)
                && view.sequence > 0
                && view.root.original == i.claim.root
                && view.root.original.wallet_class == "HOT"
                && view.root.generation == i.generation
                && view.root.phase == Phase::Active
                && view.claim.as_ref() == Some(&binding.authorized.claim_evidence)
                && view.root.node_keys.len() == 3
                && PARTIES.iter().all(|p| view
                    .root
                    .node_keys
                    .get(*p)
                    .is_some_and(|key| self.nodes[*p].contains_key(key))),
            "exact activated HOT Root/Claim/generation and original witness query required"
        );
        if i.operation_type != BusinessOperation::Provision {
            ensure!(
                view.claim_issuance
                    .as_ref()
                    .is_some_and(|grant| grant.reservation_id == i.claim.reservation_id),
                "spending requires independently granted wallet publication"
            );
        }
        if let Some(execution) = &view.execution {
            ensure!(
                execution.binding_fingerprint == binding.identity()?,
                "existing witness execution changed"
            );
        }
        let policy = ValidationPolicy {
            genesis_hash: self.config.genesis_hash.clone(),
            version: self.config.policy_version,
            max_fee_lamports: self.config.max_fee_lamports,
            max_rent_lamports: self.config.max_rent_lamports,
            max_lifetime_seconds: self.config.max_lifetime_seconds,
        };
        binding.authorized.validate_shape(
            &view.root.public_key_package,
            if live { now()? } else { i.issued_at },
            &policy,
        )?;
        Ok(())
    }
    fn check_aliases(&self, jobs: &BTreeMap<Uuid, Session>, request: &Request) -> Result<()> {
        let i = &request.binding.authorized.intent;
        let financial = i
            .financial
            .as_ref()
            .context("financial reservation required")?;
        for old in jobs.values() {
            let previous = &old.request.binding.authorized.intent;
            ensure!(
                previous.crypto_execution_id != i.crypto_execution_id,
                "original crypto execution already owned by a session"
            );
            let other = previous
                .financial
                .as_ref()
                .context("original financial identity missing")?;
            if request.binding.authorized.wire_key()?
                == old.request.binding.authorized.wire_key()?
            {
                ensure!(
                    financial.reservation_id == other.reservation_id
                        && request.binding.authorized.business_fingerprint()?
                            == old.request.binding.authorized.business_fingerprint()?,
                    "one original wire cannot own multiple financial reservations"
                );
            }
            if financial.reservation_id == other.reservation_id
                || request.binding.authorized.operation_key()?
                    == old.request.binding.authorized.operation_key()?
            {
                ensure!(
                    request.binding.authorized.operation_key()?
                        == old.request.binding.authorized.operation_key()?
                        && request.binding.authorized.business_fingerprint()?
                            == old.request.binding.authorized.business_fingerprint()?,
                    "one reservation cannot change its original business identity"
                );
            }
            ensure!(
                request.binding.authorized.attempt_key()?
                    != old.request.binding.authorized.attempt_key()?,
                "one business attempt cannot own multiple crypto sessions"
            );
        }
        Ok(())
    }
    fn report(
        &self,
        session: &Session,
        party: &str,
        round: u16,
        report: &Signed<PublicRound>,
    ) -> Result<()> {
        let r = &report.value;
        let i = &session.request.binding.authorized.intent;
        let key = &session.request.witness.value.root.node_keys[party];
        verify(
            self.nodes[party]
                .get(key)
                .context("original node public pin unavailable")?,
            "WITNESS_PUBLIC_ROUND_V1",
            report,
        )?;
        ensure!(
            r.anchor_id == self.config.witness_anchor
                && r.execution_id == i.crypto_execution_id
                && r.party_id == party
                && r.round == round
                && r.binding_fingerprint == session.request.binding.identity()?,
            "original public round identity mismatch"
        );
        if round == 1 {
            let bytes = r
                .commitments
                .as_ref()
                .context("missing original commitments")?;
            ensure!(
                r.signature_share.is_none()
                    && r.signing_package.is_none()
                    && frost::round1::SigningCommitments::deserialize(bytes)?.serialize()?
                        == *bytes,
                "canonical original R1 only"
            );
        } else {
            ensure!(
                r.commitments.is_none()
                    && r.signing_package == session.signing_package
                    && frost::round2::SignatureShare::deserialize(
                        r.signature_share
                            .as_ref()
                            .context("missing original share")?
                    )?
                    .serialize()
                        == *r.signature_share.as_ref().unwrap(),
                "canonical original R2 and immutable package required"
            );
            let public = public_package(
                &session.request.witness.value.root.public_key_package,
                &i.claim.root.group_public_key,
            )?;
            let id = identifier(party).context("party identity")?;
            frost_core::verify_signature_share::<frost::Ed25519Sha512>(
                id,
                public
                    .verifying_shares()
                    .get(&id)
                    .context("missing original party verifying share")?,
                &frost::round2::SignatureShare::deserialize(r.signature_share.as_ref().unwrap())?,
                &frost::SigningPackage::deserialize(
                    session
                        .signing_package
                        .as_ref()
                        .context("original package required")?,
                )?,
                public.verifying_key(),
            )?;
        }
        Ok(())
    }
    fn package(&self, session: &Session) -> Result<Vec<u8>> {
        let mut commitments = BTreeMap::new();
        for party in &session.request.binding.selected_signers {
            let report = session
                .round1
                .get(party)
                .context("all original R1 reports required")?;
            self.report(session, party, 1, report)?;
            commitments.insert(
                identifier(party).context("party identity")?,
                frost::round1::SigningCommitments::deserialize(
                    report.value.commitments.as_ref().unwrap(),
                )?,
            );
        }
        Ok(frost::SigningPackage::new(
            commitments,
            &decode_hex(&session.request.binding.authorized.payload_hex).context("payload")?,
        )
        .serialize()?)
    }
    fn aggregate(&self, session: &Session) -> Result<String> {
        let bytes = session
            .signing_package
            .as_ref()
            .context("original first R2 package missing")?;
        ensure!(self.package(session)? == *bytes, "first R2 package changed");
        let package = frost::SigningPackage::deserialize(bytes)?;
        let mut shares = BTreeMap::new();
        for party in &session.request.binding.selected_signers {
            let report = session
                .round2
                .get(party)
                .context("all original R2 reports required")?;
            self.report(session, party, 2, report)?;
            shares.insert(
                identifier(party).unwrap(),
                frost::round2::SignatureShare::deserialize(
                    report.value.signature_share.as_ref().unwrap(),
                )?,
            );
        }
        let public = public_package(
            &session.request.witness.value.root.public_key_package,
            &session
                .request
                .binding
                .authorized
                .intent
                .claim
                .root
                .group_public_key,
        )?;
        let signature = frost::aggregate(&package, &shares, &public)?;
        public
            .verifying_key()
            .verify(package.message(), &signature)?;
        Ok(wallet_mpc_protocol::dkg::hex(&signature.serialize()?))
    }
    fn validate_session(&self, session: &Session) -> Result<()> {
        self.validate_request(&session.request, false)?;
        let pair = &session.request.binding.selected_signers;
        ensure!(
            session.round1.keys().all(|p| pair.contains(p))
                && session.round2.keys().all(|p| pair.contains(p)),
            "foreign public report"
        );
        for (p, r) in &session.round1 {
            self.report(session, p, 1, r)?;
        }
        if let Some(package) = &session.signing_package {
            ensure!(
                self.package(session)? == *package,
                "original package mismatch"
            );
        }
        ensure!(
            session.signing_package.is_some() || session.round2.is_empty(),
            "R2 lacks original durable package"
        );
        for (p, r) in &session.round2 {
            self.report(session, p, 2, r)?;
        }
        if session.status == Status::Created {
            ensure!(
                session.round1.is_empty() && session.signing_package.is_none(),
                "created job has private history"
            );
        }
        if session.status == Status::Completed {
            ensure!(
                session.signature_hex.as_ref() == Some(&self.aggregate(session)?),
                "completed original signature mismatch"
            );
        } else {
            ensure!(
                session.signature_hex.is_none(),
                "uncommitted completed signature"
            );
        }
        Ok(())
    }
    fn save(&self, local: &mut Local, session: Session, create: bool) -> Result<()> {
        ensure!(!local.poisoned, "public coordinator durability uncertain");
        self.validate_session(&session)?;
        let id = session.request.binding.authorized.intent.session_id;
        let bytes = serde_json::to_vec(&session)?;
        ensure!(
            bytes.len() <= 1024 * 1024,
            "bounded public signing record required"
        );
        let _serial = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("public write/release ordering uncertain"))?;
        self.uncertain.store(true, Ordering::Release);
        local.poisoned = true;
        let path = self.config.directory.join(format!("{id}.json"));
        if create {
            atomic_create_secret(&path, &bytes)?;
        } else {
            atomic_replace_state(&path, &bytes)?;
        }
        local.jobs.insert(id, session);
        local.poisoned = false;
        self.uncertain.store(false, Ordering::Release);
        Ok(())
    }
    pub async fn create(&self, request: Request) -> Result<Session> {
        self.validate_request(&request, true)?;
        let id = request.binding.authorized.intent.session_id;
        let mut local = self.local.lock().await;
        ensure!(!local.poisoned, "uncertain public store");
        if let Some(old) = local.jobs.get(&id) {
            ensure!(
                old.request.binding == request.binding
                    && old.request.witness.value.root.public_key_package
                        == request.witness.value.root.public_key_package
                    && old.request.witness.value.root.node_keys
                        == request.witness.value.root.node_keys,
                "original protected session cannot change"
            );
            return Ok(old.clone());
        }
        self.check_aliases(&local.jobs, &request)?;
        let session = Session {
            request,
            status: Status::Created,
            round1: BTreeMap::new(),
            signing_package: None,
            round2: BTreeMap::new(),
            signature_hex: None,
            error_code: None,
        };
        self.save(&mut local, session.clone(), true)?;
        Ok(session)
    }
    pub async fn get(&self, id: Uuid) -> Result<Session> {
        let local = self.local.lock().await;
        ensure!(!local.poisoned, "uncertain public store");
        local
            .jobs
            .get(&id)
            .cloned()
            .context("unknown protected session")
    }
    async fn control(
        &self,
        session: &Session,
        party: &str,
        action: &str,
        round: u16,
    ) -> Result<Option<Signed<PublicRound>>> {
        let body = serde_json::json!({"binding":session.request.binding,"round":round,
            "signing_package":if round==2 {session.signing_package.clone()}else{None}});
        let path = format!("/internal/v1/solana/protected/{action}");
        let bytes = if action == "recover" {
            self.peers
                .request_pinned(
                    party,
                    &session.request.witness.value.root.node_keys[party],
                    "POST",
                    &path,
                    serde_json::to_vec(&body)?,
                )
                .await?
        } else {
            self.peers
                .request_pinned_until(
                    party,
                    &session.request.witness.value.root.node_keys[party],
                    &path,
                    serde_json::to_vec(&body)?,
                    session.request.binding.authorized.intent.expires_at,
                    || {
                        let guard = self
                            .serial
                            .lock()
                            .map_err(|_| anyhow::anyhow!("dispatch ordering uncertain"))?;
                        ensure!(
                            !self.uncertain.load(Ordering::Acquire),
                            "coordinator durability uncertain; no new private dispatch"
                        );
                        Ok(guard)
                    },
                )
                .await?
        };
        let report = if action == "recover" {
            serde_json::from_slice(&bytes)?
        } else {
            Some(serde_json::from_slice(&bytes)?)
        };
        if let Some(r) = &report {
            self.report(session, party, round, r)?;
        }
        Ok(report)
    }
    async fn record(
        &self,
        id: Uuid,
        party: &str,
        round: u16,
        report: Signed<PublicRound>,
    ) -> Result<Session> {
        let mut local = self.local.lock().await;
        let mut session = local.jobs.get(&id).cloned().context("unknown session")?;
        self.report(&session, party, round, &report)?;
        let reports = if round == 1 {
            &mut session.round1
        } else {
            &mut session.round2
        };
        if let Some(old) = reports.get(party) {
            ensure!(*old == report, "original public result cannot change");
        }
        reports.insert(party.into(), report);
        self.save(&mut local, session.clone(), false)?;
        Ok(session)
    }
    async fn complete(&self, id: Uuid) -> Result<Session> {
        let mut local = self.local.lock().await;
        let mut session = local.jobs.get(&id).cloned().context("unknown session")?;
        let signature = self.aggregate(&session)?;
        session.signature_hex = Some(signature);
        session.status = Status::Completed;
        session.error_code = None;
        self.save(&mut local, session.clone(), false)?;
        Ok(session)
    }
    pub async fn execute(self: &Arc<Self>, id: Uuid) -> Result<Session> {
        let session = {
            let mut local = self.local.lock().await;
            let mut s = local.jobs.get(&id).cloned().context("unknown session")?;
            if s.status != Status::Created {
                return Ok(s);
            }
            self.validate_request(&s.request, true)?;
            s.status = Status::InProgress;
            self.save(&mut local, s.clone(), false)?;
            s
        };
        let service = self.clone();
        // Dropping the HTTP response future detaches this owned task. It cannot
        // erase the durable claim or turn a lost response into new private work.
        tokio::spawn(async move { service.drive(id, session).await })
            .await
            .context("protected worker stopped; retain original operation")?
    }
    async fn drive(&self, id: Uuid, mut session: Session) -> Result<Session> {
        let outcome = async {
            for party in session.request.binding.selected_signers.clone() {
                let report = self
                    .control(&session, &party, "auto", 1)
                    .await?
                    .context("missing R1 result")?;
                session = self.record(id, &party, 1, report).await?;
            }
            {
                let mut local = self.local.lock().await;
                session.signing_package = Some(self.package(&session)?);
                // First package and original R1 reports fsync BEFORE ANY R2 RPC.
                self.save(&mut local, session.clone(), false)?;
            }
            for party in session.request.binding.selected_signers.clone() {
                let report = self
                    .control(&session, &party, "auto", 2)
                    .await?
                    .context("missing R2 result")?;
                session = self.record(id, &party, 2, report).await?;
            }
            self.complete(id).await
        }
        .await;
        if outcome.is_ok() {
            return outcome;
        }
        let mut local = self.local.lock().await;
        ensure!(
            !local.poisoned,
            "public write outcome uncertain; restart required"
        );
        let mut session = local.jobs.get(&id).cloned().context("unknown session")?;
        if session.status != Status::Completed {
            session.status = Status::ReconciliationRequired;
            session.error_code = Some("PRIVATE_OUTCOME_UNCERTAIN".into());
            self.save(&mut local, session.clone(), false)?;
        }
        Ok(session)
    }
    pub async fn reconcile(&self, id: Uuid) -> Result<Session> {
        let mut session = self.get(id).await?;
        if session.status == Status::Completed || session.signing_package.is_none() {
            return Ok(session);
        }
        ensure!(
            session.status == Status::ReconciliationRequired,
            "only uncertain operations may recover"
        );
        for party in session.request.binding.selected_signers.clone() {
            if !session.round2.contains_key(&party) {
                if let Ok(Some(report)) = self.control(&session, &party, "recover", 2).await {
                    session = self.record(id, &party, 2, report).await?;
                }
            }
        }
        if session.round2.len() == 2 {
            self.complete(id).await
        } else {
            Ok(session)
        }
    }
}
fn reject(_: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(
            serde_json::json!({"error":"protected operation rejected; retain original reservation"}),
        ),
    )
}
async fn create(
    State(s): State<Arc<Service>>,
    Json(r): Json<Request>,
) -> Result<Json<Session>, (StatusCode, Json<serde_json::Value>)> {
    s.create(r).await.map(Json).map_err(reject)
}
async fn get_session(
    State(s): State<Arc<Service>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Session>, (StatusCode, Json<serde_json::Value>)> {
    s.get(id).await.map(Json).map_err(reject)
}
async fn execute(
    State(s): State<Arc<Service>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Session>, (StatusCode, Json<serde_json::Value>)> {
    s.execute(id).await.map(Json).map_err(reject)
}
async fn reconcile(
    State(s): State<Arc<Service>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Session>, (StatusCode, Json<serde_json::Value>)> {
    s.reconcile(id).await.map(Json).map_err(reject)
}
pub fn router(service: Arc<Service>) -> Router {
    Router::new()
        .route("/v1/solana-protected-sessions", post(create))
        .route("/v1/solana-protected-sessions/{id}", get(get_session))
        .route("/v1/solana-protected-sessions/{id}/execute", post(execute))
        .route(
            "/v1/solana-protected-sessions/{id}/reconcile",
            post(reconcile),
        )
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .with_state(service)
}
