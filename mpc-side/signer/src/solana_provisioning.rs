//! Durable, independently signed seeded namespace/claim approvals. Enrollment
//! irreversibly fences the legacy arbitrary-message FROST API on this store.
//! Seeded spending remains disabled until its separate intent/generation gate.
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::hex,
    sign::{decode_hex, CustodyAuthorization, SignReport},
    solana_provisioning::{authorization_message, receipt_message, Approval, Claim, Report, Root},
};
use wallet_mpc_storage::{atomic_create_secret, confirm_parent_durability};
use wallet_mpc_transport::{CustodyRequestVerifier, PeerIdentity, ReceiptIdentity};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    approval: Approval<Root>,
    report: Report<Root>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Role {
    keyset_id: Uuid,
    enrollment: Option<Enrollment>,
}

// Only a byte-for-byte verification cache. Every approval still reads the
// complete committed index inventory; disk remains authoritative. No cache
// entry can authorize spending or repair missing aliases.
struct VerifiedIndex {
    bytes: Vec<u8>,
    report: Report<Claim>,
    names: [String; 4],
}

pub struct Service {
    directory: PathBuf,
    party: String,
    dkg: Arc<crate::dkg::DkgService>,
    verifier: CustodyRequestVerifier,
    identity: Option<ReceiptIdentity>,
    lock: Mutex<BTreeMap<String, VerifiedIndex>>,
}
impl Service {
    pub fn open(
        storage: PathBuf,
        party: String,
        dkg: Arc<crate::dkg::DkgService>,
        verifier: CustodyRequestVerifier,
        identity: Option<ReceiptIdentity>,
    ) -> Result<Arc<Self>> {
        let directory = storage.join("solana-provisioning");
        fs::create_dir_all(&directory)?;
        confirm_parent_durability(&directory)?;
        let service = Self {
            directory,
            party,
            dkg,
            verifier,
            identity,
            lock: Mutex::new(BTreeMap::new()),
        };
        // Original prepared/consumed/aborted executions are historical use too.
        // Never manufacture UNUSED after upgrading a previously used root.
        let signing = storage.join("signing");
        if signing.exists() {
            for entry in fs::read_dir(signing)? {
                let path = entry?.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    let report: SignReport = serde_json::from_slice(&fs::read(path)?)?;
                    report.execution.validate()?;
                    if report.execution.dkg.scope == "SOLANA" {
                        service.legacy_role(report.execution.dkg.keyset_id, true)?;
                    }
                }
            }
        }
        let mut indices = BTreeMap::<String, Report<Claim>>::new();
        let mut verified = BTreeMap::new();
        for entry in fs::read_dir(&service.directory)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .context("missing filename")?
                .to_string_lossy()
                .into_owned();
            // storage::atomic_write uses destination.with_extension("tmp-UUID").
            // Such files never committed and cannot authorize anything. Retain
            // them for inspection without interpreting them as a role/claim.
            if path
                .extension()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix("tmp-"))
                .and_then(|s| Uuid::parse_str(s).ok().filter(|u| u.to_string() == s))
                .is_some()
            {
                continue;
            }
            match path.extension().and_then(|s| s.to_str()) {
                Some("role") => {
                    let role: Role = serde_json::from_slice(&fs::read(&path)?)?;
                    ensure!(
                        name == format!("{}.role", role.keyset_id),
                        "wrong role filename"
                    );
                    service.role(role.keyset_id)?;
                }
                Some("index") => {
                    let bytes = fs::read(&path)?;
                    let report: Report<Claim> = serde_json::from_slice(&bytes)?;
                    service.verify_claim(&report)?;
                    ensure!(
                        name == service.names(&report.statement)?[0],
                        "wrong index filename"
                    );
                    verified.insert(
                        name.clone(),
                        VerifiedIndex {
                            bytes,
                            names: service.names(&report.statement)?,
                            report: report.clone(),
                        },
                    );
                    indices.insert(name, report);
                }
                Some("owner" | "claim" | "retry") => {}
                _ => anyhow::bail!("unrecognized seeded store file"),
            }
        }
        let mut aliases = BTreeMap::new();
        let mut counters = BTreeMap::<Uuid, Vec<u64>>::new();
        for report in indices.values() {
            counters
                .entry(report.statement.root.dkg.keyset_id)
                .or_default()
                .push(report.statement.index);
            for name in service.names(&report.statement)? {
                ensure!(
                    aliases.insert(name, report).is_none(),
                    "duplicate immutable claim alias"
                );
            }
        }
        for values in counters.values_mut() {
            values.sort();
            ensure!(
                values
                    .iter()
                    .enumerate()
                    .all(|(i, v)| u64::try_from(i) == Ok(*v)),
                "seed allocation gap"
            );
        }
        for entry in fs::read_dir(&service.directory)? {
            let path = entry?.path();
            if [Some("index"), Some("owner"), Some("claim"), Some("retry")]
                .contains(&path.extension().and_then(|s| s.to_str()))
            {
                let name = path.file_name().unwrap().to_string_lossy();
                let expected = aliases
                    .get(name.as_ref())
                    .context("orphan seeded claim alias")?;
                let report: Report<Claim> = serde_json::from_slice(&fs::read(&path)?)?;
                ensure!(&report == *expected, "conflicting original claim aliases");
                confirm_parent_durability(&path)?;
            }
        }
        *service.lock.try_lock().context("startup inventory lock")? = verified;
        Ok(Arc::new(service))
    }
    fn pin<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let path = self.directory.join(name);
        let bytes = serde_json::to_vec(value)?;
        if !path.exists() {
            atomic_create_secret(&path, &bytes)?;
        }
        ensure!(
            fs::read(&path)? == bytes,
            "immutable seeded record conflict"
        );
        confirm_parent_durability(&path)?;
        Ok(())
    }
    fn verify_report<T: Serialize>(&self, kind: &str, report: &Report<T>) -> Result<()> {
        ensure!(
            report.party_id == self.party && report.durable,
            "wrong own receipt identity"
        );
        self.identity
            .as_ref()
            .context("pinned receipt identity unavailable")?
            .verify(
                &receipt_message(kind, &report.statement, &self.party)?,
                &decode_hex(&report.signer_signature).context("invalid receipt signature")?,
            )
    }
    fn report<T: Serialize>(&self, kind: &str, statement: T) -> Result<Report<T>> {
        let signer_signature = hex(&self
            .identity
            .as_ref()
            .context("pinned receipt identity unavailable")?
            .sign(&receipt_message(kind, &statement, &self.party)?)?);
        Ok(Report {
            statement,
            party_id: self.party.clone(),
            durable: true,
            signer_signature,
        })
    }
    fn verify_authorization<T: Serialize>(&self, kind: &str, approval: &Approval<T>) -> Result<()> {
        let CustodyAuthorization {
            certificate_chain_der_hex,
            signature_der_hex,
        } = &approval.custody_authorization;
        let chain = certificate_chain_der_hex
            .iter()
            .map(|c| decode_hex(c).context("invalid custody certificate"))
            .collect::<Result<Vec<_>>>()?;
        self.verifier.verify(
            &authorization_message(kind, &approval.statement)?,
            &chain,
            &decode_hex(signature_der_hex).context("invalid custody signature")?,
        )
    }
    fn role(&self, keyset_id: Uuid) -> Result<Option<Role>> {
        let path = self.directory.join(format!("{keyset_id}.role"));
        if !path.exists() {
            return Ok(None);
        }
        let role: Role = serde_json::from_slice(&fs::read(&path)?)?;
        ensure!(role.keyset_id == keyset_id, "wrong original keyset");
        if let Some(enrollment) = &role.enrollment {
            enrollment.report.statement.validate()?;
            ensure!(
                enrollment.approval.statement == enrollment.report.statement
                    && enrollment.report.statement.dkg.keyset_id == keyset_id,
                "invalid original enrollment"
            );
            self.verify_report("root", &enrollment.report)?;
        }
        confirm_parent_durability(&path)?;
        Ok(Some(role))
    }
    fn legacy_role(&self, keyset: Uuid, reserve: bool) -> Result<()> {
        ensure!(
            self.role(keyset)?.is_none_or(|r| r.enrollment.is_none()),
            "dedicated seeded root cannot use legacy signing"
        );
        if reserve {
            self.pin(
                &format!("{keyset}.role"),
                &Role {
                    keyset_id: keyset,
                    enrollment: None,
                },
            )?;
        }
        Ok(())
    }
    pub async fn require_legacy(&self, keyset: Uuid, reserve: bool) -> Result<()> {
        let _guard = self.lock.lock().await;
        self.legacy_role(keyset, reserve)
    }
    async fn original(&self, root: &Root) -> Result<()> {
        root.validate()?;
        self.dkg
            .original_public(&root.dkg, &root.group_public_key, &root.public_key_package)
            .await
    }
    pub async fn enroll(&self, approval: Approval<Root>) -> Result<Report<Root>> {
        approval.statement.validate()?;
        self.verify_authorization("root", &approval)?;
        self.original(&approval.statement).await?;
        let _guard = self.lock.lock().await;
        let keyset = approval.statement.dkg.keyset_id;
        if let Some(role) = self.role(keyset)? {
            let enrollment = role
                .enrollment
                .context("historical root cannot be dedicated")?;
            ensure!(
                enrollment.report.statement == approval.statement,
                "root namespace cannot change"
            );
            return Ok(enrollment.report);
        }
        let report = self.report("root", approval.statement.clone())?;
        self.pin(
            &format!("{keyset}.role"),
            &Role {
                keyset_id: keyset,
                enrollment: Some(Enrollment {
                    approval,
                    report: report.clone(),
                }),
            },
        )?;
        Ok(report)
    }
    pub async fn probe(&self, approval: Approval<Root>) -> Result<serde_json::Value> {
        approval.statement.validate()?;
        self.verify_authorization("root", &approval)?;
        self.original(&approval.statement).await?;
        self.identity
            .as_ref()
            .context("pinned receipt identity unavailable")?;
        let _guard = self.lock.lock().await;
        if let Some(role) = self.role(approval.statement.dkg.keyset_id)? {
            ensure!(
                role.enrollment
                    .is_some_and(|e| e.report.statement == approval.statement),
                "historical or differently dedicated root"
            );
        }
        // Read-only transport response, not a durable dedication receipt or a
        // promise against future concurrent state changes on other parties.
        Ok(
            serde_json::json!({"statement": approval.statement, "party_id": self.party, "eligible": true}),
        )
    }
    fn enrolled(&self, root: &Root) -> Result<()> {
        let enrollment = self
            .role(root.dkg.keyset_id)?
            .and_then(|r| r.enrollment)
            .context("missing original seeded dedication")?;
        ensure!(
            enrollment.report.statement == *root,
            "wrong original root/network/owner"
        );
        Ok(())
    }
    fn names(&self, claim: &Claim) -> Result<[String; 4]> {
        Ok([
            format!("{}-{}.index", claim.root.dkg.keyset_id, claim.index),
            format!("{}.owner", claim.owner_slot()?),
            format!("{}.claim", claim.reservation_id),
            format!("{}.retry", claim.retry_slot()?),
        ])
    }
    fn verify_claim(&self, report: &Report<Claim>) -> Result<()> {
        report.statement.validate()?;
        self.enrolled(&report.statement.root)?;
        self.verify_report("claim", report)
    }
    /// Read-only original approval lookup. Spending cannot manufacture or repair
    /// missing provisioning aliases, and a share backup alone is insufficient.
    pub async fn require_approved(&self, claim: &Claim) -> Result<()> {
        self.original(&claim.root).await?;
        let _guard = self.lock.lock().await;
        self.enrolled(&claim.root)?;
        for name in self.names(claim)? {
            let path = self.directory.join(name);
            let report: Report<Claim> = serde_json::from_slice(&fs::read(&path)?)?;
            self.verify_claim(&report)?;
            ensure!(
                report.statement == *claim,
                "original claim identity mismatch"
            );
            confirm_parent_durability(&path)?;
        }
        Ok(())
    }
    pub async fn require_root(&self, root: &Root) -> Result<()> {
        self.original(root).await?;
        let _guard = self.lock.lock().await;
        self.enrolled(root)
    }
    pub async fn approve(&self, approval: Approval<Claim>) -> Result<Report<Claim>> {
        approval.statement.validate()?;
        self.verify_authorization("claim", &approval)?;
        self.original(&approval.statement.root).await?;
        let mut verified = self.lock.lock().await;
        let claim = &approval.statement;
        self.enrolled(&claim.root)?;
        let names = self.names(claim)?;
        let mut previous = None;
        for name in &names {
            let path = self.directory.join(name);
            if path.exists() {
                let report: Report<Claim> = serde_json::from_slice(&fs::read(path)?)?;
                self.verify_claim(&report)?;
                ensure!(
                    report.statement == *claim,
                    "owner/index/retry claim cannot be reassigned"
                );
                ensure!(
                    previous.as_ref().is_none_or(|p| *p == report),
                    "partial receipt conflict"
                );
                previous = Some(report);
            }
        }
        // The index is authoritative even if a crash preceded every alias.
        // Check all committed indices before granting a different owner/retry
        // at the next index; missing aliases must never permit reassignment.
        let mut next = 0;
        let mut seen = BTreeSet::new();
        for entry in fs::read_dir(&self.directory)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .context("missing index filename")?
                .to_string_lossy()
                .into_owned();
            if name.ends_with(".index") {
                let bytes = fs::read(&path)?;
                if let Some(cached) = verified.get(&name) {
                    ensure!(
                        cached.bytes == bytes,
                        "committed index changed since verification"
                    );
                } else {
                    // Also covers a committed index whose reply/alias writes
                    // failed. Verify it once before caching its exact bytes.
                    let report: Report<Claim> = serde_json::from_slice(&bytes)?;
                    self.verify_claim(&report)?;
                    let stored_names = self.names(&report.statement)?;
                    ensure!(name == stored_names[0], "wrong index filename");
                    verified.insert(
                        name.clone(),
                        VerifiedIndex {
                            bytes,
                            report,
                            names: stored_names,
                        },
                    );
                }
                let cached = &verified[&name];
                let stored = &cached.report;
                if stored.statement.root.dkg.keyset_id == claim.root.dkg.keyset_id {
                    next = next.max(stored.statement.index + 1);
                }
                if cached.names.iter().any(|n| names.contains(n)) {
                    ensure!(
                        stored.statement == *claim,
                        "committed claim cannot be reassigned"
                    );
                    ensure!(
                        previous.as_ref().is_none_or(|p| p == stored),
                        "partial receipt conflict"
                    );
                    previous = Some(stored.clone());
                }
                seen.insert(name);
            }
        }
        ensure!(
            verified.keys().all(|name| seen.contains(name)),
            "committed index disappeared since verification"
        );
        // All index entries share this directory: one fsync confirms the
        // enumerated directory, including indices recovered after a lost reply.
        confirm_parent_durability(&self.directory.join("inventory"))?;
        let report = match previous {
            Some(report) => report,
            None => {
                // The index record commits first. Aliases can be completed after
                // restart, never recycling the committed index or owner identity.
                ensure!(
                    claim.index == next,
                    "index must be the next monotonic allocation"
                );
                self.report("claim", claim.clone())?
            }
        };
        // Record the authoritative index before aliases. A later alias failure
        // must not remove the in-process missing-index fence.
        self.pin(&names[0], &report)?;
        verified.insert(
            names[0].clone(),
            VerifiedIndex {
                bytes: serde_json::to_vec(&report)?,
                report: report.clone(),
                names: names.clone(),
            },
        );
        for name in &names[1..] {
            self.pin(name, &report)?;
        }
        Ok(report)
    }
}

async fn enroll(
    State(service): State<Arc<Service>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<Report<Root>>, StatusCode> {
    ensure_coordinator(&peer)?;
    let approval = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service
        .enroll(approval)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
async fn probe(
    State(service): State<Arc<Service>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    ensure_coordinator(&peer)?;
    let approval = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service
        .probe(approval)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
async fn approve(
    State(service): State<Arc<Service>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<Report<Claim>>, StatusCode> {
    ensure_coordinator(&peer)?;
    let approval = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service
        .approve(approval)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
fn ensure_coordinator(peer: &PeerIdentity) -> Result<(), StatusCode> {
    if peer.role() == "coordinator" {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
pub fn router(service: Arc<Service>) -> Router {
    Router::new()
        .route("/internal/v1/solana/seeded/enroll", post(enroll))
        .route("/internal/v1/solana/seeded/probe", post(probe))
        .route("/internal/v1/solana/seeded/approve", post(approve))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(service)
}
