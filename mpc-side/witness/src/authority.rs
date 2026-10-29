use crate::{
    state::Snapshot,
    trust::{AuthorityConfig, Trust},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::PathBuf,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::PARTIES,
    witness::{
        hash, hash_text, Acknowledgement, Command, CommandAction, ExecutionView, Permit,
        PermitRequest, PublicRound, Query, QueryReply, RootView, Signed,
    },
};
use wallet_mpc_storage::{atomic_create_secret, atomic_replace_state, confirm_parent_durability};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Transition {
    Initialize,
    Command { command: Box<Signed<Command>> },
    Permit { request: Box<Signed<PermitRequest>> },
    PublicResult { report: Box<Signed<PublicRound>> },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    anchor_id: Uuid,
    sequence: u64,
    previous_hash: String,
    time: u64,
    transition: Transition,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    anchor_id: Uuid,
    sequence: u64,
    event_hash: String,
}
struct Journal {
    state: Snapshot,
    last_hash: String,
    directory: PathBuf,
    poisoned: bool,
    _lock: File,
}

pub struct Authority {
    config: AuthorityConfig,
    trust: Trust,
    journal: Mutex<Journal>,
}

fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
// Read the admission time only after acquiring the durable authority lock.
// Queuing behind another root's fsync must never extend an authorization TTL.
async fn lock_fresh<'a, T>(
    mutex: &'a Mutex<T>,
    validate: impl FnOnce(u64) -> Result<()>,
    clock: impl FnOnce() -> Result<u64>,
) -> Result<(tokio::sync::MutexGuard<'a, T>, u64)> {
    let guard = mutex.lock().await;
    let time = clock()?;
    validate(time)?;
    Ok((guard, time))
}
fn event_hash(event: &Signed<Event>) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&serde_json::to_value(event)?)?))
}
fn replay(state: &mut Snapshot, event: &Event) -> Result<()> {
    match &event.transition {
        Transition::Initialize => ensure!(
            event.sequence == 0 && state.sequence == 0 && state.roots.is_empty(),
            "invalid genesis event"
        ),
        Transition::Command { command } => {
            command.value.validate(event.time)?;
            ensure!(
                state.command(&command.value)?,
                "duplicate lifecycle journal event"
            );
        }
        Transition::Permit { request } => {
            state.permit(&request.value, &request.key_id, event.time)?;
        }
        Transition::PublicResult { report } => {
            ensure!(state.record(report)?, "duplicate result journal event");
        }
    }
    ensure!(
        state.sequence == event.sequence,
        "authority journal sequence disagreement"
    );
    Ok(())
}
impl Authority {
    pub fn open(config: AuthorityConfig, initialize: bool) -> Result<Self> {
        let trust = Trust::new(&config)?;
        fs::create_dir_all(&config.directory)?;
        ensure!(
            fs::symlink_metadata(&config.directory)?
                .file_type()
                .is_dir(),
            "authority state directory cannot be a symlink"
        );
        let directory = fs::canonicalize(&config.directory)?;
        for sensitive in [&config.tls_key, &config.lifecycle_certificate] {
            ensure!(
                !fs::canonicalize(sensitive)?.starts_with(&directory),
                "authority credentials must be protected outside journal backups"
            );
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(directory.join("authority.lock"))?;
        // One writer for this external authority. Never run divergent processes
        // over the same snapshot, even if their in-memory CAS locks differ.
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "authority directory already owned by a process"
        );
        let marker = directory.join("initialized.json");
        let events = directory.join("events");
        if initialize {
            ensure!(
                !marker.exists() && !events.exists(),
                "authority initialization cannot reset history"
            );
            fs::create_dir(&events)?;
            let genesis = Event {
                anchor_id: config.anchor_id,
                sequence: 0,
                previous_hash: "00".repeat(32),
                time: now()?,
                transition: Transition::Initialize,
            };
            let signed = trust.sign("WITNESS_EVENT_V1", genesis)?;
            atomic_create_secret(
                &events.join(format!("{:020}.json", 0)),
                &serde_json::to_vec(&signed)?,
            )?;
            let head = trust.sign(
                "WITNESS_HEAD_V1",
                Head {
                    anchor_id: config.anchor_id,
                    sequence: 0,
                    event_hash: event_hash(&signed)?,
                },
            )?;
            atomic_create_secret(&marker, &serde_json::to_vec(&head)?)?;
        }
        ensure!(
            fs::symlink_metadata(&marker).is_ok_and(|m| m.file_type().is_file() && m.len() <= 4096)
                && fs::symlink_metadata(&events).is_ok_and(|m| m.file_type().is_dir()),
            "authority history missing; initialization is explicit and cannot recover lost history"
        );
        let head: Signed<Head> = serde_json::from_slice(&fs::read(&marker)?)?;
        trust.check_signed(
            &head,
            "WITNESS_HEAD_V1",
            trust
                .witness_keys
                .get(&head.key_id)
                .context("untrusted authority head key")?,
        )?;
        ensure!(
            head.value.anchor_id == config.anchor_id,
            "authority anchor mismatch"
        );
        confirm_parent_durability(&marker)?;
        let mut paths = vec![];
        for entry in fs::read_dir(&events)? {
            let path = entry?.path();
            if path
                .extension()
                .and_then(|v| v.to_str())
                .and_then(|v| v.strip_prefix("tmp-"))
                .and_then(|v| Uuid::parse_str(v).ok())
                .is_some()
            {
                continue;
            }
            ensure!(
                path.is_file() && !fs::symlink_metadata(&path)?.file_type().is_symlink(),
                "invalid authority journal entry"
            );
            paths.push(path);
        }
        paths.sort();
        ensure!(!paths.is_empty(), "authority genesis missing");
        ensure!(
            head.value.sequence < paths.len() as u64,
            "authority history tail is missing"
        );
        let mut state = Snapshot::empty(config.anchor_id)?;
        let mut previous = "00".repeat(32);
        for (index, path) in paths.iter().enumerate() {
            ensure!(
                path.file_name().and_then(|s| s.to_str())
                    == Some(format!("{index:020}.json").as_str())
                    && fs::metadata(path)?.len() <= 1024 * 1024,
                "missing/oversized authority journal event"
            );
            let signed: Signed<Event> = serde_json::from_slice(&fs::read(path)?)?;
            let pin = trust
                .witness_keys
                .get(&signed.key_id)
                .context("untrusted witness journal signing key")?;
            trust.check_signed(&signed, "WITNESS_EVENT_V1", pin)?;
            let e = &signed.value;
            ensure!(
                e.anchor_id == config.anchor_id
                    && e.sequence == index as u64
                    && e.previous_hash == previous,
                "corrupt authority journal chain"
            );
            replay(&mut state, e)?;
            previous = event_hash(&signed)?;
            if index as u64 == head.value.sequence {
                ensure!(
                    previous == head.value.event_hash,
                    "authority head/journal disagreement"
                );
            }
            confirm_parent_durability(path)?;
        }
        // A crash after the immutable event but before head publication retains
        // its write-ahead tombstone. Never discard it as an unissued permit.
        if state.sequence > head.value.sequence {
            let recovered = trust.sign(
                "WITNESS_HEAD_V1",
                Head {
                    anchor_id: config.anchor_id,
                    sequence: state.sequence,
                    event_hash: previous.clone(),
                },
            )?;
            atomic_replace_state(&marker, &serde_json::to_vec(&recovered)?)?;
        }
        Ok(Self {
            config,
            trust,
            journal: Mutex::new(Journal {
                state,
                last_hash: previous,
                directory: events,
                poisoned: false,
                _lock: lock,
            }),
        })
    }
    fn commit(
        &self,
        j: &mut Journal,
        candidate: Snapshot,
        time: u64,
        transition: Transition,
    ) -> Result<()> {
        ensure!(
            !j.poisoned
                && candidate.sequence
                    == j.state
                        .sequence
                        .checked_add(1)
                        .context("journal exhausted")?,
            "authority unavailable/sequence conflict"
        );
        let event = Event {
            anchor_id: self.config.anchor_id,
            sequence: candidate.sequence,
            previous_hash: j.last_hash.clone(),
            time,
            transition,
        };
        let signed = self.trust.sign("WITNESS_EVENT_V1", event)?;
        let bytes = serde_json::to_vec(&signed)?;
        let next_hash = event_hash(&signed)?;
        let head = self.trust.sign(
            "WITNESS_HEAD_V1",
            Head {
                anchor_id: self.config.anchor_id,
                sequence: candidate.sequence,
                event_hash: next_hash.clone(),
            },
        )?;
        ensure!(
            bytes.len() <= 1024 * 1024,
            "authority event exceeds bounded transport/journal size"
        );
        if let Err(error) = atomic_create_secret(
            &j.directory.join(format!("{:020}.json", candidate.sequence)),
            &bytes,
        ) {
            j.poisoned = true;
            // No permitting response is released after an uncertain write.
            return Err(error.into());
        }
        if let Err(error) = atomic_replace_state(
            &j.directory
                .parent()
                .context("authority directory")?
                .join("initialized.json"),
            &serde_json::to_vec(&head)?,
        ) {
            // The immutable grant event already exists, including when head
            // replacement fails before rename. Fail all subsequent operations
            // until a restart replays and confirms its durable tombstone.
            j.poisoned = true;
            return Err(error.into());
        }
        j.last_hash = next_hash;
        j.state = candidate;
        Ok(())
    }
    pub async fn command(&self, command: Signed<Command>) -> Result<Signed<Acknowledgement>> {
        self.trust
            .check_signed(&command, "WITNESS_COMMAND_V1", &self.trust.lifecycle)?;
        let (mut j, time) =
            lock_fresh(&self.journal, |time| command.value.validate(time), now).await?;
        ensure!(!j.poisoned, "authority durability uncertain");
        match &command.value.action {
            CommandAction::RegisterClaim { evidence } => self.trust.claim_evidence(evidence)?,
            CommandAction::Enroll {
                evidence,
                node_keys,
            } => {
                self.trust.root_evidence(evidence)?;
                let p = self.trust.profile(&evidence.statement.wallet_class)?;
                for party in PARTIES {
                    ensure!(
                        node_keys
                            .get(party)
                            .is_some_and(|id| p.nodes[party].contains_key(id)),
                        "unenrolled class node identity"
                    );
                }
            }
            CommandAction::Prepare { ready, .. } => {
                let root = j
                    .state
                    .roots
                    .get(&command.value.root_identity)
                    .context("unknown original root")?;
                for report in ready {
                    self.trust.check_node(
                        &root.evidence.statement.wallet_class,
                        &report.value.party_id,
                        report,
                        "WITNESS_GENERATION_READY_V1",
                    )?;
                }
            }
            CommandAction::CloseUnreleased { attestations, .. } => {
                let root = j
                    .state
                    .roots
                    .get(&command.value.root_identity)
                    .context("unknown original root")?;
                for a in attestations {
                    self.trust.check_node(
                        &root.evidence.statement.wallet_class,
                        &a.value.request.value.party_id,
                        a,
                        "WITNESS_NO_RELEASE_V1",
                    )?;
                    self.trust.check_node(
                        &root.evidence.statement.wallet_class,
                        &a.value.request.value.party_id,
                        &a.value.request,
                        "WITNESS_PERMIT_REQUEST_V1",
                    )?;
                    self.trust.check_signed(
                        &a.value.authorization,
                        "WITNESS_CANCELLATION_V1",
                        &self.trust.lifecycle,
                    )?;
                }
            }
            _ => {}
        }
        let fingerprint = hash(&command.signing_message("WITNESS_COMMAND_V1")?);
        let mut candidate = j.state.clone();
        if candidate.command(&command.value)? {
            self.commit(
                &mut j,
                candidate,
                time,
                Transition::Command {
                    command: Box::new(command),
                },
            )?;
        }
        self.trust.sign(
            "WITNESS_ACK_V1",
            Acknowledgement {
                anchor_id: self.config.anchor_id,
                sequence: j.state.sequence,
                value_fingerprint: fingerprint,
            },
        )
    }
    pub async fn permit(&self, request: Signed<PermitRequest>) -> Result<Signed<Permit>> {
        let (mut j, time) =
            lock_fresh(&self.journal, |time| request.value.validate(time), now).await?;
        ensure!(!j.poisoned, "authority durability uncertain");
        let id = request
            .value
            .binding
            .authorized
            .intent
            .claim
            .root
            .identity()?;
        let r = j
            .state
            .roots
            .get(&id)
            .context("original root not enrolled")?;
        self.trust.check_node(
            &r.evidence.statement.wallet_class,
            &request.value.party_id,
            &request,
            "WITNESS_PERMIT_REQUEST_V1",
        )?;
        self.trust.authorized(
            &request.value.binding.authorized,
            &r.public_key_package,
            time,
        )?;
        let mut candidate = j.state.clone();
        let permit = candidate.permit(&request.value, &request.key_id, time)?;
        let response = self.trust.sign("WITNESS_PERMIT_V1", permit)?;
        self.commit(
            &mut j,
            candidate,
            time,
            Transition::Permit {
                request: Box::new(request),
            },
        )?;
        Ok(response)
    }
    pub async fn record(&self, report: Signed<PublicRound>) -> Result<Signed<Acknowledgement>> {
        let mut j = self.journal.lock().await;
        ensure!(!j.poisoned, "authority durability uncertain");
        let execution = j
            .state
            .executions
            .get(&report.value.execution_id)
            .context("unknown original execution")?;
        let class = &execution.binding.authorized.intent.claim.root.wallet_class;
        self.trust.check_node(
            class,
            &report.value.party_id,
            &report,
            "WITNESS_PUBLIC_ROUND_V1",
        )?;
        let fingerprint = hash(&report.signing_message("WITNESS_PUBLIC_ROUND_V1")?);
        let mut candidate = j.state.clone();
        if candidate.record(&report)? {
            self.commit(
                &mut j,
                candidate,
                now()?,
                Transition::PublicResult {
                    report: Box::new(report),
                },
            )?;
        }
        self.trust.sign(
            "WITNESS_ACK_V1",
            Acknowledgement {
                anchor_id: self.config.anchor_id,
                sequence: j.state.sequence,
                value_fingerprint: fingerprint,
            },
        )
    }
    pub async fn query(&self, request: Signed<Query>) -> Result<Signed<QueryReply>> {
        ensure!(
            request.value.anchor_id == self.config.anchor_id
                && hash_text(&request.value.challenge)
                && request.value.challenge != "00".repeat(32),
            "fresh original authority query required"
        );
        let j = self.journal.lock().await;
        ensure!(!j.poisoned, "authority durability uncertain");
        let r = j
            .state
            .roots
            .get(&request.value.root_identity)
            .context("unknown original root")?;
        if request.key_id == self.trust.lifecycle.key_id {
            self.trust
                .check_signed(&request, "WITNESS_QUERY_V1", &self.trust.lifecycle)?;
        } else {
            let profile = self.trust.profile(&r.evidence.statement.wallet_class)?;
            let party = PARTIES
                .iter()
                .find(|party| profile.nodes[**party].contains_key(&request.key_id))
                .context("untrusted query node")?;
            self.trust.check_node(
                &r.evidence.statement.wallet_class,
                party,
                &request,
                "WITNESS_QUERY_V1",
            )?;
        }
        let execution = if let Some(id) = request.value.execution_id {
            if let Some(e) = j.state.executions.get(&id) {
                ensure!(
                    e.root_identity == request.value.root_identity,
                    "query execution belongs to another root"
                );
                Some(ExecutionView {
                    binding_fingerprint: e.binding.identity()?,
                    status: e.status.clone(),
                    signature: e.signature.clone(),
                    reports: e.reports.clone(),
                })
            } else {
                None
            }
        } else {
            None
        };
        let abandoned = request
            .value
            .execution_id
            .is_some_and(|id| j.state.abandoned.contains_key(&id));
        let claim = if let Some(id) = request.value.claim_reservation_id {
            if let Some(e) = j.state.claims.get(&id) {
                ensure!(
                    e.statement.root == r.evidence.statement,
                    "query claim belongs to another original root"
                );
                Some(e.clone())
            } else {
                None
            }
        } else {
            None
        };
        let claim_issuance = request
            .value
            .claim_reservation_id
            .and_then(|id| j.state.claim_issuances.get(&id).cloned());
        self.trust.sign(
            "WITNESS_QUERY_REPLY_V1",
            QueryReply {
                query: request.value,
                sequence: j.state.sequence,
                root: RootView {
                    original: r.evidence.statement.clone(),
                    revision: r.revision,
                    phase: r.phase.clone(),
                    generation: r.generation.clone(),
                    public_key_package: r.public_key_package.clone(),
                    node_keys: r.node_keys.clone(),
                    prepared: r.prepared.as_ref().map(|p| p.generation.clone()),
                    next_claim_index: r.next_claim_index,
                },
                execution,
                abandoned,
                claim,
                lifecycle_key_id: Some(self.trust.lifecycle.key_id.clone()),
                claim_issuance,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    async fn expired_while_queued(validate: impl FnOnce(u64) -> Result<()> + Send + 'static) {
        let mutex = Arc::new(Mutex::new(()));
        let clock = Arc::new(AtomicU64::new(1000));
        let held = mutex.lock().await;
        let (started, waiting) = tokio::sync::oneshot::channel();
        let task = {
            let mutex = mutex.clone();
            let clock = clock.clone();
            tokio::spawn(async move {
                started.send(()).unwrap();
                lock_fresh(&mutex, validate, || Ok(clock.load(Ordering::SeqCst)))
                    .await
                    .is_err()
            })
        };
        waiting.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        clock.store(1011, Ordering::SeqCst);
        drop(held);
        assert!(
            task.await.unwrap(),
            "queued expired authorization must fail"
        );
    }

    #[tokio::test]
    async fn queued_lifecycle_command_cannot_outlive_its_authorization() {
        let command = Command {
            anchor_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            root_identity: "11".repeat(32),
            expected_revision: 1,
            expires_at: 1010,
            action: CommandAction::Freeze,
        };
        command.validate(1000).unwrap();
        expired_while_queued(move |time| command.validate(time)).await;
    }

    #[tokio::test]
    async fn queued_round_permit_cannot_outlive_its_fresh_challenge() {
        let request = crate::state::tests::admission_request();
        request.validate(1000).unwrap();
        expired_while_queued(move |time| request.validate(time)).await;
    }

    #[tokio::test]
    async fn queued_business_intent_expires_even_if_round_challenge_is_still_live() {
        let mut request = crate::state::tests::admission_request();
        request.expires_at = 1015;
        request.binding.authorized.intent.issued_at = 995;
        request.binding.authorized.intent.expires_at = 1005;
        let policy = wallet_mpc_protocol::solana_intent::ValidationPolicy {
            genesis_hash: request
                .binding
                .authorized
                .intent
                .claim
                .root
                .genesis_hash
                .clone(),
            version: 7,
            max_fee_lamports: 20000,
            max_rent_lamports: 3000000,
            max_lifetime_seconds: 120,
        };
        let package = request
            .binding
            .authorized
            .intent
            .claim
            .root
            .public_key_package
            .clone();
        request
            .binding
            .authorized
            .validate_shape(&package, 1000, &policy)
            .unwrap();
        request.validate(1011).unwrap();
        expired_while_queued(move |time| {
            request.validate(time)?;
            // Authority::permit passes this same post-lock admission time to
            // Trust::authorized; this independently tests its intent time gate.
            request
                .binding
                .authorized
                .validate_shape(&package, time, &policy)?;
            Ok(())
        })
        .await;
    }
}
