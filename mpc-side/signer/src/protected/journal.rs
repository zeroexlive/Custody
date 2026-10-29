//! Public execution tombstones, outside every private-share backup. No nonce or
//! private package is persisted here. A complete rollback of this independent
//! anchor/configuration/binary is outside the share-restore protection claim.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;
use wallet_mpc_protocol::witness::{hash, Permit, PermitRequest, PublicRound, Signed};
use wallet_mpc_storage::{atomic_create_secret, atomic_replace_state, confirm_parent_durability};
use wallet_mpc_transport::{PinnedIdentity, ReceiptIdentity};

#[derive(Clone, Copy)]
pub(super) struct Authorities<'a> {
    pub own: &'a PinnedIdentity,
    pub witness: &'a PinnedIdentity,
    pub lifecycle: Option<&'a PinnedIdentity>,
    pub party: &'a str,
}

pub(super) fn sign<T: Serialize>(
    identity: &ReceiptIdentity,
    domain: &str,
    value: T,
) -> Result<Signed<T>> {
    let key_id = identity.key_id();
    let signature = wallet_mpc_protocol::dkg::hex(
        &identity.sign(&Signed::unsigned_message(domain, &key_id, &value)?)?,
    );
    Ok(Signed {
        key_id,
        value,
        signature,
    })
}
pub(super) fn verify<T: Serialize>(
    pin: &PinnedIdentity,
    domain: &str,
    signed: &Signed<T>,
) -> Result<()> {
    ensure!(pin.key_id == signed.key_id, "pinned identity mismatch");
    pin.verify(&signed.signing_message(domain)?, &signed.signature_bytes()?)
}
pub(super) fn slot(id: Uuid, round: u16) -> String {
    format!("{id}:{round}")
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Change {
    Initialize,
    Request {
        request: Box<Signed<PermitRequest>>,
    },
    Consume {
        permit: Box<Signed<Permit>>,
    },
    Result {
        report: Box<Signed<PublicRound>>,
    },
    RefreshStart {
        start: Box<wallet_mpc_protocol::solana_generation::RefreshStart>,
    },
    RefreshReady {
        report: Box<Signed<wallet_mpc_protocol::witness::GenerationReady>>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    profile: String,
    sequence: u64,
    previous: String,
    change: Change,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    profile: String,
    sequence: u64,
    event_hash: String,
}
#[derive(Clone, Default)]
pub(super) struct Records {
    pub requests: BTreeMap<String, Signed<PermitRequest>>,
    pub consumed: BTreeMap<String, Signed<Permit>>,
    pub reports: BTreeMap<String, Signed<PublicRound>>,
    pub ceremonies: BTreeMap<Uuid, wallet_mpc_protocol::solana_generation::RefreshStart>,
    pub ready: BTreeMap<Uuid, Signed<wallet_mpc_protocol::witness::GenerationReady>>,
}
impl Records {
    fn apply(&mut self, change: &Change, authorities: Authorities<'_>) -> Result<()> {
        let Authorities {
            own,
            witness,
            lifecycle,
            party,
        } = authorities;
        match change {
            Change::RefreshStart { start } => {
                let life =
                    lifecycle.context("lifecycle mutation is disabled for this deployment")?;
                verify(life, "WITNESS_FROST_REFRESH_PLAN_V1", &start.plan)?;
                verify(witness, "WITNESS_QUERY_REPLY_V1", &start.frozen)?;
                start.validate_shape()?;
                let plan = &start.plan.value;
                ensure!(
                    plan.node_keys.get(party) == Some(&own.key_id)
                        && !self.ceremonies.contains_key(&plan.ceremony_id)
                        && !self
                            .ceremonies
                            .values()
                            .any(|c| c.plan.value.session_id == plan.session_id)
                        && !self.requests.values().any(|r| r
                            .value
                            .binding
                            .authorized
                            .intent
                            .crypto_execution_id
                            == plan.ceremony_id
                            || r.value.binding.authorized.intent.session_id == plan.session_id),
                    "ceremony/identity already consumed or disagrees"
                );
                self.ceremonies.insert(plan.ceremony_id, (**start).clone());
            }
            Change::RefreshReady { report } => {
                verify(own, "WITNESS_GENERATION_READY_V1", report)?;
                let r = &report.value;
                let start = self
                    .ceremonies
                    .get(&r.generation.ceremony_id)
                    .context("missing original refresh start")?;
                let p = &start.plan.value;
                ensure!(
                    !self.ready.contains_key(&p.ceremony_id)
                        && r.party_id == party
                        && r.root_identity == p.root.identity()?
                        && r.previous_generation == p.previous
                        && r.generation.epoch == p.next_epoch
                        && r.generation.public_key_package_sha256 == hash(&r.public_key_package)
                        && r.public_key_package != p.previous_public_key_package,
                    "original durable refresh agreement mismatch"
                );
                wallet_mpc_protocol::sign::public_package(
                    &r.public_key_package,
                    &p.root.group_public_key,
                )?;
                self.ready.insert(p.ceremony_id, (**report).clone());
            }
            Change::Initialize => ensure!(
                self.requests.is_empty() && self.consumed.is_empty() && self.reports.is_empty(),
                "invalid local genesis"
            ),
            Change::Request { request } => {
                verify(own, "WITNESS_PERMIT_REQUEST_V1", request)?;
                ensure!(request.value.party_id == party, "foreign private request");
                ensure!(
                    !self
                        .ceremonies
                        .contains_key(&request.value.binding.authorized.intent.crypto_execution_id)
                        && !self.ceremonies.values().any(|c| c.plan.value.session_id
                            == request.value.binding.authorized.intent.session_id),
                    "signing identifiers belong to a lifecycle ceremony"
                );
                let key = slot(
                    request.value.binding.authorized.intent.crypto_execution_id,
                    request.value.round,
                );
                ensure!(
                    !self.requests.contains_key(&key),
                    "private round request already reserved"
                );
                self.requests.insert(key, (**request).clone());
            }
            Change::Consume { permit } => {
                verify(witness, "WITNESS_PERMIT_V1", permit)?;
                let request = &permit.value.request;
                let key = slot(
                    request.binding.authorized.intent.crypto_execution_id,
                    request.round,
                );
                ensure!(
                    !self.consumed.contains_key(&key)
                        && self.requests.get(&key).is_some_and(|r| r.value == *request),
                    "private permission original request mismatch/replay"
                );
                self.consumed.insert(key, (**permit).clone());
            }
            Change::Result { report } => {
                verify(own, "WITNESS_PUBLIC_ROUND_V1", report)?;
                let p = &report.value;
                let key = slot(p.execution_id, p.round);
                let request = &self
                    .consumed
                    .get(&key)
                    .context("result lacks consumed permission")?
                    .value
                    .request;
                ensure!(
                    p.party_id == party
                        && p.anchor_id == request.anchor_id
                        && p.binding_fingerprint == request.binding.identity()?
                        && !self.reports.contains_key(&key),
                    "original public round mismatch"
                );
                self.reports.insert(key, (**report).clone());
            }
        }
        Ok(())
    }
}
pub(super) struct Journal {
    pub records: Records,
    directory: PathBuf,
    profile: String,
    sequence: u64,
    last_hash: String,
    pub poisoned: bool,
    _lock: File,
}
impl Journal {
    pub fn open(
        directory: &Path,
        profile: String,
        identity: &ReceiptIdentity,
        authorities: Authorities<'_>,
        initialize: bool,
    ) -> Result<Self> {
        let Authorities { own, .. } = authorities;
        fs::create_dir_all(directory)?;
        ensure!(
            fs::symlink_metadata(directory)?.file_type().is_dir(),
            "protected anchor cannot be a symlink"
        );
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(directory.join("node.lock"))?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "protected anchor already owned by a process"
        );
        let events = directory.join("events");
        let marker = directory.join("initialized.json");
        if initialize {
            ensure!(
                !events.exists() && !marker.exists(),
                "protected anchor initialization cannot reset history"
            );
            fs::create_dir(&events)?;
            let event = sign(
                identity,
                "WITNESS_NODE_EVENT_V1",
                Event {
                    profile: profile.clone(),
                    sequence: 0,
                    previous: "00".repeat(32),
                    change: Change::Initialize,
                },
            )?;
            let event_hash = hash(&serde_json::to_vec(&serde_json::to_value(&event)?)?);
            atomic_create_secret(
                &events.join(format!("{:020}.json", 0)),
                &serde_json::to_vec(&event)?,
            )?;
            let head = sign(
                identity,
                "WITNESS_NODE_HEAD_V1",
                Head {
                    profile: profile.clone(),
                    sequence: 0,
                    event_hash,
                },
            )?;
            atomic_create_secret(&marker, &serde_json::to_vec(&head)?)?;
        }
        ensure!(
            fs::symlink_metadata(&marker).is_ok_and(|m| m.file_type().is_file() && m.len() <= 4096)
                && fs::symlink_metadata(&events).is_ok_and(|m| m.file_type().is_dir()),
            "protected history missing; share restore cannot initialize it"
        );
        let head: Signed<Head> = serde_json::from_slice(&fs::read(&marker)?)?;
        verify(own, "WITNESS_NODE_HEAD_V1", &head)?;
        ensure!(head.value.profile == profile, "protected profile changed");
        let mut paths = vec![];
        for e in fs::read_dir(&events)? {
            let p = e?.path();
            if p.extension()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix("tmp-"))
                .and_then(|s| Uuid::parse_str(s).ok().filter(|u| u.to_string() == s))
                .is_some()
            {
                continue;
            }
            ensure!(
                fs::symlink_metadata(&p)?.file_type().is_file(),
                "invalid protected journal entry"
            );
            paths.push(p);
        }
        paths.sort();
        ensure!(
            head.value.sequence < paths.len() as u64,
            "protected history tail missing"
        );
        let mut records = Records::default();
        let mut last_hash = "00".repeat(32);
        let mut sequence = 0;
        for (index, path) in paths.iter().enumerate() {
            ensure!(
                path.file_name().and_then(|s| s.to_str())
                    == Some(format!("{index:020}.json").as_str())
                    && fs::metadata(path)?.len() <= 1024 * 1024,
                "protected journal gap/bounds"
            );
            let event: Signed<Event> = serde_json::from_slice(&fs::read(path)?)?;
            verify(own, "WITNESS_NODE_EVENT_V1", &event)?;
            let e = &event.value;
            ensure!(
                e.profile == profile
                    && e.sequence == index as u64
                    && e.previous == last_hash
                    && (index != 0 || matches!(e.change, Change::Initialize))
                    && (index == 0 || !matches!(e.change, Change::Initialize)),
                "protected journal identity/sequence"
            );
            records.apply(&e.change, authorities)?;
            last_hash = hash(&serde_json::to_vec(&serde_json::to_value(&event)?)?);
            sequence = e.sequence;
            if sequence == head.value.sequence {
                ensure!(
                    last_hash == head.value.event_hash,
                    "protected head mismatch"
                );
            }
            confirm_parent_durability(path)?;
        }
        if sequence > head.value.sequence {
            let head = sign(
                identity,
                "WITNESS_NODE_HEAD_V1",
                Head {
                    profile: profile.clone(),
                    sequence,
                    event_hash: last_hash.clone(),
                },
            )?;
            atomic_replace_state(&marker, &serde_json::to_vec(&head)?)?;
        }
        confirm_parent_durability(&marker)?;
        Ok(Self {
            records,
            directory: directory.into(),
            profile,
            sequence,
            last_hash,
            poisoned: false,
            _lock: lock,
        })
    }
    pub fn append(
        &mut self,
        change: Change,
        identity: &ReceiptIdentity,
        authorities: Authorities<'_>,
    ) -> Result<()> {
        ensure!(!self.poisoned, "protected durability uncertain");
        let mut candidate = self.records.clone();
        candidate.apply(&change, authorities)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .context("protected journal exhausted")?;
        let event = sign(
            identity,
            "WITNESS_NODE_EVENT_V1",
            Event {
                profile: self.profile.clone(),
                sequence,
                previous: self.last_hash.clone(),
                change,
            },
        )?;
        let last_hash = hash(&serde_json::to_vec(&serde_json::to_value(&event)?)?);
        let bytes = serde_json::to_vec(&event)?;
        ensure!(bytes.len() <= 1024 * 1024, "protected event bounds");
        let head = sign(
            identity,
            "WITNESS_NODE_HEAD_V1",
            Head {
                profile: self.profile.clone(),
                sequence,
                event_hash: last_hash.clone(),
            },
        )?;
        // Poison on every write error, including errors after an immutable event
        // but before head publication. Restart conservatively replays the tail.
        self.poisoned = true;
        atomic_create_secret(
            &self
                .directory
                .join("events")
                .join(format!("{sequence:020}.json")),
            &bytes,
        )?;
        atomic_replace_state(
            &self.directory.join("initialized.json"),
            &serde_json::to_vec(&head)?,
        )?;
        self.records = candidate;
        self.sequence = sequence;
        self.last_hash = last_hash;
        self.poisoned = false;
        Ok(())
    }
}
