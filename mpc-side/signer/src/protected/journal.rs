//! Public execution tombstones, outside every private-share backup. No nonce or
//! private package is persisted here. A complete rollback of this independent
//! anchor/configuration/binary is outside the share-restore protection claim.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;
use wallet_mpc_protocol::sign::decode_hex;
use wallet_mpc_protocol::witness::{hash, Permit, PermitRequest, PublicRound, Signed};
use wallet_mpc_storage::{atomic_create_secret, atomic_replace_state, confirm_parent_durability};
use wallet_mpc_transport::{PinnedIdentity, ReceiptIdentity};

#[derive(Clone, Copy)]
pub(super) struct Authorities<'a> {
    pub own: &'a PinnedIdentity,
    pub witness: &'a PinnedIdentity,
    pub lifecycle: Option<&'a PinnedIdentity>,
    pub party: &'a str,
    pub profile: &'a str,
    pub policy: &'a super::policy::Policy,
    pub class: &'a str,
    pub migration_lifecycle: Option<&'a PinnedIdentity>,
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
    ProfileMigrationGenesis {
        admission: Box<wallet_mpc_protocol::solana_profile_migration::SuccessorAdmission>,
    },
    ProfileMigrationFence {
        admission: Box<wallet_mpc_protocol::solana_profile_migration::SourceAdmission>,
    },
    Request {
        request: Box<Signed<PermitRequest>>,
    },
    Consume {
        permit: Box<Signed<Permit>>,
    },
    Result {
        report: Box<Signed<PublicRound>>,
    },
    CurrentClaimQuery {
        lease: Box<wallet_mpc_protocol::solana_claim_authority::ClaimQueryLease>,
    },
    CurrentClaimReport {
        grant: Box<wallet_mpc_protocol::solana_claim_authority::CurrentClaimGrant>,
    },
    RefreshStart {
        start: Box<wallet_mpc_protocol::solana_generation::RefreshStart>,
    },
    RefreshReady {
        report: Box<Signed<wallet_mpc_protocol::witness::GenerationReady>>,
    },
    RepairStart {
        start: Box<wallet_mpc_protocol::solana_recovery::ReplacementStart>,
    },
    RepairReady {
        report: Box<Signed<wallet_mpc_protocol::solana_recovery::RepairReady>>,
    },
    ReplacementRefreshStart {
        start: Box<wallet_mpc_protocol::solana_recovery::ReplacementStart>,
    },
    Cancel {
        attestation: Box<Signed<wallet_mpc_protocol::witness::NoRelease>>,
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
type Head = wallet_mpc_protocol::solana_profile_migration::MigrationSourceHead;
#[derive(Clone, Default)]
pub(super) struct Records {
    pub current_claim_queries:
        BTreeMap<String, wallet_mpc_protocol::solana_claim_authority::ClaimQueryLease>,
    pub current_claim_grants:
        BTreeMap<String, wallet_mpc_protocol::solana_claim_authority::CurrentClaimGrant>,
    pub profile_migration_source:
        Option<wallet_mpc_protocol::solana_profile_migration::SourceAdmission>,
    pub profile_migration_fence:
        Option<wallet_mpc_protocol::solana_profile_migration::SourceAdmission>,
    pub requests: BTreeMap<String, Signed<PermitRequest>>,
    pub consumed: BTreeMap<String, Signed<Permit>>,
    pub reports: BTreeMap<String, Signed<PublicRound>>,
    pub ceremonies: BTreeMap<Uuid, wallet_mpc_protocol::solana_generation::RefreshStart>,
    pub ready: BTreeMap<Uuid, Signed<wallet_mpc_protocol::witness::GenerationReady>>,
    pub cancelled: BTreeMap<Uuid, Signed<wallet_mpc_protocol::witness::NoRelease>>,
    pub repairs: BTreeMap<Uuid, wallet_mpc_protocol::solana_recovery::ReplacementStart>,
    pub repaired: BTreeMap<Uuid, Signed<wallet_mpc_protocol::solana_recovery::RepairReady>>,
    pub replacement_refresh: BTreeMap<Uuid, wallet_mpc_protocol::solana_recovery::ReplacementStart>,
}
impl Records {
    pub fn current_claim_compatible(
        &self,
        claim: &wallet_mpc_protocol::solana_provisioning::Claim,
    ) -> Result<()> {
        for grant in self.current_claim_grants.values() {
            let original = &grant.report.statement;
            if original.reservation_id == claim.reservation_id
                || (original.root == claim.root
                    && (original.index == claim.index
                        || original.owner_slot()? == claim.owner_slot()?
                        || original.retry_slot()? == claim.retry_slot()?))
            {
                ensure!(
                    original == claim,
                    "current Claim owner/index/retry/reservation is immutable"
                );
            }
        }
        Ok(())
    }

    pub fn refresh_plan(
        &self,
        ceremony: Uuid,
    ) -> Result<&wallet_mpc_protocol::solana_generation::RefreshPlan> {
        if let Some(start) = self.ceremonies.get(&ceremony) {
            return Ok(&start.plan.value);
        }
        Ok(&self
            .replacement_refresh
            .get(&ceremony)
            .context("missing original refresh start")?
            .plan
            .value
            .refresh)
    }
    fn repair_id_reserved(&self, id: Uuid) -> bool {
        self.repairs.values().any(|start| {
            let p = &start.plan.value;
            [
                p.repair_session_id,
                p.repair_ceremony_id,
                p.refresh.session_id,
                p.refresh.ceremony_id,
                p.recipient_anchor_id,
            ]
            .contains(&id)
        })
    }
    fn migration_id_reserved(&self, id: Uuid) -> bool {
        self.profile_migration_source
            .as_ref()
            .or(self.profile_migration_fence.as_ref())
            .is_some_and(|a| {
                let p = a.fence.value.approvals.plan();
                [p.migration_id, p.new_anchor_id].contains(&id)
            })
    }
    fn private_id_reserved(&self, id: Uuid) -> bool {
        self.migration_id_reserved(id)
            || self.repair_id_reserved(id)
            || self
                .ceremonies
                .values()
                .any(|c| c.plan.value.session_id == id || c.plan.value.ceremony_id == id)
            || self.requests.values().any(|r| {
                let i = &r.value.binding.authorized.intent;
                i.session_id == id || i.crypto_execution_id == id
            })
    }
    fn apply(&mut self, change: &Change, authorities: Authorities<'_>) -> Result<()> {
        let Authorities {
            own,
            witness,
            lifecycle,
            party,
            profile,
            policy,
            class,
            migration_lifecycle,
        } = authorities;
        ensure!(
            self.profile_migration_fence.is_none()
                || matches!(change, Change::ProfileMigrationGenesis { .. }),
            "original profile permanently fenced; no valid journal suffix allowed"
        );
        match change {
            Change::CurrentClaimQuery { lease } => {
                let life = lifecycle
                    .context("current Claim receipts require explicit Lifecycle authority")?;
                lease.validate_shape(party)?;
                policy.current_claim_approval(
                    class,
                    &lease.approval,
                    life,
                    lease.issued_at,
                    false,
                )?;
                verify(own, "WITNESS_QUERY_V1", &lease.query)?;
                self.current_claim_compatible(&lease.approval.statement)?;
                ensure!(
                    !self
                        .current_claim_queries
                        .contains_key(&lease.query.value.challenge),
                    "current Claim challenge cannot be reused"
                );
                self.current_claim_queries
                    .insert(lease.query.value.challenge.clone(), lease.as_ref().clone());
            }
            Change::CurrentClaimReport { grant } => {
                let lease = self
                    .current_claim_queries
                    .get(&grant.lease_challenge)
                    .context("original current Claim challenge required")?;
                let life = lifecycle
                    .context("current Claim receipts require explicit Lifecycle authority")?;
                policy.current_claim_approval(
                    class,
                    &lease.approval,
                    life,
                    grant.granted_at,
                    false,
                )?;
                verify(witness, "WITNESS_QUERY_REPLY_V1", &grant.witness)?;
                lease.validate_new_report(&grant.witness.value, party, grant.granted_at)?;
                let report = &grant.report;
                ensure!(
                    report.statement == lease.approval.statement
                        && report.party_id == party
                        && report.durable,
                    "exact own current Claim durable receipt required"
                );
                own.verify(
                    &wallet_mpc_protocol::solana_claim_authority::receipt_message(
                        &lease.approval.authority,
                        &report.statement,
                        party,
                    )?,
                    &decode_hex(&report.signer_signature)
                        .context("current Claim signature encoding")?,
                )?;
                let key = lease.approval.authority.identity(&report.statement.root)?
                    + ":"
                    + &report.statement.reservation_id.to_string();
                self.current_claim_compatible(&report.statement)?;
                ensure!(
                    !self.current_claim_grants.contains_key(&key),
                    "original current Claim report cannot change"
                );
                if let Some(pin) = grant.witness.value.node_profiles.get(party) {
                    pin.validate_shape()?;
                    ensure!(
                        pin.node_key_id == own.key_id && pin.profile_sha256 == profile,
                        "current Claim report requires exact witness profile pin"
                    );
                }
                self.current_claim_grants
                    .insert(key, grant.as_ref().clone());
            }
            Change::ProfileMigrationGenesis { admission } => {
                ensure!(
                    self.profile_migration_source.is_none(),
                    "migration genesis already imported"
                );
                let source = self.profile_migration_fence.as_ref().context(
                    "successor genesis requires completely verified terminal predecessor records",
                )?;
                admission.validate_shape(source)?;
                let p = source.fence.value.approvals.plan();
                ensure!(
                    p.new_profile_sha256 == profile
                        && p.party_id == party
                        && p.node_key_id == own.key_id
                        && lifecycle.is_some_and(|k| k.key_id == p.new_lifecycle_key_id),
                    "exact approved successor fingerprint and Life required"
                );
                let head: Signed<Head> = serde_json::from_str(&admission.source_head_json)?;
                verify(own, "WITNESS_NODE_HEAD_V1", &head)?;
                for (root, lease) in &admission.queries {
                    verify(own, "WITNESS_PROFILE_MIGRATION_QUERY_LEASE_V1", lease)?;
                    verify(own, "WITNESS_QUERY_V1", &lease.value.query)?;
                    verify(witness, "WITNESS_QUERY_REPLY_V1", &admission.frozen[root])?;
                }
                self.profile_migration_source = self.profile_migration_fence.take();
            }
            Change::ProfileMigrationFence { admission } => {
                use wallet_mpc_protocol::solana_profile_migration::FENCE_DOMAIN;
                admission.validate_shape()?;
                let p = admission.fence.value.approvals.plan();
                ensure!(
                    !self.private_id_reserved(p.migration_id)
                        && !self.private_id_reserved(p.new_anchor_id),
                    "migration identifiers already belong to original private history"
                );
                ensure!(
                    p.old_profile_sha256 == profile
                        && p.party_id == party
                        && p.node_key_id == own.key_id
                        && p.cohort[0].original.wallet_class == class
                        && p.cohort[0].original.genesis_hash == policy.limits.genesis_hash,
                    "exact original profile/cohort/class/network source fence required"
                );
                policy.migration_approvals(
                    &admission.fence.value.approvals,
                    migration_lifecycle.context(
                        "terminal migration requires explicit offline successor context",
                    )?,
                    false,
                )?;
                verify(own, FENCE_DOMAIN, &admission.fence)?;
                let original_head: Signed<Head> =
                    serde_json::from_str(&admission.original_head_json)?;
                verify(own, "WITNESS_NODE_HEAD_V1", &original_head)?;
                for (root, lease) in &admission.queries {
                    verify(own, "WITNESS_PROFILE_MIGRATION_QUERY_LEASE_V1", lease)?;
                    verify(own, "WITNESS_QUERY_V1", &lease.value.query)?;
                    verify(witness, "WITNESS_QUERY_REPLY_V1", &admission.frozen[root])?;
                }
                self.profile_migration_fence = Some((**admission).clone());
            }
            Change::Cancel { attestation } => {
                let proof = &attestation.value;
                let request = &proof.request;
                verify(own, "WITNESS_NO_RELEASE_V1", attestation)?;
                verify(own, "WITNESS_PERMIT_REQUEST_V1", request)?;
                verify(
                    lifecycle.context("lifecycle cancellation disabled")?,
                    "WITNESS_CANCELLATION_V1",
                    &proof.authorization,
                )?;
                proof.authorization.value.matches(request)?;
                let id = request.value.binding.authorized.intent.crypto_execution_id;
                let key = slot(id, 2);
                ensure!(
                    request.value.party_id == party
                        && self.requests.get(&key) == Some(request)
                        && !self.reports.contains_key(&key)
                        && !self.cancelled.contains_key(&id),
                    "original R2 request required; a durable result can never attest no release"
                );
                self.cancelled.insert(id, (**attestation).clone());
            }
            Change::RepairStart { start } => {
                let life = lifecycle.context("lifecycle repair disabled")?;
                verify(life, "WITNESS_FROST_REPLACEMENT_PLAN_V1", &start.plan)?;
                verify(witness, "WITNESS_QUERY_REPLY_V1", &start.frozen)?;
                start.validate_shape()?;
                let p = &start.plan.value;
                let expected_key = if p.party_id == party {
                    ensure!(
                        p.recipient_profile_sha256 == profile,
                        "exact replacement profile required"
                    );
                    &p.refresh.node_keys[party]
                } else {
                    &p.previous_node_keys[party]
                };
                let ids = [
                    p.repair_session_id,
                    p.repair_ceremony_id,
                    p.refresh.session_id,
                    p.refresh.ceremony_id,
                    p.recipient_anchor_id,
                ];
                ensure!(
                    expected_key == &own.key_id
                        && ids.iter().all(|id| !self.private_id_reserved(*id)),
                    "original repair identity/ceremony already consumed or mismatched"
                );
                self.repairs.insert(p.repair_ceremony_id, (**start).clone());
            }
            Change::RepairReady { report } => {
                verify(own, "WITNESS_FROST_REPAIR_READY_V1", report)?;
                let r = &report.value;
                let p = &self
                    .repairs
                    .get(&r.repair_ceremony_id)
                    .context("missing original private repair start")?
                    .plan
                    .value;
                ensure!(
                    party == p.party_id
                        && !self.repaired.contains_key(&p.repair_ceremony_id)
                        && r.root_identity == p.refresh.root.identity()?
                        && r.plan_identity == p.identity()?
                        && r.generation == p.refresh.previous
                        && r.party_id == party,
                    "exact recipient one-share staging provenance required"
                );
                self.repaired
                    .insert(p.repair_ceremony_id, (**report).clone());
            }
            Change::ReplacementRefreshStart { start } => {
                let life = lifecycle.context("lifecycle repair disabled")?;
                verify(life, "WITNESS_FROST_REPLACEMENT_PLAN_V1", &start.plan)?;
                verify(witness, "WITNESS_QUERY_REPLY_V1", &start.frozen)?;
                start.validate_shape()?;
                let p = &start.plan.value;
                let original = self
                    .repairs
                    .get(&p.repair_ceremony_id)
                    .context("missing original repair ceremony")?;
                ensure!(
                    original.plan.value == *p
                        && p.refresh.node_keys.get(party) == Some(&own.key_id)
                        && !self.ceremonies.contains_key(&p.refresh.ceremony_id)
                        && !self
                            .replacement_refresh
                            .contains_key(&p.refresh.ceremony_id)
                        && (party != p.party_id
                            || self.repaired.contains_key(&p.repair_ceremony_id)),
                    "exact reserved repair then fresh replacement refresh required"
                );
                self.replacement_refresh
                    .insert(p.refresh.ceremony_id, (**start).clone());
            }
            Change::RefreshStart { start } => {
                let life =
                    lifecycle.context("lifecycle mutation is disabled for this deployment")?;
                verify(life, "WITNESS_FROST_REFRESH_PLAN_V1", &start.plan)?;
                verify(witness, "WITNESS_QUERY_REPLY_V1", &start.frozen)?;
                start.validate_shape()?;
                let plan = &start.plan.value;
                if start.frozen.value.refresh.is_some() {
                    start.validate_reservation()?;
                    ensure!(!self.private_id_reserved(plan.session_id)
                        && !self.private_id_reserved(plan.ceremony_id),
                        "new refresh identifiers cannot cross-reuse any original private identifier");
                }
                ensure!(
                    !self.repair_id_reserved(plan.ceremony_id)
                        && !self.repair_id_reserved(plan.session_id)
                        && !self.migration_id_reserved(plan.ceremony_id)
                        && !self.migration_id_reserved(plan.session_id),
                    "ordinary refresh identifiers belong to a reserved replacement"
                );
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
                let p = self.refresh_plan(r.generation.ceremony_id)?;
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
                let ceremony = p.ceremony_id;
                self.ready.insert(ceremony, (**report).clone());
            }
            Change::Initialize => ensure!(
                self.requests.is_empty() && self.consumed.is_empty() && self.reports.is_empty(),
                "invalid local genesis"
            ),
            Change::Request { request } => {
                let intent = &request.value.binding.authorized.intent;
                ensure!(
                    !self.repair_id_reserved(intent.crypto_execution_id)
                        && !self.repair_id_reserved(intent.session_id)
                        && !self.migration_id_reserved(intent.crypto_execution_id)
                        && !self.migration_id_reserved(intent.session_id),
                    "private signing identifiers belong to replacement history"
                );
                verify(own, "WITNESS_PERMIT_REQUEST_V1", request)?;
                ensure!(request.value.party_id == party, "foreign private request");
                ensure!(
                    !self
                        .cancelled
                        .contains_key(&request.value.binding.authorized.intent.crypto_execution_id),
                    "execution permanently cancelled"
                );
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
                ensure!(
                    !self
                        .cancelled
                        .contains_key(&request.binding.authorized.intent.crypto_execution_id),
                    "execution permanently cancelled"
                );
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
                ensure!(
                    !self.cancelled.contains_key(&p.execution_id),
                    "execution permanently cancelled"
                );
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
    pub(super) fn original_head_json(&self, own: &PinnedIdentity) -> Result<String> {
        Ok(String::from_utf8(self.signed_head_bytes(own)?)?)
    }
    pub(super) fn public_head(&self, own: &PinnedIdentity) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.signed_head_bytes(own)?)?)
    }
    fn signed_head_bytes(&self, own: &PinnedIdentity) -> Result<Vec<u8>> {
        ensure!(!self.poisoned, "original public head durability uncertain");
        let path = self.directory.join("initialized.json");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        ensure!(
            file.metadata()
                .is_ok_and(|m| m.file_type().is_file() && m.len() <= 4096),
            "bounded original signed head required"
        );
        let mut bytes = vec![];
        file.take(4097).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 4096,
            "original signed head grew beyond bounds"
        );
        let head: Signed<Head> = serde_json::from_slice(&bytes)?;
        verify(own, "WITNESS_NODE_HEAD_V1", &head)?;
        ensure!(
            head.value.profile == self.profile
                && head.value.sequence == self.sequence
                && head.value.event_hash == self.last_hash,
            "original public head changed after verified open"
        );
        Ok(bytes)
    }
    pub fn open(
        directory: &Path,
        profile: String,
        identity: &ReceiptIdentity,
        authorities: Authorities<'_>,
        initialize: bool,
    ) -> Result<Self> {
        Self::open_inner(
            directory,
            profile,
            identity,
            authorities,
            initialize,
            None,
            None,
        )
    }
    /// The caller must keep the verified predecessor journal locked for the
    /// lifetime of this journal; imported maps are never reconstructed from a
    /// signed inventory or a successor's assertions.
    pub(super) fn open_successor(
        directory: &Path,
        profile: String,
        identity: &ReceiptIdentity,
        authorities: Authorities<'_>,
        predecessor: &(Records, String),
        initialize: Option<wallet_mpc_protocol::solana_profile_migration::SuccessorAdmission>,
    ) -> Result<Self> {
        Self::open_inner(
            directory,
            profile,
            identity,
            authorities,
            initialize.is_some(),
            Some(predecessor),
            initialize,
        )
    }
    fn open_inner(
        directory: &Path,
        profile: String,
        identity: &ReceiptIdentity,
        authorities: Authorities<'_>,
        initialize: bool,
        predecessor: Option<&(Records, String)>,
        genesis: Option<wallet_mpc_protocol::solana_profile_migration::SuccessorAdmission>,
    ) -> Result<Self> {
        let Authorities { own, .. } = authorities;
        let initial = predecessor.map_or_else(Records::default, |(records, _)| records.clone());
        let genesis_matches = |event: &Event| -> Result<()> {
            match (&event.change, predecessor) {
                (Change::ProfileMigrationGenesis { admission }, Some((_, source_head))) => {
                    ensure!(&admission.source_head_json == source_head,
                        "successor genesis must link the exact fully replayed final source head bytes");
                }
                (Change::Initialize, None) => {}
                _ => {
                    anyhow::bail!("journal genesis does not match its verified predecessor context")
                }
            }
            Ok(())
        };
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
        if initialize && !marker.exists() {
            ensure!(
                predecessor.is_some() || !events.exists(),
                "protected anchor initialization cannot reset history"
            );
            if !events.exists() {
                fs::create_dir(&events)?;
            }
            ensure!(
                fs::symlink_metadata(&events)?.file_type().is_dir(),
                "invalid events directory"
            );
            let path = events.join(format!("{:020}.json", 0));
            let entries: Vec<_> = fs::read_dir(&events)?.collect::<std::io::Result<_>>()?;
            ensure!(
                entries.is_empty()
                    || (predecessor.is_some() && entries.len() == 1 && entries[0].path() == path),
                "uncertain genesis cannot discard existing history"
            );
            let event: Signed<Event> = if entries.is_empty() {
                let change = if let Some(admission) = genesis {
                    let time = super::now()?;
                    ensure!(
                        admission
                            .queries
                            .values()
                            .all(|q| q.value.issued_at <= time && time < q.value.expires_at)
                            && admission.initialized_at <= time
                            && time - admission.initialized_at <= 15,
                        "successor query leases expired before initialization"
                    );
                    Change::ProfileMigrationGenesis {
                        admission: Box::new(admission),
                    }
                } else {
                    Change::Initialize
                };
                let e = Event {
                    profile: profile.clone(),
                    sequence: 0,
                    previous: "00".repeat(32),
                    change,
                };
                genesis_matches(&e)?;
                initial.clone().apply(&e.change, authorities)?;
                let signed = sign(identity, "WITNESS_NODE_EVENT_V1", e)?;
                let bytes = serde_json::to_vec(&signed)?;
                ensure!(bytes.len() <= 1024 * 1024, "protected genesis event bounds");
                atomic_create_secret(&path, &bytes)?;
                signed
            } else {
                ensure!(
                    fs::symlink_metadata(&path)
                        .is_ok_and(|m| m.file_type().is_file() && m.len() <= 1024 * 1024),
                    "bounded original orphan genesis required"
                );
                let signed: Signed<Event> = serde_json::from_slice(&fs::read(&path)?)?;
                verify(own, "WITNESS_NODE_EVENT_V1", &signed)?;
                ensure!(
                    signed.value.profile == profile
                        && signed.value.sequence == 0
                        && signed.value.previous == "00".repeat(32),
                    "original orphan genesis mismatch"
                );
                genesis_matches(&signed.value)?;
                initial.clone().apply(&signed.value.change, authorities)?;
                confirm_parent_durability(&path)?;
                signed
            };
            let event_hash = hash(&serde_json::to_vec(&serde_json::to_value(&event)?)?);
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
        } else if initialize {
            ensure!(
                predecessor.is_some(),
                "protected anchor initialization cannot reset history"
            );
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
        let mut records = initial;
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
                    && (index == 0
                        || !matches!(
                            e.change,
                            Change::Initialize | Change::ProfileMigrationGenesis { .. }
                        )),
                "protected journal identity/sequence"
            );
            if index == 0 {
                genesis_matches(e)?;
            }
            if let Change::ProfileMigrationFence { admission } = &e.change {
                let p = admission.fence.value.approvals.plan();
                ensure!(
                    p.source_sequence.checked_add(1) == Some(e.sequence)
                        && p.source_event_hash == e.previous,
                    "terminal profile intent must follow its exact original signed source head"
                );
            }
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
        ensure!(
            !matches!(
                change,
                Change::Initialize | Change::ProfileMigrationGenesis { .. }
            ),
            "journal genesis cannot be appended as a suffix"
        );
        if let Change::ProfileMigrationFence { admission } = &change {
            let p = admission.fence.value.approvals.plan();
            let time = super::now()?;
            p.validate(time)?;
            ensure!(
                p.source_sequence == self.sequence && p.source_event_hash == self.last_hash,
                "original source head changed before terminal migration fence"
            );
            ensure!(
                self.original_head_json(authorities.own)? == admission.original_head_json,
                "terminal intent must retain original head bytes without rewriting them"
            );
            let Authorities {
                policy,
                migration_lifecycle,
                ..
            } = authorities;
            policy.migration_approvals(
                &admission.fence.value.approvals,
                migration_lifecycle.context("offline successor Life context required")?,
                true,
            )?;
            ensure!(
                admission
                    .queries
                    .values()
                    .all(|q| q.value.issued_at <= time && time < q.value.expires_at),
                "original own migration query leases expired before terminal fence"
            );
        }
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
