//! Explicit same-identity successor configuration. Source import and offline
//! execution are intentionally separate from normal protected initialization.
use super::Profile;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use wallet_mpc_protocol::{solana_profile_migration::MigrationPlan, witness::hash_text};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub migration_id: Uuid,
    pub anchor_id: Uuid,
    pub source_profile: PathBuf,
    pub source_profile_sha256: String,
    pub source_anchor: PathBuf,
    pub source_sequence: u64,
    pub source_event_hash: String,
    pub cohort: Vec<String>,
}

struct Source {
    old: Profile,
    old_hash: String,
    new: Option<(Profile, String)>,
    identity: wallet_mpc_transport::ReceiptIdentity,
    own: wallet_mpc_transport::PinnedIdentity,
    witness: wallet_mpc_transport::PinnedIdentity,
    life: Option<wallet_mpc_transport::PinnedIdentity>,
    policy: super::policy::Policy,
    journal: super::journal::Journal,
}
impl Source {
    fn open(old_path: &Path, new_path: Option<&Path>, output: Option<&Path>) -> Result<Self> {
        Self::open_loaded(
            old_path,
            new_path.map(Profile::load).transpose()?,
            new_path,
            output,
        )
    }
    fn open_loaded(
        old_path: &Path,
        new: Option<(Profile, String)>,
        new_path: Option<&Path>,
        output: Option<&Path>,
    ) -> Result<Self> {
        use anyhow::Context;
        use wallet_mpc_transport::{PinnedIdentity, ReceiptIdentity, AUTHORITY_ROLES};
        let (old, old_hash) = Profile::load(old_path)?;
        ensure!(
            old.lifecycle_certificate.is_none()
                && old.replacement_bootstrap.is_none()
                && old.profile_migration.is_none(),
            "this explicit migration only accepts an original LC=None profile"
        );
        if let Some((successor, _)) = &new {
            let b = successor
                .profile_migration
                .as_ref()
                .context("explicit successor bootstrap required")?;
            ensure!(
                std::fs::canonicalize(old_path)? == std::fs::canonicalize(&b.source_profile)?
                    && b.source_profile_sha256 == old_hash
                    && b.source_anchor == old.anchor_directory,
                "CLI source must be the exact predecessor referenced by the successor bootstrap"
            );
        }
        if let Some(output) = output {
            validate_output(
                output,
                old_path,
                &old,
                new_path.zip(new.as_ref().map(|(p, _)| p)),
            )?;
        }
        let life = new
            .as_ref()
            .map(|(p, _)| {
                PinnedIdentity::new(
                    p.lifecycle_certificate
                        .as_ref()
                        .context("successor lifecycle pin required")?,
                    "lifecycle",
                    &AUTHORITY_ROLES,
                )
            })
            .transpose()?;
        let identity = ReceiptIdentity::new(&old.tls, &old.signer.party_id)?;
        let own = PinnedIdentity::new(&old.tls.cert, &old.signer.party_id, &AUTHORITY_ROLES)?;
        let witness = PinnedIdentity::new(&old.witness_certificate, "witness", &AUTHORITY_ROLES)?;
        let policy = super::policy::Policy::new(&old.class, &old.policy)?;
        let journal = super::journal::Journal::open(
            &old.anchor_directory,
            old_hash.clone(),
            &identity,
            super::journal::Authorities {
                own: &own,
                witness: &witness,
                lifecycle: None,
                party: &old.signer.party_id,
                profile: &old_hash,
                policy: &policy,
                class: &old.class,
                migration_lifecycle: life.as_ref(),
            },
            false,
        )?;
        Ok(Self {
            old,
            old_hash,
            new,
            identity,
            own,
            witness,
            life,
            policy,
            journal,
        })
    }
    fn validate(&self, plan: &MigrationPlan) -> Result<()> {
        use anyhow::Context;
        let (new, fingerprint) = self
            .new
            .as_ref()
            .context("explicit successor profile required")?;
        let bootstrap = new
            .profile_migration
            .as_ref()
            .context("explicit successor bootstrap required")?;
        bootstrap.validate_profiles(&self.old, &self.old_hash, new, plan, fingerprint)?;
        ensure!(
            plan.node_key_id == self.own.key_id
                && Some(&plan.new_lifecycle_key_id) == self.life.as_ref().map(|k| &k.key_id),
            "exact original TLS key and explicitly approved successor Life pin required"
        );
        Ok(())
    }
    fn status(&self) -> Result<serde_json::Value> {
        let roots: std::collections::BTreeSet<_> = self
            .journal
            .records
            .requests
            .values()
            .map(|r| r.value.binding.authorized.intent.claim.root.identity())
            .collect::<Result<_>>()?;
        if let Some(admission) = &self.journal.records.profile_migration_fence {
            self.validate(admission.fence.value.approvals.plan())?;
        }
        Ok(serde_json::json!({"source_profile_sha256":self.old_hash,
            "source_head":self.journal.public_head(&self.own)?, "signing_roots_observed":roots,
            "terminal_fence":self.journal.records.profile_migration_fence.as_ref().map(|a| &a.fence),
            "successor_import_available":true}))
    }
}

/// Retains the original source flock throughout successor service lifetime.
/// The source is immutable after its terminal fence and is fully replayed at
/// every restart under its original profile/authorization context.
pub(super) struct Predecessor {
    _source: Source,
}
pub(super) fn open_runtime(
    profile: &Profile,
    fingerprint: &str,
    initialize: bool,
) -> Result<(super::journal::Journal, Predecessor)> {
    use anyhow::Context;
    ensure!(!initialize, "successor requires explicit offline history import; normal initialization cannot reset source history");
    let b = profile
        .profile_migration
        .as_ref()
        .context("successor bootstrap required")?;
    let source = Source::open_loaded(
        &b.source_profile,
        Some((profile.clone(), fingerprint.to_owned())),
        None,
        None,
    )?;
    let terminal = source
        .journal
        .records
        .profile_migration_fence
        .as_ref()
        .context("complete terminal original source required")?;
    source.validate(terminal.fence.value.approvals.plan())?;
    let predecessor = (
        source.journal.records.clone(),
        source.journal.original_head_json(&source.own)?,
    );
    let journal = super::journal::Journal::open_successor(
        &profile.anchor_directory,
        fingerprint.to_owned(),
        &source.identity,
        super::journal::Authorities {
            own: &source.own,
            witness: &source.witness,
            lifecycle: source.life.as_ref(),
            party: &profile.signer.party_id,
            profile: fingerprint,
            policy: &source.policy,
            class: &profile.class,
            migration_lifecycle: None,
        },
        &predecessor,
        None,
    )?;
    Ok((journal, Predecessor { _source: source }))
}

fn query_leases(
    source: &Source,
    plan: &MigrationPlan,
    purpose: wallet_mpc_protocol::solana_profile_migration::MigrationQueryPurpose,
) -> Result<
    std::collections::BTreeMap<
        String,
        wallet_mpc_protocol::witness::Signed<
            wallet_mpc_protocol::solana_profile_migration::MigrationQueryLease,
        >,
    >,
> {
    use wallet_mpc_protocol::{solana_profile_migration::MigrationQueryLease, witness::Query};
    let now = super::now()?;
    let mut leases = std::collections::BTreeMap::new();
    for root in &plan.cohort {
        let id = root.original.identity()?;
        let mut nonce = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let query = super::journal::sign(
            &source.identity,
            "WITNESS_QUERY_V1",
            Query {
                anchor_id: plan.witness_anchor,
                root_identity: id.clone(),
                challenge: wallet_mpc_protocol::dkg::hex(&nonce),
                execution_id: None,
                claim_reservation_id: None,
                candidate_claim: None,
                materialization_id: None,
                rotation_id: None,
            },
        )?;
        let lease = super::journal::sign(
            &source.identity,
            "WITNESS_PROFILE_MIGRATION_QUERY_LEASE_V1",
            MigrationQueryLease {
                purpose: purpose.clone(),
                plan_identity: plan.identity()?,
                query,
                issued_at: now,
                expires_at: now
                    .checked_add(15)
                    .ok_or_else(|| anyhow::anyhow!("query clock overflow"))?,
            },
        )?;
        leases.insert(id, lease);
    }
    Ok(leases)
}

fn validate_output(
    output: &Path,
    old_path: &Path,
    old: &Profile,
    new: Option<(&Path, &Profile)>,
) -> Result<()> {
    use anyhow::Context;
    let parent = std::fs::canonicalize(
        output
            .parent()
            .context("explicit existing output parent required")?,
    )?;
    let candidate = parent.join(
        output
            .file_name()
            .context("explicit output filename required")?,
    );
    match std::fs::symlink_metadata(&candidate) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => anyhow::bail!("migration output must not exist before any mutation"),
    }
    let mut forbidden = vec![];
    let mut add = |path: &Path, p: &Profile| -> Result<()> {
        forbidden.extend([
            std::fs::canonicalize(&p.anchor_directory)?,
            std::fs::canonicalize(&p.signer.storage_directory)?,
            std::fs::canonicalize(
                path.parent()
                    .context("external profile directory required")?,
            )?,
        ]);
        for file in [
            &p.signer.wrapping_key_path,
            Path::new(&p.tls.key),
            Path::new(&p.tls.cert),
            Path::new(&p.tls.ca),
            Path::new(&p.witness_tls.key),
            Path::new(&p.witness_tls.ca),
            Path::new(&p.witness_certificate),
            Path::new(&p.policy.custody_ca),
            Path::new(&p.policy.custody_certificate),
            Path::new(&p.policy.policy_ca),
            Path::new(&p.policy.policy_certificate),
        ] {
            forbidden.push(std::fs::canonicalize(
                file.parent()
                    .context("external credential directory required")?,
            )?);
        }
        for file in p
            .policy
            .receipt_certificates
            .values()
            .flatten()
            .chain(p.lifecycle_certificate.iter())
        {
            forbidden.push(std::fs::canonicalize(
                Path::new(file)
                    .parent()
                    .context("external trust-material directory required")?,
            )?);
        }
        Ok(())
    };
    add(old_path, old)?;
    if let Some((path, p)) = new {
        add(path, p)?;
    }
    ensure!(!forbidden.iter().any(|p| candidate.starts_with(p)),
        "migration output must stay outside original/successor journals, shares and profile/credential directories");
    Ok(())
}

fn read_public<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        file.metadata()
            .is_ok_and(|m| m.file_type().is_file() && m.len() <= 1024 * 1024),
        "bounded regular public migration input required"
    );
    let mut bytes = vec![];
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "public migration input grew beyond bounds"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

/// Offline public control only. No MPC key package or nonce is loaded/exported,
/// no lifecycle private key is held. Import never initializes private MPC state.
pub fn run(args: Vec<String>) -> Result<()> {
    use anyhow::Context;
    use std::collections::BTreeMap;
    use wallet_mpc_protocol::{
        solana_profile_migration::{
            MigrationApprovals, MigrationFence, MigrationQueryLease, MigrationQueryPurpose,
            SourceAdmission, SuccessorAdmission, FENCE_DOMAIN,
        },
        witness::{QueryReply, Signed},
    };
    let command = args
        .first()
        .context("use inspect, challenge, fence, successor-challenge, import or verify")?;
    ensure!(
        [
            "inspect",
            "challenge",
            "fence",
            "successor-challenge",
            "import",
            "verify"
        ]
        .contains(&command.as_str())
            && (args.len() - 1).is_multiple_of(2),
        "strict explicit migration arguments required"
    );
    let mut options = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        ensure!(
            [
                "--old-profile",
                "--new-profile",
                "--approvals",
                "--leases",
                "--frozen",
                "--output"
            ]
            .contains(&pair[0].as_str())
                && options.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
            "unknown or duplicate migration option"
        );
    }
    let mut source = Source::open(
        Path::new(
            options
                .get("--old-profile")
                .context("--old-profile required")?,
        ),
        options.get("--new-profile").map(Path::new),
        options.get("--output").map(Path::new),
    )?;
    let output = if command == "inspect" {
        source.status()?
    } else if ["successor-challenge", "import", "verify"].contains(&command.as_str()) {
        let terminal = source
            .journal
            .records
            .profile_migration_fence
            .as_ref()
            .context("complete original terminal source fence required")?;
        let plan = terminal.fence.value.approvals.plan();
        source.validate(plan)?;
        if command == "successor-challenge" {
            serde_json::to_value(query_leases(
                &source,
                plan,
                MigrationQueryPurpose::SuccessorImport,
            )?)?
        } else {
            let (new, fingerprint) = source.new.as_ref().context("successor profile required")?;
            let source_head = source.journal.original_head_json(&source.own)?;
            let admission = if command == "import" {
                Some(SuccessorAdmission {
                    source_head_json: source_head.clone(),
                    source_fence_sha256: terminal.fence.value.identity()?,
                    initialized_at: super::now()?,
                    queries: read_public(options.get("--leases").context("--leases required")?)?,
                    frozen: read_public(options.get("--frozen").context("--frozen required")?)?,
                })
            } else {
                None
            };
            let predecessor = (source.journal.records.clone(), source_head);
            let successor = super::journal::Journal::open_successor(
                &new.anchor_directory,
                fingerprint.clone(),
                &source.identity,
                super::journal::Authorities {
                    own: &source.own,
                    witness: &source.witness,
                    lifecycle: source.life.as_ref(),
                    party: &new.signer.party_id,
                    profile: fingerprint,
                    policy: &source.policy,
                    class: &new.class,
                    migration_lifecycle: None,
                },
                &predecessor,
                admission,
            )?;
            serde_json::json!({"source_profile_sha256":source.old_hash,
                "successor_profile_sha256":fingerprint,
                "source_head":source.journal.public_head(&source.own)?,
                "successor_head":successor.public_head(&source.own)?,
                "successor_history_imported":successor.records.profile_migration_source.is_some(),
                "private_round_executed":false,
                "records":{"requests":successor.records.requests.len(),
                    "consumed":successor.records.consumed.len(), "reports":successor.records.reports.len(),
                    "ceremonies":successor.records.ceremonies.len(), "ready":successor.records.ready.len(),
                    "cancelled":successor.records.cancelled.len(), "repairs":successor.records.repairs.len(),
                    "repaired":successor.records.repaired.len(), "replacement_refresh":successor.records.replacement_refresh.len()}})
        }
    } else {
        let approvals: MigrationApprovals =
            read_public(options.get("--approvals").context("--approvals required")?)?;
        let plan = approvals.plan();
        source.validate(plan)?;
        if let Some(admitted) = &source.journal.records.profile_migration_fence {
            ensure!(
                admitted.fence.value.approvals == approvals,
                "original terminal migration intent cannot change"
            );
            source.status()?
        } else if command == "challenge" {
            source.policy.migration_approvals(
                &approvals,
                source.life.as_ref().context("successor Life required")?,
                true,
            )?;
            let now = super::now()?;
            plan.validate(now)?;
            let head = source.journal.public_head(&source.own)?;
            ensure!(
                head["value"]["sequence"].as_u64() == Some(plan.source_sequence)
                    && head["value"]["event_hash"].as_str()
                        == Some(plan.source_event_hash.as_str()),
                "original head changed before migration queries"
            );
            serde_json::to_value(query_leases(
                &source,
                plan,
                MigrationQueryPurpose::SourceFence,
            )?)?
        } else {
            let queries: BTreeMap<String, Signed<MigrationQueryLease>> =
                read_public(options.get("--leases").context("--leases required")?)?;
            let frozen: BTreeMap<String, Signed<QueryReply>> =
                read_public(options.get("--frozen").context("--frozen required")?)?;
            let fence = super::journal::sign(
                &source.identity,
                FENCE_DOMAIN,
                MigrationFence {
                    approvals,
                    fenced_at: super::now()?,
                },
            )?;
            let admission = SourceAdmission {
                fence,
                original_head_json: source.journal.original_head_json(&source.own)?,
                queries,
                frozen,
            };
            let authorities = super::journal::Authorities {
                own: &source.own,
                witness: &source.witness,
                lifecycle: None,
                party: &source.old.signer.party_id,
                profile: &source.old_hash,
                policy: &source.policy,
                class: &source.old.class,
                migration_lifecycle: source.life.as_ref(),
            };
            source.journal.append(
                super::journal::Change::ProfileMigrationFence {
                    admission: Box::new(admission),
                },
                &source.identity,
                authorities,
            )?;
            source.status()?
        }
    };
    let bytes = serde_json::to_vec(&output)?;
    if let Some(path) = options.get("--output") {
        wallet_mpc_storage::atomic_create_secret(Path::new(path), &bytes)?;
    } else {
        println!("{}", std::str::from_utf8(&bytes)?);
    }
    Ok(())
}
impl Bootstrap {
    pub fn validate_shape(&self) -> Result<()> {
        ensure!(
            !self.migration_id.is_nil()
                && !self.anchor_id.is_nil()
                && self.migration_id != self.anchor_id
                && self.source_profile.is_absolute()
                && self.source_anchor.is_absolute()
                && hash_text(&self.source_profile_sha256)
                && self.source_profile_sha256 != "00".repeat(32)
                && hash_text(&self.source_event_hash)
                && self.source_event_hash != "00".repeat(32)
                && self.source_sequence < u64::MAX
                && !self.cohort.is_empty()
                && self.cohort.len() <= 32
                && self
                    .cohort
                    .iter()
                    .all(|r| hash_text(r) && *r != "00".repeat(32))
                && self.cohort.windows(2).all(|r| r[0] < r[1]),
            "exact original source/profile/head and ordered successor cohort required"
        );
        Ok(())
    }

    pub fn validate_profiles(
        &self,
        old: &Profile,
        old_hash: &str,
        new: &Profile,
        plan: &MigrationPlan,
        new_hash: &str,
    ) -> Result<()> {
        self.validate_shape()?;
        plan.validate_shape()?;
        ensure!(
            old.lifecycle_certificate.is_none()
                && old.replacement_bootstrap.is_none()
                && old.profile_migration.is_none()
                && new.lifecycle_certificate.is_some()
                && new.replacement_bootstrap.is_none()
                && old.anchor_directory == self.source_anchor
                && old_hash == self.source_profile_sha256
                && plan.old_profile_sha256 == old_hash
                && plan.new_profile_sha256 == new_hash
                && plan.party_id == old.signer.party_id
                && plan.migration_id == self.migration_id
                && plan.new_anchor_id == self.anchor_id
                && plan.source_sequence == self.source_sequence
                && plan.source_event_hash == self.source_event_hash
                && plan.cohort[0].original.wallet_class == old.class
                && plan.witness_anchor == old.witness_anchor,
            "only exact original LC=None identity/profile/head may adopt this successor"
        );
        let mut expected = old.clone();
        expected.lifecycle_certificate = new.lifecycle_certificate.clone();
        expected.anchor_directory = new.anchor_directory.clone();
        expected.profile_migration = Some(self.clone());
        ensure!(serde_json::to_value(&expected)? == serde_json::to_value(new)?,
            "migration cannot silently alter TLS/storage/wrapper/policy/receipt/network/class configuration");
        let roots: Vec<_> = plan
            .cohort
            .iter()
            .map(|r| r.original.identity())
            .collect::<Result<_>>()?;
        ensure!(
            roots == self.cohort,
            "successor Root whitelist must equal the exact approved cohort"
        );
        Ok(())
    }

    pub fn validate_paths(&self, profile_path: &Path, profile: &Profile) -> Result<()> {
        self.validate_shape()?;
        let source = std::fs::canonicalize(&self.source_anchor)?;
        let target = std::fs::canonicalize(&profile.anchor_directory)?;
        let storage = std::fs::canonicalize(&profile.signer.storage_directory)?;
        let old_profile = std::fs::canonicalize(&self.source_profile)?;
        let current = std::fs::canonicalize(profile_path)?;
        ensure!(
            !source.starts_with(&target)
                && !target.starts_with(&source)
                && !source.starts_with(&storage)
                && !storage.starts_with(&source)
                && old_profile != current
                && !old_profile.starts_with(&target)
                && !old_profile.starts_with(&storage),
            "fresh independent public successor anchor and original external profile required"
        );
        Ok(())
    }
}
