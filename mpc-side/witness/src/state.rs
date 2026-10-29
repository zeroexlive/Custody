use anyhow::{ensure, Context, Result};
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::{hex, identifier, PARTIES},
    sign::{decode_hex, public_package},
    solana_intent::Generation,
    solana_provisioning::{Claim, Evidence, Root},
    witness::{
        hash, hash_text, Binding, Command, CommandAction, ExecutionStatus, GenerationReady, Permit,
        PermitRequest, Phase, PublicRound, Signed,
    },
};

#[cfg(test)]
pub(crate) mod tests;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub generation: Generation,
    pub public_key_package: Vec<u8>,
    pub node_keys: BTreeMap<String, String>,
    pub ready: Vec<Signed<GenerationReady>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootState {
    pub evidence: Evidence<Root>,
    pub revision: u64,
    pub phase: Phase,
    pub generation: Generation,
    pub public_key_package: Vec<u8>,
    pub node_keys: BTreeMap<String, String>,
    pub prepared: Option<Prepared>,
    pub next_claim_index: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub binding: Binding,
    pub root_identity: String,
    pub package: Vec<u8>,
    pub node_keys: BTreeMap<String, String>,
    pub grants: BTreeMap<String, PermitRequest>,
    pub reports: BTreeMap<String, Signed<PublicRound>>,
    pub signing_package: Option<Vec<u8>>,
    pub status: ExecutionStatus,
    pub signature: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogicalOperation {
    pub business_fingerprint: String,
    pub executions: Vec<Uuid>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub anchor_id: Uuid,
    pub sequence: u64,
    pub roots: BTreeMap<String, RootState>,
    pub executions: BTreeMap<Uuid, Execution>,
    pub operations: BTreeMap<String, LogicalOperation>,
    pub attempts: BTreeMap<String, String>,
    pub sessions: BTreeMap<Uuid, String>,
    pub challenges: BTreeSet<String>,
    pub abandoned: BTreeMap<Uuid, String>,
    pub commands: BTreeMap<Uuid, Command>,
    pub claims: BTreeMap<Uuid, Evidence<Claim>>,
    pub claim_indices: BTreeMap<String, Uuid>,
    pub claim_owners: BTreeMap<String, Uuid>,
    pub claim_retries: BTreeMap<String, Uuid>,
    pub wires: BTreeMap<String, String>,
}

pub(crate) fn slot(party: &str, round: u16) -> String {
    format!("{party}:{round}")
}
pub(crate) fn roster(keys: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        keys.len() == 3
            && PARTIES
                .iter()
                .all(|p| keys.get(*p).is_some_and(|v| hash_text(v)))
            && keys.values().collect::<BTreeSet<_>>().len() == 3,
        "three independent node identity pins required"
    );
    Ok(())
}
impl Snapshot {
    pub(crate) fn empty(anchor_id: Uuid) -> Result<Self> {
        ensure!(
            !anchor_id.is_nil(),
            "explicit authority anchor identity required"
        );
        Ok(Self {
            anchor_id,
            sequence: 0,
            roots: BTreeMap::new(),
            executions: BTreeMap::new(),
            operations: BTreeMap::new(),
            attempts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            challenges: BTreeSet::new(),
            abandoned: BTreeMap::new(),
            commands: BTreeMap::new(),
            claims: BTreeMap::new(),
            claim_indices: BTreeMap::new(),
            claim_owners: BTreeMap::new(),
            claim_retries: BTreeMap::new(),
            wires: BTreeMap::new(),
        })
    }
    fn advance(&mut self, root: &str) -> Result<()> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("authority sequence exhausted")?;
        let state = self.roots.get_mut(root).context("unknown root")?;
        state.revision = state
            .revision
            .checked_add(1)
            .context("root revision exhausted")?;
        Ok(())
    }
    pub(crate) fn command(&mut self, command: &Command) -> Result<bool> {
        ensure!(
            command.anchor_id == self.anchor_id,
            "wrong authority anchor"
        );
        if let Some(previous) = self.commands.get(&command.request_id) {
            ensure!(
                previous == command,
                "original lifecycle command cannot change"
            );
            return Ok(false);
        }
        let id = &command.root_identity;
        if let CommandAction::Enroll {
            evidence,
            node_keys,
        } = &command.action
        {
            evidence.validate()?;
            let root = &evidence.statement;
            root.validate()?;
            roster(node_keys)?;
            ensure!(
                root.identity()? == *id && command.expected_revision == 0,
                "original root enrollment identity"
            );
            ensure!(
                !self.roots.contains_key(id)
                    && !self
                        .roots
                        .values()
                        .any(|r| r.evidence.statement.dkg.keyset_id == root.dkg.keyset_id
                            || r.evidence.statement.group_public_key == root.group_public_key),
                "root/key identity already enrolled"
            );
            self.roots.insert(
                id.clone(),
                RootState {
                    evidence: (**evidence).clone(),
                    revision: 0,
                    phase: Phase::Active,
                    generation: Generation {
                        epoch: 0,
                        ceremony_id: root.dkg.execution_id,
                        public_key_package_sha256: hash(&root.public_key_package),
                    },
                    public_key_package: root.public_key_package.clone(),
                    node_keys: node_keys.clone(),
                    prepared: None,
                    next_claim_index: 0,
                },
            );
        } else {
            let r = self.roots.get(id).context("unknown original root")?;
            ensure!(
                r.revision == command.expected_revision,
                "stale lifecycle CAS revision"
            );
            match &command.action {
                CommandAction::RegisterClaim { evidence } => {
                    evidence.validate()?;
                    evidence.statement.validate()?;
                    let claim = &evidence.statement;
                    ensure!(
                        claim.root == r.evidence.statement && claim.root.identity()? == *id,
                        "claim requires exact enrolled original root"
                    );
                    let index = format!("{id}:{}", claim.index);
                    let owner = claim.owner_slot()?;
                    let retry = claim.retry_slot()?;
                    let reservation = claim.reservation_id;
                    if let Some(original) = self.claims.get(&reservation) {
                        ensure!(
                            original.statement == *claim
                                && self.claim_indices.get(&index) == Some(&reservation)
                                && self.claim_owners.get(&owner) == Some(&reservation)
                                && self.claim_retries.get(&retry) == Some(&reservation),
                            "original claim registration cannot change"
                        );
                    } else {
                        ensure!(
                            r.phase == Phase::Active
                                && claim.index == r.next_claim_index
                                && !self.claim_indices.contains_key(&index)
                                && !self.claim_owners.contains_key(&owner)
                                && !self.claim_retries.contains_key(&retry),
                            "claim index/owner/retry already reserved or out of sequence"
                        );
                        // One authority transaction commits all permanent aliases
                        // before a wallet may be issued or a permit acknowledged.
                        self.claims.insert(reservation, (**evidence).clone());
                        self.claim_indices.insert(index, reservation);
                        self.claim_owners.insert(owner, reservation);
                        self.claim_retries.insert(retry, reservation);
                        self.roots.get_mut(id).unwrap().next_claim_index = claim
                            .index
                            .checked_add(1)
                            .context("claim counter exhausted")?;
                    }
                }
                CommandAction::Freeze => {
                    ensure!(
                        r.phase == Phase::Active,
                        "only active generation can freeze"
                    );
                    self.roots.get_mut(id).unwrap().phase = Phase::Frozen;
                }
                CommandAction::CloseNoSignature { execution_id } => {
                    ensure!(
                        !execution_id.is_nil() && r.phase != Phase::Prepared,
                        "valid original execution and active/frozen authority required"
                    );
                    if let Some(e) = self.executions.get_mut(execution_id) {
                        ensure!(
                            e.root_identity == *id
                                && e.status == ExecutionStatus::Open
                                && e.grants.values().all(|g| g.round != 2),
                            "any R2 grant remains potentially signed"
                        );
                        // The same durable authority transaction serializes this
                        // terminal fence with R2 permit creation.
                        e.status = ExecutionStatus::NoSignature;
                    } else {
                        ensure!(
                            !self.abandoned.contains_key(execution_id),
                            "execution already abandoned"
                        );
                        self.abandoned.insert(*execution_id, id.clone());
                    }
                }
                CommandAction::CloseUnreleased {
                    execution_id,
                    attestations,
                } => {
                    ensure!(
                        r.phase == Phase::Frozen,
                        "freeze required for terminal R2 closure"
                    );
                    let e = self
                        .executions
                        .get_mut(execution_id)
                        .context("original execution missing")?;
                    ensure!(
                        e.root_identity == *id && e.status == ExecutionStatus::Open,
                        "original open execution required"
                    );
                    let grantees: BTreeMap<_, _> = e
                        .grants
                        .values()
                        .filter(|g| g.round == 2)
                        .map(|g| (g.party_id.as_str(), g))
                        .collect();
                    ensure!(
                        !grantees.is_empty()
                            && grantees.len() == attestations.len()
                            && !e.reports.values().any(|p| p.value.round == 2),
                        "every actual R2 grantee must attest with no contradictory result"
                    );
                    let mut seen = BTreeSet::new();
                    for a in attestations {
                        let proof = &a.value;
                        let request = &proof.request;
                        let party = request.value.party_id.as_str();
                        proof.authorization.value.matches(request)?;
                        ensure!(
                            seen.insert(party)
                                && grantees.get(party).is_some_and(|g| **g == request.value)
                                && e.node_keys.get(party) == Some(&a.key_id)
                                && a.key_id == request.key_id
                                && request.value.binding == e.binding
                                && request.value.signing_package == e.signing_package,
                            "original grantee/key/request/package mismatch or duplicate"
                        );
                    }
                    // This CAS shares the permission/result mutex. After commit
                    // no original late R2 report or permission may revive it.
                    e.status = ExecutionStatus::NoSignature;
                }
                CommandAction::Prepare { ready, node_keys } => {
                    ensure!(
                        r.phase == Phase::Frozen && r.prepared.is_none(),
                        "generation must be frozen before preparation"
                    );
                    ensure!(
                        !self
                            .executions
                            .values()
                            .any(|e| e.root_identity == *id && e.status == ExecutionStatus::Open),
                        "unresolved private executions must drain"
                    );
                    roster(node_keys)?;
                    ensure!(
                        ready.len() == 3,
                        "all three durable generation agreements required"
                    );
                    let next = &ready[0].value;
                    ensure!(
                        next.generation.epoch
                            == r.generation
                                .epoch
                                .checked_add(1)
                                .context("epoch exhausted")?
                            && !next.generation.ceremony_id.is_nil()
                            && next.generation.ceremony_id != r.generation.ceremony_id
                            && next.generation.ceremony_id != r.evidence.statement.dkg.execution_id
                            && next.generation.ceremony_id != r.evidence.statement.dkg.session_id
                            && !self.commands.values().any(|c| {
                                matches!(&c.action, CommandAction::Prepare { ready, .. }
                                    if ready.iter().any(|r| r.value.generation.ceremony_id
                                        == next.generation.ceremony_id))
                            })
                            && next.public_key_package.len() <= 4096
                            && next.public_key_package != r.public_key_package
                            && next.generation.public_key_package_sha256
                                == hash(&next.public_key_package),
                        "genuine next generation/package required"
                    );
                    public_package(
                        &next.public_key_package,
                        &r.evidence.statement.group_public_key,
                    )?;
                    for (report, party) in ready.iter().zip(PARTIES) {
                        ensure!(
                            report.value.root_identity == *id
                                && report.value.party_id == party
                                && report.key_id == node_keys[party]
                                && report.value.previous_generation == r.generation
                                && report.value.generation == next.generation
                                && report.value.public_key_package == next.public_key_package,
                            "generation readiness disagreement"
                        );
                    }
                    let prepared = Prepared {
                        generation: next.generation.clone(),
                        public_key_package: next.public_key_package.clone(),
                        node_keys: node_keys.clone(),
                        ready: ready.clone(),
                    };
                    let r = self.roots.get_mut(id).unwrap();
                    r.phase = Phase::Prepared;
                    r.prepared = Some(prepared);
                }
                CommandAction::Activate => {
                    ensure!(
                        r.phase == Phase::Prepared,
                        "all-three prepared agreement required"
                    );
                    ensure!(
                        !self
                            .executions
                            .values()
                            .any(|e| e.root_identity == *id && e.status == ExecutionStatus::Open),
                        "unresolved executions cannot be reset by activation"
                    );
                    let r = self.roots.get_mut(id).unwrap();
                    let next = r.prepared.take().context("missing prepared generation")?;
                    r.generation = next.generation;
                    r.public_key_package = next.public_key_package;
                    r.node_keys = next.node_keys;
                    r.phase = Phase::Active;
                }
                CommandAction::Enroll { .. } => unreachable!(),
            }
        }
        self.advance(id)?;
        self.commands.insert(command.request_id, command.clone());
        Ok(true)
    }

    pub(crate) fn permit(
        &mut self,
        req: &PermitRequest,
        node_key: &str,
        now: u64,
    ) -> Result<Permit> {
        req.validate(now)?;
        ensure!(req.anchor_id == self.anchor_id, "wrong anchor");
        let i = &req.binding.authorized.intent;
        let root = i.claim.root.identity()?;
        let r = self
            .roots
            .get(&root)
            .context("unregistered original root")?;
        ensure!(
            r.phase == Phase::Active
                && r.generation == i.generation
                && r.evidence.statement == i.claim.root
                && r.node_keys
                    .get(&req.party_id)
                    .is_some_and(|k| k == node_key),
            "inactive/stale generation or node identity"
        );
        ensure!(
            self.claims
                .get(&i.claim.reservation_id)
                .is_some_and(|e| e.statement == i.claim),
            "exact original claim must be durably registered before private permission"
        );
        let challenge = format!("{node_key}:{}:{}", req.party_id, req.challenge);
        ensure!(
            !self.challenges.contains(&challenge),
            "signer challenge already used"
        );
        let execution_id = i.crypto_execution_id;
        let logical_key = req.binding.authorized.operation_key()?;
        let wire = req.binding.authorized.wire_key()?;
        ensure!(
            self.wires.get(&wire).is_none_or(|old| old == &logical_key),
            "exact Solana message belongs to another logical operation"
        );
        ensure!(
            !self.abandoned.contains_key(&execution_id),
            "late request for definitively abandoned execution"
        );
        if !self.executions.contains_key(&execution_id) {
            ensure!(
                req.round == 1,
                "first private round must reserve the operation"
            );
            let business = req.binding.authorized.business_fingerprint()?;
            if let Some(previous) = self.operations.get(&logical_key) {
                ensure!(
                    previous.business_fingerprint == business
                        && previous.executions.iter().all(|id| self
                            .executions
                            .get(id)
                            .is_some_and(|e| e.status == ExecutionStatus::NoSignature)),
                    "logical operation already possibly signed or business intent changed"
                );
            }
            let attempt = req.binding.authorized.attempt_key()?;
            ensure!(
                self.attempts
                    .get(&attempt)
                    .is_none_or(|old| old == &logical_key)
                    && self
                        .sessions
                        .get(&i.session_id)
                        .is_none_or(|old| old == &logical_key),
                "attempt/session belongs to another operation"
            );
            self.attempts.insert(attempt, logical_key.clone());
            self.wires.insert(wire.clone(), logical_key.clone());
            self.sessions.insert(i.session_id, logical_key.clone());
            self.operations
                .entry(logical_key.clone())
                .or_insert(LogicalOperation {
                    business_fingerprint: business,
                    executions: vec![],
                })
                .executions
                .push(execution_id);
            self.executions.insert(
                execution_id,
                Execution {
                    binding: req.binding.clone(),
                    root_identity: root.clone(),
                    package: r.public_key_package.clone(),
                    node_keys: r.node_keys.clone(),
                    grants: BTreeMap::new(),
                    reports: BTreeMap::new(),
                    signing_package: None,
                    status: ExecutionStatus::Open,
                    signature: None,
                },
            );
        }
        ensure!(
            self.wires.get(&wire) == Some(&logical_key),
            "original execution wire alias missing"
        );
        let e = self.executions.get_mut(&execution_id).unwrap();
        ensure!(
            e.binding.identity()? == req.binding.identity()?
                && e.root_identity == root
                && e.status == ExecutionStatus::Open,
            "original execution identity/status conflict"
        );
        let key = slot(&req.party_id, req.round);
        ensure!(
            !e.grants.contains_key(&key),
            "private round grant already consumed; no secret retry"
        );
        if req.round == 2 {
            let bytes = req.signing_package.as_ref().context("R2 package missing")?;
            let package = frost::SigningPackage::deserialize(bytes)?;
            let payload = decode_hex(&req.binding.authorized.payload_hex).context("payload")?;
            ensure!(
                package.serialize()? == *bytes
                    && package.message() == &payload
                    && package.signing_commitments().len() == 2,
                "canonical original signing package required"
            );
            for party in &e.binding.selected_signers {
                let record = e
                    .reports
                    .get(&slot(party, 1))
                    .context("all original R1 receipts required")?;
                let c = frost::round1::SigningCommitments::deserialize(
                    record
                        .value
                        .commitments
                        .as_ref()
                        .context("R1 commitment missing")?,
                )?;
                ensure!(
                    package.signing_commitment(&identifier(party).context("party identity")?)
                        == Some(c),
                    "original party commitment mismatch"
                );
            }
            if let Some(original) = &e.signing_package {
                ensure!(original == bytes, "execution signing package cannot change");
            } else {
                e.signing_package = Some(bytes.clone());
            }
        }
        e.grants.insert(key, req.clone());
        self.challenges.insert(challenge);
        self.advance(&root)?;
        Ok(Permit {
            request: req.clone(),
            sequence: self.sequence,
            root_revision: self.roots[&root].revision,
        })
    }

    pub(crate) fn record(&mut self, frame: &Signed<PublicRound>) -> Result<bool> {
        let p = &frame.value;
        ensure!(p.anchor_id == self.anchor_id, "wrong public result anchor");
        let e = self
            .executions
            .get_mut(&p.execution_id)
            .context("unknown result execution")?;
        let key = slot(&p.party_id, p.round);
        ensure!(
            e.binding.identity()? == p.binding_fingerprint
                && e.node_keys
                    .get(&p.party_id)
                    .is_some_and(|k| k == &frame.key_id)
                && e.grants.contains_key(&key),
            "result lacks original identity/round grant"
        );
        if let Some(original) = e.reports.get(&key) {
            ensure!(original == frame, "original public receipt cannot change");
            return Ok(false);
        }
        // A closed zero-R2 operation cannot gain a private partial later.
        ensure!(
            e.status == ExecutionStatus::Open,
            "closed original operation"
        );
        if p.round == 1 {
            ensure!(
                p.signature_share.is_none() && p.signing_package.is_none(),
                "R1 public shape"
            );
            let bytes = p.commitments.as_ref().context("R1 commitments required")?;
            let commitments = frost::round1::SigningCommitments::deserialize(bytes)?;
            ensure!(
                commitments.serialize()? == *bytes,
                "canonical R1 commitments"
            );
        } else {
            ensure!(
                p.round == 2 && p.commitments.is_none() && p.signing_package == e.signing_package,
                "original R2 package required"
            );
            let bytes = p.signature_share.as_ref().context("R2 share required")?;
            let share = frost::round2::SignatureShare::deserialize(bytes)?;
            ensure!(share.serialize() == *bytes, "canonical signature share");
            let package = frost::SigningPackage::deserialize(
                e.signing_package.as_ref().context("missing R2 package")?,
            )?;
            let public = public_package(
                &e.package,
                &e.binding.authorized.intent.claim.root.group_public_key,
            )?;
            let id = identifier(&p.party_id).context("party identity")?;
            frost_core::verify_signature_share::<frost::Ed25519Sha512>(
                id,
                public
                    .verifying_shares()
                    .get(&id)
                    .context("missing party share")?,
                &share,
                &package,
                public.verifying_key(),
            )?;
        }
        e.reports.insert(key, frame.clone());
        if e.binding
            .selected_signers
            .iter()
            .all(|party| e.reports.contains_key(&slot(party, 2)))
        {
            let shares = e
                .binding
                .selected_signers
                .iter()
                .map(|party| -> Result<_> {
                    Ok((
                        identifier(party).context("party identity")?,
                        frost::round2::SignatureShare::deserialize(
                            e.reports[&slot(party, 2)]
                                .value
                                .signature_share
                                .as_ref()
                                .context("share")?,
                        )?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let package = frost::SigningPackage::deserialize(e.signing_package.as_ref().unwrap())?;
            let public = public_package(
                &e.package,
                &e.binding.authorized.intent.claim.root.group_public_key,
            )?;
            let signature = frost::aggregate(&package, &shares, &public)?;
            public
                .verifying_key()
                .verify(package.message(), &signature)?;
            e.signature = Some(hex(&signature.serialize()?));
            // Crypto completion permits epoch draining, NEVER a fresh financial
            // attempt. Logical-operation fencing remains permanent until an
            // independently authoritative financial reconciliation is added.
            e.status = ExecutionStatus::SignedPending;
        }
        let root = e.root_identity.clone();
        self.advance(&root)?;
        Ok(true)
    }
}
