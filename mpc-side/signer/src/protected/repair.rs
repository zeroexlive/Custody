//! Direct authenticated upstream RTS: helper Delta stays between two helpers;
//! Sigma goes only to the explicitly authorized replacement. No full key exists.
use super::{journal, now, refresh, repair_store, Service as Host};
use crate::{EnvelopeGuard, ProtocolEnvelope};
use anyhow::{ensure, Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::{identifier, PARTIES},
    sign::public_package,
    solana_recovery::{RepairReady, ReplacementPlan, ReplacementStart},
    witness::{GenerationReady, Query, QueryReply, Signed},
};
use wallet_mpc_transport::{PeerIdentity, SignerClient};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &str = "WITNESS_FROST_REPLACEMENT_PLAN_V1";
const PROTOCOL: &str = "FROST_ED25519_REPAIR_V1";
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Repair,
    Refresh,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub plan: Signed<ReplacementPlan>,
    pub stage: Stage,
    pub frozen: Option<Signed<QueryReply>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub repair_ceremony_id: Uuid,
    pub party_id: String,
    pub status: String,
    pub repaired: Option<Signed<RepairReady>>,
    pub generation_ready: Option<Signed<GenerationReady>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    plan_identity: String,
    package: Vec<u8>,
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.package.zeroize();
    }
}
struct SecretEnvelope(ProtocolEnvelope);
impl Drop for SecretEnvelope {
    fn drop(&mut self) {
        self.0.payload.zeroize();
    }
}
struct Active {
    plan: ReplacementPlan,
    received: BTreeMap<String, Zeroizing<Vec<u8>>>,
    outgoing: Option<Zeroizing<Vec<u8>>>,
    sent_delta: bool,
    sent_sigma: bool,
}
#[derive(Default)]
struct Local {
    active: BTreeMap<Uuid, Active>,
    queries: BTreeMap<(Uuid, Stage), (Query, u64)>,
}
pub struct Service {
    host: Arc<Host>,
    peers: SignerClient,
    refresh: Arc<refresh::Service>,
    store: repair_store::Store,
    local: Mutex<Local>,
    guard: EnvelopeGuard,
}
impl Service {
    pub fn open(
        host: Arc<Host>,
        peers: SignerClient,
        refresh: Arc<refresh::Service>,
    ) -> Result<Arc<Self>> {
        let store = repair_store::Store::open(
            &host.profile.signer.storage_directory,
            &host.profile.signer.wrapping_key_path,
            host.profile.signer.party_id.clone(),
        )?;
        Ok(Arc::new(Self {
            host,
            peers,
            refresh,
            store,
            local: Mutex::new(Local::default()),
            guard: EnvelopeGuard::default(),
        }))
    }
    fn authorize(&self, signed: &Signed<ReplacementPlan>, live: bool) -> Result<()> {
        let life = self
            .host
            .lifecycle
            .as_ref()
            .context("lifecycle repair disabled")?;
        journal::verify(life, DOMAIN, signed)?;
        let p = &signed.value;
        if live {
            p.validate(now()?)?;
        } else {
            p.validate_shape()?;
        }
        let own = &self.host.profile.signer.party_id;
        ensure!(
            p.refresh.anchor_id == self.host.profile.witness_anchor
                && p.refresh.root.wallet_class == self.host.profile.class
                && p.refresh.root.genesis_hash == self.host.policy.limits.genesis_hash,
            "exact isolated original class/network/authority required"
        );
        if p.party_id == *own {
            let bootstrap = self
                .host
                .profile
                .replacement_bootstrap
                .as_ref()
                .context("recipient requires a fresh explicit replacement profile")?;
            ensure!(
                p.refresh.node_keys.get(own) == Some(&self.host.own.key_id)
                    && bootstrap.root_identity == p.refresh.root.identity()?
                    && bootstrap.anchor_id == p.recipient_anchor_id
                    && self.host.fingerprint == p.recipient_profile_sha256,
                "exact new recipient key/profile/anchor/Root required"
            );
        } else {
            ensure!(
                p.previous_node_keys.get(own) == Some(&self.host.own.key_id),
                "both helper identities must be current and unchanged"
            );
        }
        Ok(())
    }
    pub async fn query(&self, control: Control) -> Result<Signed<Query>> {
        self.authorize(&control.plan, true)?;
        let p = &control.plan.value;
        let mut random = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);
        let query = Query {
            anchor_id: p.refresh.anchor_id,
            root_identity: p.refresh.root.identity()?,
            challenge: wallet_mpc_protocol::dkg::hex(&random),
            execution_id: None,
            claim_reservation_id: None,
        };
        let mut local = self.local.lock().await;
        let time = now()?;
        local.queries.retain(|_, (_, deadline)| time < *deadline);
        let slot = (p.repair_ceremony_id, control.stage);
        ensure!(
            local.queries.len() < 32 || local.queries.contains_key(&slot),
            "too many pending replacement queries"
        );
        local.queries.insert(
            slot,
            (
                query.clone(),
                time.checked_add(15).context("clock overflow")?,
            ),
        );
        journal::sign(&self.host.identity, "WITNESS_QUERY_V1", query)
    }
    async fn fresh_start(&self, control: Control) -> Result<(ReplacementStart, u64)> {
        let stage = control.stage;
        let frozen = if let Some(reply) = control.frozen {
            reply
        } else {
            let client = self
                .host
                .client
                .as_ref()
                .context("COLD requires an explicit signed courier query")?;
            let query = self
                .query(Control {
                    plan: control.plan.clone(),
                    stage,
                    frozen: None,
                })
                .await?;
            serde_json::from_slice(
                &client
                    .request("/v1/witness/query", serde_json::to_vec(&query)?)
                    .await?,
            )?
        };
        journal::verify(&self.host.witness, "WITNESS_QUERY_REPLY_V1", &frozen)?;
        let start = ReplacementStart {
            plan: control.plan,
            frozen,
        };
        start.validate_shape()?;
        self.host.policy.verify_root(
            &start
                .frozen
                .value
                .replacement
                .as_ref()
                .context("original enrollment missing")?
                .original_evidence,
        )?;
        let mut local = self.local.lock().await;
        let (query, deadline) = local
            .queries
            .remove(&(start.plan.value.repair_ceremony_id, stage))
            .context("own original replacement query missing")?;
        ensure!(
            query == start.frozen.value.query && now()? < deadline,
            "original live replacement query required"
        );
        Ok((start, deadline))
    }
    fn report_value(
        &self,
        p: &ReplacementPlan,
        status: &str,
        repaired: Option<Signed<RepairReady>>,
    ) -> Report {
        Report {
            repair_ceremony_id: p.repair_ceremony_id,
            party_id: self.host.profile.signer.party_id.clone(),
            status: status.into(),
            repaired,
            generation_ready: None,
        }
    }
    async fn status(&self, p: &ReplacementPlan) -> Result<Report> {
        let own = &self.host.profile.signer.party_id;
        let mut host = self.host.local.lock().await;
        ensure!(!host.journal.poisoned, "repair history uncertain");
        let start = host
            .journal
            .records
            .repairs
            .get(&p.repair_ceremony_id)
            .context("original repair start unavailable")?;
        ensure!(start.plan.value == *p, "original repair plan cannot change");
        if own == &p.party_id {
            if let Some(ready) = host.journal.records.repaired.get(&p.repair_ceremony_id) {
                ensure!(
                    self.store.present(p)?,
                    "durable repaired share missing; no fallback"
                );
                return Ok(self.report_value(p, "REPAIRED_PENDING_REFRESH", Some(ready.clone())));
            }
            if self.store.present(p)? {
                let ready = journal::sign(
                    &self.host.identity,
                    "WITNESS_FROST_REPAIR_READY_V1",
                    RepairReady {
                        root_identity: p.refresh.root.identity()?,
                        plan_identity: p.identity()?,
                        generation: p.refresh.previous.clone(),
                        repair_ceremony_id: p.repair_ceremony_id,
                        party_id: own.clone(),
                    },
                )?;
                self.host.append(
                    &mut host,
                    journal::Change::RepairReady {
                        report: Box::new(ready.clone()),
                    },
                )?;
                return Ok(self.report_value(p, "REPAIRED_PENDING_REFRESH", Some(ready)));
            }
        }
        drop(host);
        let active = self
            .local
            .lock()
            .await
            .active
            .contains_key(&p.repair_ceremony_id);
        Ok(self.report_value(
            p,
            if active {
                "REPAIR_ACTIVE"
            } else {
                "REPAIR_INTERRUPTED"
            },
            None,
        ))
    }
    async fn start(&self, control: Control) -> Result<Report> {
        self.authorize(&control.plan, true)?;
        let p = control.plan.value.clone();
        let own = &self.host.profile.signer.party_id;
        if control.stage == Stage::Refresh {
            let consumed = {
                let host = self.host.local.lock().await;
                ensure!(!host.journal.poisoned, "repair history uncertain");
                host.journal
                    .records
                    .replacement_refresh
                    .contains_key(&p.refresh.ceremony_id)
            };
            if consumed {
                let r = self
                    .refresh
                    .control_replacement("report", &control.plan)
                    .await?;
                return Ok(Report {
                    repair_ceremony_id: p.repair_ceremony_id,
                    party_id: own.clone(),
                    status: r.status,
                    repaired: None,
                    generation_ready: r.ready,
                });
            }
            let (start, deadline) = self.fresh_start(control).await?;
            let key = if own == &p.party_id {
                let ready = self.status(&p).await?;
                ensure!(
                    ready.repaired.is_some(),
                    "durable recipient staging required before refresh"
                );
                self.store.load(&p)?
            } else {
                self.current_helper(&p).await?
            };
            let r = self.refresh.start_replacement(start, key, deadline).await?;
            return Ok(Report {
                repair_ceremony_id: p.repair_ceremony_id,
                party_id: own.clone(),
                status: r.status,
                repaired: None,
                generation_ready: r.ready,
            });
        }
        {
            let host = self.host.local.lock().await;
            ensure!(!host.journal.poisoned, "repair history uncertain");
            if host
                .journal
                .records
                .repairs
                .contains_key(&p.repair_ceremony_id)
            {
                drop(host);
                return self.status(&p).await;
            }
        }
        let (start, deadline) = self.fresh_start(control).await?;
        let key = if own != &p.party_id {
            Some(self.current_helper(&p).await?)
        } else {
            None
        };
        let mut local = self.local.lock().await;
        ensure!(local.active.len() < 8, "too many private repairs");
        {
            let mut host = self.host.local.lock().await;
            self.host.append(
                &mut host,
                journal::Change::RepairStart {
                    start: Box::new(start.clone()),
                },
            )?;
        }
        if own == &p.party_id {
            self.host
                .provenance
                .set(start)
                .map_err(|_| anyhow::anyhow!("replacement provenance already consumed"))?;
        }
        // Durable tombstone and fresh own query precede all upstream randomness.
        let host = self.host.local.lock().await;
        ensure!(!host.journal.poisoned, "repair history uncertain");
        p.validate(now()?)?;
        ensure!(
            now()? < deadline,
            "replacement query expired before private work"
        );
        let mut active = Active {
            plan: p.clone(),
            received: BTreeMap::new(),
            outgoing: None,
            sent_delta: false,
            sent_sigma: false,
        };
        if let Some(key) = key {
            let helpers = p
                .helpers()?
                .into_iter()
                .map(|party| identifier(party).context("helper identifier"))
                .collect::<Result<Vec<_>>>()?;
            let deltas = frost::keys::repairable::repair_share_part1::<frost::Ed25519Sha512, _>(
                &helpers,
                &key,
                &mut rand_core::OsRng,
                identifier(&p.party_id).context("recipient identifier")?,
            )?;
            for (id, delta) in deltas {
                let party = PARTIES
                    .iter()
                    .find(|p| identifier(p) == Some(id))
                    .context("repair helper")?;
                let bytes = Zeroizing::new(delta.serialize());
                if *party == own {
                    active.received.insert(own.clone(), bytes);
                } else {
                    active.outgoing = Some(bytes);
                }
            }
        }
        local.active.insert(p.repair_ceremony_id, active);
        drop(host);
        drop(local);
        self.status(&p).await
    }
    async fn current_helper(&self, p: &ReplacementPlan) -> Result<frost::keys::KeyPackage> {
        self.host.require_root(&p.refresh.root).await?;
        let (key, package) = if p.refresh.previous.epoch == 0 {
            (
                self.host.dkg.original_seeded_key(&p.refresh.root).await?,
                p.refresh.root.public_key_package.clone(),
            )
        } else {
            self.host
                .generation_store
                .load(&p.refresh.root, &p.refresh.previous)?
        };
        ensure!(
            package == p.refresh.previous_public_key_package,
            "actual current helper generation required"
        );
        let public = public_package(&package, &p.refresh.root.group_public_key)?;
        ensure!(
            public.verifying_shares().get(key.identifier()) == Some(key.verifying_share()),
            "current helper public/private share mismatch"
        );
        Ok(key)
    }
    pub async fn control(&self, action: &str, control: Control) -> Result<Report> {
        if action == "start" {
            return self.start(control).await;
        }
        self.authorize(&control.plan, action != "report" && action != "abort")?;
        let p = &control.plan.value;
        if control.stage == Stage::Refresh {
            let r = self
                .refresh
                .control_replacement(action, &control.plan)
                .await?;
            return Ok(Report {
                repair_ceremony_id: p.repair_ceremony_id,
                party_id: self.host.profile.signer.party_id.clone(),
                status: r.status,
                repaired: None,
                generation_ready: r.ready,
            });
        }
        if action == "report" {
            return self.status(p).await;
        }
        let own = &self.host.profile.signer.party_id;
        let mut local = self.local.lock().await;
        if action == "abort" {
            local.active.remove(&p.repair_ceremony_id);
            drop(local);
            return self.status(p).await;
        }
        let active = local
            .active
            .get_mut(&p.repair_ceremony_id)
            .context("ephemeral repair lost; never regenerate a consumed ceremony")?;
        let host = self.host.local.lock().await;
        ensure!(!host.journal.poisoned, "repair history uncertain");
        ensure!(active.plan == *p, "original private repair plan mismatch");
        p.validate(now()?)?;
        if action == "finalize" {
            ensure!(
                own == &p.party_id && active.received.len() == 2,
                "both helper Sigma packages required"
            );
            let active = local.active.remove(&p.repair_ceremony_id).unwrap();
            let sigmas = active
                .received
                .values()
                .map(|bytes| frost::keys::repairable::Sigma::deserialize(bytes))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            p.validate(now()?)?;
            let public = public_package(
                &p.refresh.previous_public_key_package,
                &p.refresh.root.group_public_key,
            )?;
            let key = frost::keys::repairable::repair_share_part3(
                &sigmas,
                identifier(own).context("recipient identifier")?,
                &public,
            )?;
            self.store.persist(p, &key)?;
            drop(host);
            drop(local);
            return self.status(p).await;
        }
        ensure!(
            own != &p.party_id,
            "recipient cannot generate helper packages"
        );
        let (round, target, package) = match action {
            "round1" => {
                ensure!(!active.sent_delta, "private Delta already consumed");
                active.sent_delta = true;
                let other = p
                    .helpers()?
                    .into_iter()
                    .find(|p| *p != own)
                    .context("other helper")?;
                (
                    1,
                    other.to_owned(),
                    active.outgoing.take().context("private Delta missing")?,
                )
            }
            "round2" => {
                ensure!(
                    active.sent_delta && active.received.len() == 2 && !active.sent_sigma,
                    "both original helper Delta packages required exactly once"
                );
                active.sent_sigma = true;
                let deltas = active
                    .received
                    .values()
                    .map(|bytes| frost::keys::repairable::Delta::deserialize(bytes))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                p.validate(now()?)?;
                let sigma = frost::keys::repairable::repair_share_part2(&deltas);
                active.received.clear();
                (2, p.party_id.clone(), Zeroizing::new(sigma.serialize()))
            }
            _ => anyhow::bail!("unsupported private repair action"),
        };
        drop(host);
        drop(local);
        let mut package = package;
        let wire = Wire {
            plan_identity: p.identity()?,
            package: std::mem::take(&mut *package),
        };
        let mut envelope = SecretEnvelope(ProtocolEnvelope {
            logical_session_id: p.repair_session_id,
            crypto_execution_id: p.repair_ceremony_id,
            keyset_id: p.refresh.root.dkg.keyset_id,
            protocol: PROTOCOL.into(),
            sender: own.clone(),
            recipient: target.clone(),
            round,
            sequence: round.into(),
            payload: serde_json::to_vec(&wire)?,
            payload_digest: String::new(),
        });
        envelope.0.payload_digest = envelope.0.transcript_digest();
        self.peers
            .request_pinned_until(
                &target,
                &p.refresh.node_keys[&target],
                "/internal/v1/solana/replacement/message",
                serde_json::to_vec(&envelope.0)?,
                p.refresh.expires_at,
                || self.host.private_release(),
            )
            .await?;
        self.status(p).await
    }
    async fn receive(&self, peer: &PeerIdentity, mut envelope: SecretEnvelope) -> Result<()> {
        let mut local = self.local.lock().await;
        let host = self.host.local.lock().await;
        ensure!(!host.journal.poisoned, "repair history uncertain");
        let active = local
            .active
            .get_mut(&envelope.0.crypto_execution_id)
            .context("unknown/terminal private repair")?;
        let p = &active.plan;
        p.validate(now()?)?;
        let own = &self.host.profile.signer.party_id;
        let e = &envelope.0;
        ensure!(
            e.protocol == PROTOCOL
                && e.logical_session_id == p.repair_session_id
                && e.keyset_id == p.refresh.root.dkg.keyset_id
                && [1, 2].contains(&e.round)
                && e.sequence == u64::from(e.round)
                && e.sender != *own
                && p.refresh
                    .node_keys
                    .get(peer.role())
                    .is_some_and(|key| key == peer.key_id()),
            "exact authorized private repair peer/envelope required"
        );
        let helpers = p.helpers()?;
        ensure!(
            helpers.contains(&peer.role())
                && ((e.round == 1 && helpers.contains(&own.as_str()))
                    || (e.round == 2 && *own == p.party_id)),
            "private Delta/Sigma recipient boundary"
        );
        self.guard.accept(
            e,
            own,
            &format!("spiffe://wallet-mpc/{}", peer.role()),
            &self.host.profile.signer.trusted_peers,
        )?;
        ensure!(
            !active.received.contains_key(&e.sender),
            "private repair package duplicated"
        );
        let mut wire: Wire = serde_json::from_slice(&e.payload)?;
        ensure!(
            wire.plan_identity == p.identity()?,
            "private repair plan binding mismatch"
        );
        if e.round == 1 {
            let value = frost::keys::repairable::Delta::deserialize(&wire.package)?;
            ensure!(
                value.serialize() == wire.package,
                "canonical private Delta required"
            );
        } else {
            let value = frost::keys::repairable::Sigma::deserialize(&wire.package)?;
            ensure!(
                value.serialize() == wire.package,
                "canonical private Sigma required"
            );
        }
        active.received.insert(
            e.sender.clone(),
            Zeroizing::new(std::mem::take(&mut wire.package)),
        );
        envelope.0.payload.zeroize();
        Ok(())
    }
}
fn rejected(_: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(
            serde_json::json!({"error":"replacement rejected; retain original identities and outcome"}),
        ),
    )
}
async fn query(
    State(s): State<Arc<Service>>,
    Json(c): Json<Control>,
) -> Result<Json<Signed<Query>>, (StatusCode, Json<serde_json::Value>)> {
    s.query(c).await.map(Json).map_err(rejected)
}
async fn control(
    State(s): State<Arc<Service>>,
    Path(action): Path<String>,
    Json(c): Json<Control>,
) -> Result<Json<Report>, (StatusCode, Json<serde_json::Value>)> {
    s.control(&action, c).await.map(Json).map_err(rejected)
}
async fn message(
    State(s): State<Arc<Service>>,
    Extension(peer): Extension<PeerIdentity>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let envelope: ProtocolEnvelope =
        serde_json::from_slice(&body).map_err(|e| rejected(e.into()))?;
    s.receive(&peer, SecretEnvelope(envelope))
        .await
        .map(|_| StatusCode::OK)
        .map_err(rejected)
}
pub fn router(s: Arc<Service>) -> Router {
    let class = s.host.profile.class.clone();
    let controls = Router::new()
        .route("/internal/v1/solana/replacement/query", post(query))
        .route("/internal/v1/solana/replacement/{action}", post(control))
        .route_layer(axum::middleware::from_fn(
            move |Extension(peer): Extension<PeerIdentity>,
                  request: axum::extract::Request,
                  next: axum::middleware::Next| {
                let class = class.clone();
                async move {
                    if (class == "COLD" && peer.role() != "courier")
                        || (class != "COLD" && peer.role() != "coordinator")
                    {
                        return Err(StatusCode::FORBIDDEN);
                    }
                    Ok(next.run(request).await)
                }
            },
        ));
    let private = Router::new()
        .route("/internal/v1/solana/replacement/message", post(message))
        .route_layer(axum::middleware::from_fn(
            |Extension(peer): Extension<PeerIdentity>,
             request: axum::extract::Request,
             next: axum::middleware::Next| async move {
                if !PARTIES.contains(&peer.role()) {
                    return Err(StatusCode::FORBIDDEN);
                }
                Ok(next.run(request).await)
            },
        ));
    controls
        .merge(private)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(s)
}
