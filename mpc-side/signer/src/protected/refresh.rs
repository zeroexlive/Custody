//! Authenticated direct-peer upstream FROST refresh. The coordinator receives
//! public status/readiness only; private packages never leave their peer mesh.
use super::{journal, now, Service as Host};
use crate::{EnvelopeGuard, ProtocolEnvelope};
use anyhow::{ensure, Context, Result};
use axum::{
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
    solana_generation::{RefreshPlan, RefreshStart},
    witness::{hash, GenerationReady, Query, QueryReply, Signed},
};
use wallet_mpc_transport::{PeerIdentity, SignerClient};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &str = "WITNESS_FROST_REFRESH_PLAN_V1";
const PROTOCOL: &str = "FROST_ED25519_REFRESH_V1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Round2Wire {
    round1_view: String,
    package: Vec<u8>,
}
impl Drop for Round2Wire {
    fn drop(&mut self) {
        self.package.zeroize();
    }
}
struct Active {
    plan: RefreshPlan,
    key: frost::keys::KeyPackage,
    first: Option<frost::keys::dkg::round1::SecretPackage>,
    public: frost::keys::dkg::round1::Package,
    received1: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    second: Option<frost::keys::dkg::round2::SecretPackage>,
    received2: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    sent1: bool,
    sent2: bool,
}
#[derive(Default)]
struct Local {
    active: BTreeMap<Uuid, Active>,
    queries: BTreeMap<Uuid, (Query, u64)>,
}
pub struct Service {
    host: Arc<Host>,
    peers: SignerClient,
    local: Mutex<Local>,
    guard: EnvelopeGuard,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub plan: Signed<RefreshPlan>,
    pub frozen: Option<Signed<QueryReply>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub ceremony_id: Uuid,
    pub party_id: String,
    pub status: String,
    pub ready: Option<Signed<GenerationReady>>,
}
impl Service {
    pub fn open(host: Arc<Host>, peers: SignerClient) -> Arc<Self> {
        Arc::new(Self {
            host,
            peers,
            local: Mutex::new(Local::default()),
            guard: EnvelopeGuard::default(),
        })
    }
    fn authorize(&self, plan: &Signed<RefreshPlan>, live: bool) -> Result<()> {
        let life = self
            .host
            .lifecycle
            .as_ref()
            .context("lifecycle mutation disabled")?;
        journal::verify(life, DOMAIN, plan)?;
        if live {
            plan.value.validate(now()?)?;
        } else {
            plan.value.validate_shape()?;
        }
        ensure!(
            plan.value.anchor_id == self.host.profile.witness_anchor
                && plan.value.root.wallet_class == self.host.profile.class
                && plan.value.node_keys.get(&self.host.profile.signer.party_id)
                    == Some(&self.host.own.key_id),
            "exact class/authority/current participant identity required"
        );
        Ok(())
    }
    pub async fn query(&self, plan: Signed<RefreshPlan>) -> Result<Signed<Query>> {
        self.authorize(&plan, true)?;
        self.host
            .provisioning
            .require_root(&plan.value.root)
            .await?;
        let mut random = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);
        let value = Query {
            anchor_id: plan.value.anchor_id,
            root_identity: plan.value.root.identity()?,
            challenge: wallet_mpc_protocol::dkg::hex(&random),
            execution_id: None,
            claim_reservation_id: None,
        };
        let mut local = self.local.lock().await;
        let time = now()?;
        local.queries.retain(|_, (_, deadline)| time < *deadline);
        ensure!(
            local.queries.len() < 32 || local.queries.contains_key(&plan.value.ceremony_id),
            "too many pending lifecycle queries"
        );
        local.queries.insert(
            plan.value.ceremony_id,
            (
                value.clone(),
                now()?.checked_add(15).context("time overflow")?,
            ),
        );
        journal::sign(&self.host.identity, "WITNESS_QUERY_V1", value)
    }
    async fn status(&self, plan: &RefreshPlan) -> Result<Report> {
        let mut anchor = self.host.local.lock().await;
        ensure!(!anchor.journal.poisoned, "protected history uncertain");
        if let Some(r) = anchor.journal.records.ready.get(&plan.ceremony_id) {
            ensure!(
                anchor.journal.records.ceremonies[&plan.ceremony_id]
                    .plan
                    .value
                    == *plan,
                "original lifecycle plan cannot change"
            );
            // Verify the private artifact still exists before returning READY.
            let (generation, public) = self
                .host
                .generation_store
                .finished(plan)?
                .context("durable private generation missing; explicit repair required")?;
            ensure!(
                r.value.generation == generation && r.value.public_key_package == public,
                "public/private generation disagreement"
            );
            return Ok(Report {
                ceremony_id: plan.ceremony_id,
                party_id: self.host.profile.signer.party_id.clone(),
                status: "READY".into(),
                ready: Some(r.clone()),
            });
        }
        let consumed = anchor
            .journal
            .records
            .ceremonies
            .get(&plan.ceremony_id)
            .context("refresh not started")?;
        ensure!(
            consumed.plan.value == *plan,
            "original refresh identity changed"
        );
        if let Some((generation, public)) = self.host.generation_store.finished(plan)? {
            let ready = journal::sign(
                &self.host.identity,
                "WITNESS_GENERATION_READY_V1",
                GenerationReady {
                    root_identity: plan.root.identity()?,
                    previous_generation: plan.previous.clone(),
                    generation,
                    public_key_package: public,
                    party_id: self.host.profile.signer.party_id.clone(),
                },
            )?;
            self.host.append(
                &mut anchor,
                journal::Change::RefreshReady {
                    report: Box::new(ready.clone()),
                },
            )?;
            return Ok(Report {
                ceremony_id: plan.ceremony_id,
                party_id: self.host.profile.signer.party_id.clone(),
                status: "READY".into(),
                ready: Some(ready),
            });
        }
        Ok(Report {
            ceremony_id: plan.ceremony_id,
            party_id: self.host.profile.signer.party_id.clone(),
            status: "IN_PROGRESS_OR_RECONCILIATION_REQUIRED".into(),
            ready: None,
        })
    }
    async fn start(&self, control: Control) -> Result<Report> {
        self.authorize(&control.plan, true)?;
        let plan = &control.plan.value;
        // Every automatic path creates its OWN query. A COLD/manual response
        // must answer a still-live query issued by this process's query route.
        let frozen = if let Some(reply) = control.frozen {
            reply
        } else {
            let client = self
                .host
                .client
                .as_ref()
                .context("COLD requires explicit signed query courier")?;
            let query = self.query(control.plan.clone()).await?;
            serde_json::from_slice(
                &client
                    .request("/v1/witness/query", serde_json::to_vec(&query)?)
                    .await?,
            )?
        };
        journal::verify(&self.host.witness, "WITNESS_QUERY_REPLY_V1", &frozen)?;
        let start = RefreshStart {
            plan: control.plan.clone(),
            frozen,
        };
        start.validate_shape()?;
        let mut local = self.local.lock().await;
        let (query, deadline) = local
            .queries
            .remove(&plan.ceremony_id)
            .context("own original live query missing")?;
        ensure!(
            query == start.frozen.value.query && now()? < deadline,
            "stale/replayed lifecycle query response"
        );
        ensure!(
            local.active.len() < 8,
            "too many active lifecycle ceremonies"
        );
        let key = if plan.previous.epoch == 0 {
            self.host.dkg.original_seeded_key(&plan.root).await?
        } else {
            let (key, public) = self
                .host
                .generation_store
                .load(&plan.root, &plan.previous)?;
            ensure!(
                public == plan.previous_public_key_package,
                "prior private generation/package mismatch"
            );
            key
        };
        let previous = public_package(
            &plan.previous_public_key_package,
            &plan.root.group_public_key,
        )?;
        ensure!(
            previous.verifying_shares().get(key.identifier()) == Some(key.verifying_share()),
            "actual prior private verification share required"
        );
        {
            let mut anchor = self.host.local.lock().await;
            self.host.append(
                &mut anchor,
                journal::Change::RefreshStart {
                    start: Box::new(start),
                },
            )?;
        }
        // Tombstone commits before fresh upstream secret polynomial work.
        plan.validate(now()?)?;
        ensure!(
            now()? < deadline,
            "lifecycle query expired before private work"
        );
        let (first, public) = frost::keys::refresh::refresh_dkg_part1(
            identifier(&self.host.profile.signer.party_id).context("own party")?,
            3,
            2,
            rand_core::OsRng,
        )?;
        local.active.insert(
            plan.ceremony_id,
            Active {
                plan: plan.clone(),
                key,
                first: Some(first),
                public,
                received1: BTreeMap::new(),
                second: None,
                received2: BTreeMap::new(),
                sent1: false,
                sent2: false,
            },
        );
        drop(local);
        self.status(plan).await
    }
    pub async fn control(&self, action: &str, control: Control) -> Result<Report> {
        if action == "start" {
            return self.start(control).await;
        }
        // Aborting only discards volatile private ceremony state; an expired
        // signed plan must not trap that state until a process restart.
        self.authorize(&control.plan, action != "report" && action != "abort")?;
        let plan = &control.plan.value;
        if action == "report" {
            return self.status(plan).await;
        }
        let own = &self.host.profile.signer.party_id;
        let mut local = self.local.lock().await;
        let active = local
            .active
            .get_mut(&plan.ceremony_id)
            .context("ephemeral refresh state lost; never rerun consumed ceremony")?;
        ensure!(
            active.plan == *plan,
            "original active lifecycle plan mismatch"
        );
        if action == "abort" {
            local.active.remove(&plan.ceremony_id);
            drop(local);
            return self.status(plan).await;
        }
        if action == "finalize" {
            ensure!(
                active.sent2 && active.received2.len() == 2,
                "all three refresh participants required"
            );
            let active = local.active.remove(&plan.ceremony_id).unwrap();
            plan.validate(now()?)?;
            let (key, public) = frost::keys::refresh::refresh_dkg_shares(
                active
                    .second
                    .as_ref()
                    .context("refresh second round missing")?,
                &active.received1,
                &active.received2,
                public_package(
                    &plan.previous_public_key_package,
                    &plan.root.group_public_key,
                )?,
                active.key,
            )?;
            ensure!(
                public.verifying_key().serialize()?
                    == wallet_mpc_protocol::sign::decode_hex(&plan.root.group_public_key)
                        .context("original group key")?,
                "refresh cannot rotate the group key"
            );
            self.host.generation_store.persist(plan, &key, &public)?;
            drop(local);
            return self.status(plan).await;
        }
        let (round, outgoing): (u16, BTreeMap<String, Vec<u8>>) = match action {
            "round1" => {
                ensure!(!active.sent1, "refresh round1 already sent");
                plan.validate(now()?)?;
                active.sent1 = true;
                (
                    1,
                    PARTIES
                        .iter()
                        .filter(|p| **p != own)
                        .map(|p| Ok(((*p).into(), active.public.serialize()?)))
                        .collect::<Result<_>>()?,
                )
            }
            "round2" => {
                ensure!(
                    active.sent1 && active.received1.len() == 2 && !active.sent2,
                    "refresh round1 incomplete or already consumed"
                );
                let view = round1_view(active, own)?;
                plan.validate(now()?)?;
                let (second, packages) = frost::keys::refresh::refresh_dkg_part2(
                    active
                        .first
                        .take()
                        .context("refresh round1 secret consumed")?,
                    &active.received1,
                )?;
                active.second = Some(second);
                active.sent2 = true;
                let outgoing = packages
                    .into_iter()
                    .map(|(id, package)| {
                        let p = PARTIES
                            .iter()
                            .find(|p| identifier(p) == Some(id))
                            .context("upstream refresh recipient")?;
                        Ok((
                            (*p).into(),
                            serde_json::to_vec(&Round2Wire {
                                round1_view: view.clone(),
                                package: package.serialize()?,
                            })?,
                        ))
                    })
                    .collect::<Result<_>>()?;
                (2, outgoing)
            }
            _ => anyhow::bail!("unsupported refresh action"),
        };
        drop(local);
        for (party, payload) in outgoing {
            let mut envelope = ProtocolEnvelope {
                logical_session_id: plan.session_id,
                crypto_execution_id: plan.ceremony_id,
                keyset_id: plan.root.dkg.keyset_id,
                protocol: PROTOCOL.into(),
                sender: own.clone(),
                recipient: party.clone(),
                round,
                sequence: round.into(),
                payload,
                payload_digest: String::new(),
            };
            envelope.payload_digest = envelope.transcript_digest();
            self.peers
                .request_pinned(
                    &party,
                    &plan.node_keys[&party],
                    "POST",
                    "/internal/v1/solana/generation/message",
                    serde_json::to_vec(&envelope)?,
                )
                .await?;
        }
        self.status(plan).await
    }
    async fn receive(&self, peer: &PeerIdentity, envelope: ProtocolEnvelope) -> Result<()> {
        let mut local = self.local.lock().await;
        let active = local
            .active
            .get_mut(&envelope.crypto_execution_id)
            .context("unknown/terminal refresh ceremony")?;
        let p = &active.plan;
        p.validate(now()?)?;
        ensure!(
            envelope.protocol == PROTOCOL
                && envelope.logical_session_id == p.session_id
                && envelope.keyset_id == p.root.dkg.keyset_id
                && [1, 2].contains(&envelope.round)
                && envelope.sequence == u64::from(envelope.round)
                && envelope.sender != self.host.profile.signer.party_id
                && p.node_keys
                    .get(peer.role())
                    .is_some_and(|k| k == peer.key_id()),
            "exact planned refresh peer/round required"
        );
        self.guard.accept(
            &envelope,
            &self.host.profile.signer.party_id,
            &format!("spiffe://wallet-mpc/{}", peer.role()),
            &self.host.profile.signer.trusted_peers,
        )?;
        let id = identifier(&envelope.sender).context("refresh sender")?;
        if envelope.round == 1 {
            ensure!(
                active.second.is_none() && !active.received1.contains_key(&id),
                "refresh round1 closed/duplicate"
            );
            let package = frost::keys::dkg::round1::Package::deserialize(&envelope.payload)?;
            ensure!(
                package.serialize()? == envelope.payload,
                "canonical refresh public package required"
            );
            active.received1.insert(id, package);
        } else {
            ensure!(
                active.received1.len() == 2 && !active.received2.contains_key(&id),
                "refresh round2 not ready/duplicate"
            );
            let wire: Round2Wire = serde_json::from_slice(&envelope.payload)?;
            ensure!(
                wire.round1_view == round1_view(active, &self.host.profile.signer.party_id)?,
                "equivocated refresh round1 view"
            );
            let package = frost::keys::dkg::round2::Package::deserialize(&wire.package)?;
            ensure!(
                package.serialize()? == wire.package,
                "canonical refresh private package required"
            );
            active.received2.insert(id, package);
        }
        Ok(())
    }
}
fn round1_view(active: &Active, own: &str) -> Result<String> {
    let mut packages = BTreeMap::new();
    packages.insert(own.to_owned(), active.public.serialize()?);
    for (id, package) in &active.received1 {
        let party = PARTIES
            .iter()
            .find(|p| identifier(p) == Some(*id))
            .context("refresh identifier")?;
        packages.insert((*party).to_owned(), package.serialize()?);
    }
    ensure!(packages.len() == 3, "complete refresh view required");
    Ok(hash(&serde_json::to_vec(&packages)?))
}
fn rejected(_: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(
            serde_json::json!({"error":"lifecycle rejected; retain original generation and outcome"}),
        ),
    )
}
async fn control(
    State(s): State<Arc<Service>>,
    Path(action): Path<String>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<Report>, (StatusCode, Json<serde_json::Value>)> {
    if peer.role() != "coordinator" && !(s.host.profile.class == "COLD" && peer.role() == "courier")
    {
        return Err(rejected(anyhow::anyhow!("lifecycle controller role")));
    }
    let control = serde_json::from_slice(&body)
        .map_err(|_| rejected(anyhow::anyhow!("invalid lifecycle input")))?;
    s.control(&action, control)
        .await
        .map(Json)
        .map_err(rejected)
}
async fn query(
    State(s): State<Arc<Service>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<Signed<Query>>, (StatusCode, Json<serde_json::Value>)> {
    if peer.role() != "coordinator" && !(s.host.profile.class == "COLD" && peer.role() == "courier")
    {
        return Err(rejected(anyhow::anyhow!("lifecycle query role")));
    }
    let plan = serde_json::from_slice(&body)
        .map_err(|_| rejected(anyhow::anyhow!("invalid lifecycle plan")))?;
    s.query(plan).await.map(Json).map_err(rejected)
}
async fn receive(
    State(s): State<Arc<Service>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let body = Zeroizing::new(body.to_vec());
    let envelope = serde_json::from_slice(&body)
        .map_err(|_| rejected(anyhow::anyhow!("invalid private envelope")))?;
    s.receive(&peer, envelope).await.map_err(rejected)?;
    Ok(Json(serde_json::json!({"accepted":true})))
}
pub fn router(s: Arc<Service>) -> Router {
    Router::new()
        .route("/internal/v1/solana/generation/{action}", post(control))
        .route("/internal/v1/solana/generation/query", post(query))
        .route("/internal/v1/solana/generation/message", post(receive))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(s)
}
