//! Public observation of one already signed wire. No nonce or share is loaded.
use super::{journal, now, Service};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use std::sync::Arc;
use wallet_mpc_protocol::{
    dkg::hex,
    solana_finality::{
        FinalityCompletion, FinalityLease, FinalityObservation, FinalityReady, FinalityRequest,
        ObservedFinality, PLAN_DOMAIN, REPORT_DOMAIN,
    },
    witness::{Query, QueryReply, Signed},
};
use wallet_mpc_transport::PeerIdentity;
impl Service {
    fn authorize_finality(&self, request: &FinalityRequest, time: u64, live: bool) -> Result<()> {
        request.validate_archived_wire()?;
        let life = self
            .lifecycle
            .as_ref()
            .context("explicit finality Lifecycle capability required")?;
        journal::verify(life, PLAN_DOMAIN, &request.authorization)?;
        let plan = request.plan();
        ensure!(
            plan.root.wallet_class == self.profile.class
                && plan.root.genesis_hash == self.policy.limits.genesis_hash
                && plan.witness_anchor == self.profile.witness_anchor
                && plan.observing_node_keys[&self.profile.signer.party_id] == self.own.key_id,
            "exact independently installed current source observer required"
        );
        if live {
            plan.validate(time)?;
        }
        self.require_migration_root(&plan.root)
    }
    fn finality_query_message(&self, request: &FinalityRequest) -> Result<Signed<Query>> {
        let mut nonce = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        journal::sign(
            &self.identity,
            "WITNESS_QUERY_V1",
            Query {
                anchor_id: request.plan().witness_anchor,
                root_identity: request.plan().root.identity()?,
                challenge: hex(&nonce),
                execution_id: Some(request.plan().execution_id),
                claim_reservation_id: None,
                candidate_claim: None,
            },
        )
    }
    pub async fn finality_query(&self, request: FinalityRequest) -> Result<Signed<Query>> {
        self.authorize_finality(&request, now()?, true)?;
        if self.profile.replacement_bootstrap.is_some() {
            // Existing replacement provenance verification uses only original
            // public evidence in this branch, not an old missing DKG share.
            self.require_root(&request.plan().root).await?;
        } else {
            self.provisioning
                .require_public_enrollment(&request.plan().root)
                .await?;
        }
        let mut local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "public finality history uncertain");
        let time = now()?;
        self.authorize_finality(&request, time, true)?;
        if let Some(original) = local
            .journal
            .records
            .finality_queries
            .values()
            .find(|l| l.request.plan().observation_id == request.plan().observation_id)
        {
            ensure!(
                original.request == request && time < original.expires_at,
                "original finality attempt cannot change or renew"
            );
            return Ok(original.query.clone());
        }
        ensure!(
            local
                .journal
                .records
                .finality_queries
                .values()
                .filter(|l| time < l.expires_at)
                .count()
                < 32,
            "too many live public finality queries"
        );
        let lease = FinalityLease {
            query: self.finality_query_message(&request)?,
            request,
            issued_at: time,
            expires_at: time
                .checked_add(15)
                .context("public finality clock overflow")?,
        };
        lease.validate_shape(&self.profile.signer.party_id)?;
        let response = lease.query.clone();
        self.append(
            &mut local,
            journal::Change::FinalityQuery {
                lease: Box::new(lease),
            },
        )?;
        Ok(response)
    }
    pub async fn finality_observe(&self, proof: Signed<QueryReply>) -> Result<Signed<Query>> {
        journal::verify(&self.witness, "WITNESS_QUERY_REPLY_V1", &proof)?;
        let lease = {
            let local = self.local.lock().await;
            ensure!(!local.journal.poisoned, "public finality history uncertain");
            let lease = local
                .journal
                .records
                .finality_queries
                .get(&proof.value.query.challenge)
                .context("original own finality query missing")?
                .clone();
            self.authorize_finality(&lease.request, now()?, true)?;
            lease.validate_proof(&proof.value, &self.profile.signer.party_id, now()?)?;
            self.current_claim_profile(&local, &proof.value)?;
            if let Some(original) = local
                .journal
                .records
                .finality_observed
                .get(&lease.request.plan().observation_id)
            {
                ensure!(
                    original.lease == lease,
                    "original observation cannot change"
                );
                return Ok(original.final_query.clone());
            }
            lease
        };
        let genesis = self
            .rpc
            .call("getGenesisHash", serde_json::json!([]))
            .await?;
        ensure!(
            genesis.as_str() == Some(&lease.request.plan().root.genesis_hash),
            "independent finality genesis mismatch"
        );
        let signature = bs58::encode(
            wallet_mpc_protocol::sign::decode_hex(&lease.request.plan().signature_hex).unwrap(),
        )
        .into_string();
        let statuses = self
            .rpc
            .call(
                "getSignatureStatuses",
                serde_json::json!([[signature],{"searchTransactionHistory":true}]),
            )
            .await?;
        let transaction=self.rpc.call("getTransaction",serde_json::json!([signature,{"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}])).await?;
        ensure!(
            self.rpc
                .call("getGenesisHash", serde_json::json!([]))
                .await?
                == genesis,
            "RPC identity changed during observation"
        );
        let observation = FinalityObservation::verify_rpc(
            &lease.request,
            &statuses,
            &transaction,
            genesis.as_str().context("RPC genesis text")?,
        )?;
        let mut local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "public finality history uncertain");
        let time = now()?;
        self.authorize_finality(&lease.request, time, true)?;
        lease.validate_proof(&proof.value, &self.profile.signer.party_id, time)?;
        if let Some(original) = local
            .journal
            .records
            .finality_observed
            .get(&lease.request.plan().observation_id)
        {
            ensure!(
                original.lease == lease,
                "original observation cannot change"
            );
            return Ok(original.final_query.clone());
        }
        let observed = ObservedFinality {
            final_query: self.finality_query_message(&lease.request)?,
            lease,
            initial_witness: proof,
            observation,
            observed_at: time,
        };
        let query = observed.final_query.clone();
        self.append(
            &mut local,
            journal::Change::FinalityObserved {
                observed: Box::new(observed),
            },
        )?;
        Ok(query)
    }
    pub async fn finality_complete(
        &self,
        completion: FinalityCompletion,
    ) -> Result<Signed<FinalityReady>> {
        journal::verify(&self.witness, "WITNESS_QUERY_REPLY_V1", &completion.witness)?;
        let mut local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "public finality history uncertain");
        if let Some(original) = local
            .journal
            .records
            .finality_reports
            .get(&completion.observation_id)
        {
            ensure!(
                completion.witness.value.query == original.value.observed.final_query.value,
                "original public finality completion query required"
            );
            return Ok(original.clone());
        }
        let observed = local
            .journal
            .records
            .finality_observed
            .get(&completion.observation_id)
            .context("original public observation missing")?
            .clone();
        let time = now()?;
        self.authorize_finality(&observed.lease.request, time, true)?;
        self.current_claim_profile(&local, &completion.witness.value)?;
        let ready = FinalityReady {
            party_id: self.profile.signer.party_id.clone(),
            observed,
            final_witness: completion.witness,
            profile_fingerprint: self.fingerprint.clone(),
            reported_at: time,
        };
        ready.validate(time)?;
        let report = journal::sign(&self.identity, REPORT_DOMAIN, ready)?;
        self.append(
            &mut local,
            journal::Change::FinalityReport {
                report: Box::new(report.clone()),
            },
        )?;
        Ok(report)
    }
    pub async fn finality_recover(
        &self,
        request: FinalityRequest,
    ) -> Result<Option<Signed<FinalityReady>>> {
        self.authorize_finality(&request, now()?, false)?;
        let local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "public finality history uncertain");
        let Some(report) = local
            .journal
            .records
            .finality_reports
            .get(&request.plan().observation_id)
        else {
            return Ok(None);
        };
        ensure!(
            report.value.observed.lease.request == request,
            "original public finality request required"
        );
        Ok(Some(report.clone()))
    }
}
fn reject(_: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error":"public finality rejected; retain original execution"})),
    )
}
pub fn router(s: Arc<Service>) -> Router {
    if s.lifecycle.is_none() {
        return Router::new();
    }
    async fn query(
        State(s): State<Arc<Service>>,
        Extension(peer): Extension<PeerIdentity>,
        Json(request): Json<FinalityRequest>,
    ) -> Result<Json<Signed<Query>>, (StatusCode, Json<serde_json::Value>)> {
        super::claims::allowed(&s, &peer).map_err(reject)?;
        s.finality_query(request).await.map(Json).map_err(reject)
    }
    async fn observe(
        State(s): State<Arc<Service>>,
        Extension(peer): Extension<PeerIdentity>,
        Json(proof): Json<Signed<QueryReply>>,
    ) -> Result<Json<Signed<Query>>, (StatusCode, Json<serde_json::Value>)> {
        super::claims::allowed(&s, &peer).map_err(reject)?;
        s.finality_observe(proof).await.map(Json).map_err(reject)
    }
    async fn complete(
        State(s): State<Arc<Service>>,
        Extension(peer): Extension<PeerIdentity>,
        Json(completion): Json<FinalityCompletion>,
    ) -> Result<Json<Signed<FinalityReady>>, (StatusCode, Json<serde_json::Value>)> {
        super::claims::allowed(&s, &peer).map_err(reject)?;
        s.finality_complete(completion)
            .await
            .map(Json)
            .map_err(reject)
    }
    async fn recover(
        State(s): State<Arc<Service>>,
        Extension(peer): Extension<PeerIdentity>,
        Json(request): Json<FinalityRequest>,
    ) -> Result<Json<Option<Signed<FinalityReady>>>, (StatusCode, Json<serde_json::Value>)> {
        super::claims::allowed(&s, &peer).map_err(reject)?;
        s.finality_recover(request).await.map(Json).map_err(reject)
    }
    Router::new()
        .route("/internal/v1/solana/finality/query", post(query))
        .route("/internal/v1/solana/finality/observe", post(observe))
        .route("/internal/v1/solana/finality/complete", post(complete))
        .route("/internal/v1/solana/finality/recover", post(recover))
        .layer(DefaultBodyLimit::max(512 * 1024))
        .with_state(s)
}
