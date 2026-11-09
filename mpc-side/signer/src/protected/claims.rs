//! Public current-identity receipts. No FROST nonce, signature or broadcast.
use super::{journal, now, Local, Service};
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
    solana_claim_authority::{
        ClaimQueryLease, CurrentClaimApproval, CurrentClaimControl, CurrentClaimGrant,
    },
    solana_provisioning::{Claim, Report},
    witness::{Query, QueryReply, Signed},
};
use wallet_mpc_transport::PeerIdentity;

fn slot(approval: &CurrentClaimApproval) -> Result<String> {
    Ok(approval.authority.identity(&approval.statement.root)?
        + ":"
        + &approval.statement.reservation_id.to_string())
}

impl Service {
    fn authorize_current_claim(
        &self,
        approval: &CurrentClaimApproval,
        time: u64,
        live: bool,
    ) -> Result<()> {
        let life = self
            .lifecycle
            .as_ref()
            .context("explicit Lifecycle current-Claim capability required")?;
        self.require_migration_root(&approval.statement.root)?;
        self.policy
            .current_claim_approval(&self.profile.class, approval, life, time, live)
    }

    pub(super) fn current_claim_profile(&self, local: &Local, view: &QueryReply) -> Result<()> {
        let party = &self.profile.signer.party_id;
        let pin = view.node_profiles.get(party);
        if let Some(pin) = pin {
            pin.validate_shape()?;
            ensure!(
                pin.node_key_id == self.own.key_id && pin.profile_sha256 == self.fingerprint,
                "current Claim requires exact current profile provenance"
            );
        }
        if let Some(bootstrap) = &self.profile.profile_migration {
            let pin = pin.context("migrated current Claim source requires W profile pin")?;
            let source = local
                .journal
                .records
                .profile_migration_source
                .as_ref()
                .context("original profile source provenance missing")?;
            ensure!(
                pin.anchor_id == bootstrap.anchor_id
                    && pin.authority_id == bootstrap.migration_id
                    && pin.source_fence_sha256 == source.fence.value.identity()?,
                "original current Claim profile source fence required"
            );
        }
        if let Some(bootstrap) = &self.profile.replacement_bootstrap {
            let pin = pin.context("replacement current Claim source requires W profile pin")?;
            let source = self
                .provenance
                .get()
                .context("replacement provenance missing")?;
            ensure!(
                pin.anchor_id == bootstrap.anchor_id
                    && pin.authority_id == source.plan.value.repair_ceremony_id
                    && pin.source_fence_sha256 == source.plan.value.identity()?,
                "original replacement profile provenance required"
            );
        }
        Ok(())
    }

    pub async fn current_claim_recover(
        &self,
        approval: &CurrentClaimApproval,
    ) -> Result<Option<Report<Claim>>> {
        // Read-only recovery verifies the original public authorization without
        // requiring the historical receipt roster to be today's signer roster.
        self.authorize_current_claim(approval, approval.issued_at, false)?;
        let local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "current Claim history uncertain");
        let Some(grant) = local
            .journal
            .records
            .current_claim_grants
            .get(&slot(approval)?)
        else {
            return Ok(None);
        };
        ensure!(
            grant.report.statement == approval.statement,
            "original current Claim cannot change"
        );
        Ok(Some(grant.report.clone()))
    }

    pub async fn current_claim_query(
        &self,
        approval: CurrentClaimApproval,
    ) -> Result<Signed<Query>> {
        self.authorize_current_claim(&approval, now()?, true)?;
        self.require_root(&approval.statement.root).await?;
        let mut local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "current Claim history uncertain");
        let _original = self
            .provisioning
            .current_aliases_compatible(&approval.statement)
            .await?;
        let time = now()?;
        self.authorize_current_claim(&approval, time, true)?;
        let party = &self.profile.signer.party_id;
        let (_, keys) = approval.authority.prepared()?;
        ensure!(
            keys[party] == self.own.key_id,
            "actual current receipt identity required"
        );
        local
            .journal
            .records
            .current_claim_compatible(&approval.statement)?;
        let body = approval.message()?;
        for lease in local.journal.records.current_claim_queries.values() {
            if time < lease.expires_at && lease.approval.message()? == body {
                return Ok(lease.query.clone());
            }
        }
        ensure!(
            local
                .journal
                .records
                .current_claim_queries
                .values()
                .filter(|lease| time < lease.expires_at)
                .count()
                < 32,
            "too many current Claim queries"
        );
        let mut nonce = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let query = journal::sign(
            &self.identity,
            "WITNESS_QUERY_V1",
            Query {
                anchor_id: self.profile.witness_anchor,
                root_identity: approval.statement.root.identity()?,
                challenge: hex(&nonce),
                execution_id: None,
                claim_reservation_id: Some(approval.statement.reservation_id),
                candidate_claim: Some(Box::new(approval.statement.clone())),
            },
        )?;
        let lease = ClaimQueryLease {
            approval,
            query: query.clone(),
            issued_at: time,
            expires_at: time.checked_add(15).context("query time overflow")?,
        };
        self.append(
            &mut local,
            journal::Change::CurrentClaimQuery {
                lease: Box::new(lease),
            },
        )?;
        Ok(query)
    }

    pub async fn current_claim_approve(
        &self,
        control: CurrentClaimControl,
    ) -> Result<Report<Claim>> {
        if let Some(report) = self.current_claim_recover(&control.approval).await? {
            return Ok(report);
        }
        self.authorize_current_claim(&control.approval, now()?, true)?;
        let proof = if let Some(proof) = control.witness {
            proof
        } else {
            let client = self
                .client
                .as_ref()
                .context("COLD requires explicit current Claim courier query")?;
            let query = self.current_claim_query(control.approval.clone()).await?;
            serde_json::from_slice::<Signed<QueryReply>>(
                &client
                    .request("/v1/witness/query", serde_json::to_vec(&query)?)
                    .await?,
            )?
        };
        journal::verify(&self.witness, "WITNESS_QUERY_REPLY_V1", &proof)?;
        self.require_root(&control.approval.statement.root).await?;
        let mut local = self.local.lock().await;
        ensure!(!local.journal.poisoned, "current Claim history uncertain");
        let _original = self
            .provisioning
            .current_aliases_compatible(&control.approval.statement)
            .await?;
        if let Some(grant) = local
            .journal
            .records
            .current_claim_grants
            .get(&slot(&control.approval)?)
        {
            ensure!(
                grant.report.statement == control.approval.statement,
                "original current Claim cannot change"
            );
            return Ok(grant.report.clone());
        }
        let lease = local
            .journal
            .records
            .current_claim_queries
            .get(&proof.value.query.challenge)
            .context("original current Claim query required")?
            .clone();
        ensure!(
            lease.approval.message()? == control.approval.message()?,
            "original current Claim request required"
        );
        self.current_claim_profile(&local, &proof.value)?;
        local
            .journal
            .records
            .current_claim_compatible(&control.approval.statement)?;
        let authority = &control.approval.authority;
        let generation = authority.generation()?;
        let ready = local
            .journal
            .records
            .ready
            .get(&generation.ceremony_id)
            .context("committed current generation required; staging cannot approve")?;
        ensure!(
            ready.value.generation == *generation
                && ready.value.root_identity == control.approval.statement.root.identity()?,
            "exact committed current generation required"
        );
        let (key, public) = self
            .generation_store
            .load(&control.approval.statement.root, generation)?;
        drop(key);
        ensure!(
            public == ready.value.public_key_package,
            "current generation artifact mismatch"
        );
        let time = now()?;
        self.authorize_current_claim(&control.approval, time, true)?;
        lease.validate_new_report(&proof.value, &self.profile.signer.party_id, time)?;
        _original.fence_legacy_frontier(
            &control.approval.statement.root,
            &authority.identity(&control.approval.statement.root)?,
        )?;
        let time = now()?;
        self.authorize_current_claim(&control.approval, time, true)?;
        lease.validate_new_report(&proof.value, &self.profile.signer.party_id, time)?;
        let report = Report {
            statement: control.approval.statement.clone(),
            party_id: self.profile.signer.party_id.clone(),
            durable: true,
            signer_signature: hex(&self.identity.sign(
                &wallet_mpc_protocol::solana_claim_authority::receipt_message(
                    authority,
                    &control.approval.statement,
                    &self.profile.signer.party_id,
                )?,
            )?),
        };
        self.append(
            &mut local,
            journal::Change::CurrentClaimReport {
                grant: Box::new(CurrentClaimGrant {
                    lease_challenge: proof.value.query.challenge.clone(),
                    witness: proof,
                    report: report.clone(),
                    granted_at: time,
                }),
            },
        )?;
        Ok(report)
    }
}

fn reject(_: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(
            serde_json::json!({"error":"current Claim rejected; retain original Claim and authority IDs"}),
        ),
    )
}

pub(super) fn allowed(s: &Service, peer: &PeerIdentity) -> Result<()> {
    ensure!(
        peer.role()
            == if s.profile.class == "COLD" {
                "courier"
            } else {
                "coordinator"
            },
        "exact current Claim class caller required"
    );
    Ok(())
}

pub fn router(s: Arc<Service>) -> Router {
    if s.lifecycle.is_none() {
        return Router::new();
    }
    async fn query(
        State(s): State<Arc<Service>>,
        Extension(peer): Extension<PeerIdentity>,
        Json(approval): Json<CurrentClaimApproval>,
    ) -> Result<Json<Signed<Query>>, (StatusCode, Json<serde_json::Value>)> {
        allowed(&s, &peer).map_err(reject)?;
        s.current_claim_query(approval)
            .await
            .map(Json)
            .map_err(reject)
    }
    async fn approve(
        State(s): State<Arc<Service>>,
        Extension(peer): Extension<PeerIdentity>,
        Json(control): Json<CurrentClaimControl>,
    ) -> Result<Json<Report<Claim>>, (StatusCode, Json<serde_json::Value>)> {
        allowed(&s, &peer).map_err(reject)?;
        s.current_claim_approve(control)
            .await
            .map(Json)
            .map_err(reject)
    }
    async fn recover(
        State(s): State<Arc<Service>>,
        Extension(peer): Extension<PeerIdentity>,
        Json(approval): Json<CurrentClaimApproval>,
    ) -> Result<Json<Option<Report<Claim>>>, (StatusCode, Json<serde_json::Value>)> {
        allowed(&s, &peer).map_err(reject)?;
        s.current_claim_recover(&approval)
            .await
            .map(Json)
            .map_err(reject)
    }
    Router::new()
        .route("/internal/v1/solana/current-claim/query", post(query))
        .route("/internal/v1/solana/current-claim/approve", post(approve))
        .route("/internal/v1/solana/current-claim/recover", post(recover))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(s)
}
