//! Independent authority process. Its private identity/configuration and journal
//! are separate from the signer backup; no MPC private share is handled here.
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use std::sync::Arc;
use wallet_mpc_protocol::witness::{Command, PermitRequest, PublicRound, Query, Signed};
use wallet_mpc_transport::{serve_roles_in, PeerIdentity, AUTHORITY_ROLES};
use wallet_mpc_witness::{Authority, AuthorityConfig};

fn reject(_: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error":"authority request rejected; retain original operation"})),
    )
}
async fn command(
    State(a): State<Arc<Authority>>,
    Extension(peer): Extension<PeerIdentity>,
    Json(value): Json<Signed<Command>>,
) -> Result<Json<impl serde::Serialize>, (StatusCode, Json<serde_json::Value>)> {
    if peer.role() != "lifecycle" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"lifecycle issuer required"})),
        ));
    }
    a.command(value).await.map(Json).map_err(reject)
}
async fn permit(
    State(a): State<Arc<Authority>>,
    Extension(peer): Extension<PeerIdentity>,
    Json(value): Json<Signed<PermitRequest>>,
) -> Result<Json<impl serde::Serialize>, (StatusCode, Json<serde_json::Value>)> {
    if peer.role() != value.value.party_id && peer.role() != "courier" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error":"original signer transport or authenticated courier required"}),
            ),
        ));
    }
    a.permit(value).await.map(Json).map_err(reject)
}
async fn record(
    State(a): State<Arc<Authority>>,
    Json(value): Json<Signed<PublicRound>>,
) -> Result<Json<impl serde::Serialize>, (StatusCode, Json<serde_json::Value>)> {
    a.record(value).await.map(Json).map_err(reject)
}
async fn query(
    State(a): State<Arc<Authority>>,
    Json(value): Json<Signed<Query>>,
) -> Result<Json<impl serde::Serialize>, (StatusCode, Json<serde_json::Value>)> {
    a.query(value).await.map(Json).map_err(reject)
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    anyhow::ensure!(
        args.is_empty() || args == ["--initialize"],
        "only explicit --initialize is supported"
    );
    let path = std::env::var("MPC_WITNESS_CONFIG")?;
    let config: AuthorityConfig = serde_json::from_slice(&std::fs::read(path)?)?;
    let server = config.tls().server_in("witness", &AUTHORITY_ROLES)?;
    let bind = config.bind;
    let authority = Arc::new(Authority::open(config, !args.is_empty())?);
    let router = Router::new()
        .route("/v1/witness/command", post(command))
        .route("/v1/witness/permit", post(permit))
        .route("/v1/witness/record", post(record))
        .route("/v1/witness/query", post(query))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(authority);
    serve_roles_in(
        bind,
        server,
        router,
        &["lifecycle", "signer-a", "signer-b", "signer-c", "courier"],
        &AUTHORITY_ROLES,
    )
    .await
}
