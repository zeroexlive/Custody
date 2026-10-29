//! Required-profile entrypoint. No insecure mode or generic signing router.
use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Extension, Json, Router,
};
use std::{path::Path, sync::Arc};
use wallet_mpc_protocol::{
    dkg::DkgRequest,
    solana_provisioning::Root,
    witness::{Permit, Signed},
};
use wallet_mpc_signer::{
    dkg::DkgService,
    protected::{Control, Profile, Service},
    solana_provisioning, ExecutionTombstones, SignerStore, PROTOCOL_VERSION,
};
use wallet_mpc_transport::{
    serve_roles_in, Capabilities, CustodyRequestVerifier, PeerIdentity, ReceiptIdentity,
    SignerClient, ROLES,
};

fn reject(_: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error":"protected signing rejected; retain original execution"})),
    )
}
async fn automatic(
    State(s): State<Arc<Service>>,
    body: Bytes,
) -> Result<Json<impl serde::Serialize>, (StatusCode, Json<serde_json::Value>)> {
    let control: Control = serde_json::from_slice(&body).map_err(|e| reject(e.into()))?;
    s.automatic(control).await.map(Json).map_err(reject)
}
async fn challenge(
    State(s): State<Arc<Service>>,
    body: Bytes,
) -> Result<Json<impl serde::Serialize>, (StatusCode, Json<serde_json::Value>)> {
    let control: Control = serde_json::from_slice(&body).map_err(|e| reject(e.into()))?;
    s.challenge(control).await.map(Json).map_err(reject)
}
async fn apply(
    State(s): State<Arc<Service>>,
    body: Bytes,
) -> Result<Json<impl serde::Serialize>, (StatusCode, Json<serde_json::Value>)> {
    let permit: Signed<Permit> = serde_json::from_slice(&body).map_err(|e| reject(e.into()))?;
    s.apply(permit).await.map(Json).map_err(reject)
}
async fn recover(
    State(s): State<Arc<Service>>,
    body: Bytes,
) -> Result<Json<impl serde::Serialize>, (StatusCode, Json<serde_json::Value>)> {
    let control: Control = serde_json::from_slice(&body).map_err(|e| reject(e.into()))?;
    s.recover(&control).await.map(Json).map_err(reject)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.is_empty() || args == ["--initialize"],
        "only explicit --initialize is supported"
    );
    let profile_path = std::env::var("MPC_PROTECTED_PROFILE")?;
    let (profile, fingerprint) = Profile::load(Path::new(&profile_path))?;
    let tls = profile.tls.clone();
    let party = profile.signer.party_id.clone();
    let class = profile.class.clone();
    let store = SignerStore::open(profile.signer.clone())?;
    let executions =
        ExecutionTombstones::open(profile.signer.storage_directory.join("executions"))?;
    let peers = SignerClient::with_targets(&tls, &party, profile.peer_targets.clone())?;
    let dkg = DkgService::open(store, executions, peers.clone())?;
    let provisioning = solana_provisioning::Service::open(
        profile.signer.storage_directory.clone(),
        party.clone(),
        dkg.clone(),
        CustodyRequestVerifier::for_role(&profile.policy.custody_ca, "custody", &ROLES)?,
        Some(ReceiptIdentity::new(&tls, &party)?),
    )?;
    let bind = profile.bind;
    const PROTECTED_ROLES: [&str; 6] = [
        "custody",
        "coordinator",
        "signer-a",
        "signer-b",
        "signer-c",
        "courier",
    ];
    let server = tls.server_in(&party, &PROTECTED_ROLES)?;
    let service = Service::open(
        profile,
        fingerprint,
        dkg.clone(),
        provisioning.clone(),
        !args.is_empty(),
    )?;
    let refresh = wallet_mpc_signer::protected::refresh::Service::open(service.clone(), peers);
    let capabilities = Capabilities {
        signer_identity: party,
        protocol_version: PROTOCOL_VERSION.into(),
        supported_algorithms: vec!["FROST_ED25519".into()],
        service_ready: true,
    };
    let protected_class = class.clone();
    let protected = Router::new()
        .route("/internal/v1/solana/protected/auto", post(automatic))
        .route("/internal/v1/solana/protected/challenge", post(challenge))
        .route("/internal/v1/solana/protected/apply", post(apply))
        .route("/internal/v1/solana/protected/recover", post(recover))
        .route_layer(middleware::from_fn(
            move |Extension(peer): Extension<PeerIdentity>,
                  request: axum::extract::Request,
                  next: Next| {
                let class = protected_class.clone();
                async move {
                    if peer.role() != "coordinator"
                        && !(class == "COLD" && peer.role() == "courier")
                    {
                        return Err(StatusCode::FORBIDDEN);
                    }
                    Ok(next.run(request).await)
                }
            },
        ))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(service);
    let provisioning_and_dkg = wallet_mpc_signer::dkg::router(dkg)
        .merge(solana_provisioning::router(provisioning))
        .route_layer(middleware::from_fn(
            move |request: axum::extract::Request, next: Next| {
                let class = class.clone();
                async move {
                    if request.uri().path().ends_with("/dkg/message") {
                        return Ok::<Response, StatusCode>(next.run(request).await);
                    }
                    let path = request.uri().path().to_owned();
                    let (parts, body) = request.into_parts();
                    let bytes = to_bytes(body, 64 * 1024)
                        .await
                        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
                    let allowed = if path.contains("/dkg/") {
                        serde_json::from_slice::<DkgRequest>(&bytes).is_ok_and(|r| {
                            r.is_frost()
                                && r.scope == "SOLANA"
                                && r.custody_class.as_deref() == Some(class.as_str())
                        })
                    } else {
                        let value: serde_json::Value =
                            serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
                        let statement = &value["statement"];
                        let root = statement.get("root").unwrap_or(statement);
                        serde_json::from_value::<Root>(root.clone())
                            .is_ok_and(|r| r.wallet_class == class && r.validate().is_ok())
                    };
                    if !allowed {
                        return Err(StatusCode::CONFLICT);
                    }
                    Ok(next
                        .run(axum::extract::Request::from_parts(parts, Body::from(bytes)))
                        .await)
                }
            },
        ));
    let app = Router::new()
        .route(
            "/internal/v1/capabilities",
            get(move || {
                let metadata = capabilities.clone();
                async move { Json(metadata) }
            }),
        )
        .merge(provisioning_and_dkg)
        .merge(protected)
        .merge(wallet_mpc_signer::protected::refresh::router(refresh));
    serve_roles_in(
        bind,
        server,
        app,
        &["coordinator", "signer-a", "signer-b", "signer-c", "courier"],
        &PROTECTED_ROLES,
    )
    .await
}
