use std::{path::PathBuf, sync::Arc};
use wallet_mpc_coordinator::{app, network_app, phase6a_insecure_local_listener, DurableStore};
use wallet_mpc_transport::{required, serve, SignerClient, TlsConfig};
#[tokio::main]
async fn main() {
    let local_development = std::env::var("MPC_INSECURE_LOCAL_DEV").as_deref() == Ok("true");
    let path = std::env::var_os("MPC_COORDINATOR_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/wallet-mpc/coordinator.json"));
    let store = Arc::new(DurableStore::open(path).expect("open durable coordinator state"));
    let protected_profile = std::env::var("MPC_SOLANA_PROTECTED_COORDINATOR_PROFILE").ok();
    if local_development {
        assert!(
            protected_profile.is_none(),
            "protected financial signing requires authenticated transport"
        );
        let bind = phase6a_insecure_local_listener(true).unwrap();
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        axum::serve(listener, app(store)).await.unwrap();
    } else {
        let tls = TlsConfig::from_env().expect("mTLS configuration required");
        let server = tls
            .server("coordinator")
            .expect("coordinator TLS configuration invalid");
        if protected_profile.is_some() {
            for suffix in ["A", "B", "C"] {
                let address: std::net::SocketAddr = required(&format!("MPC_SIGNER_{suffix}_ADDR"))
                    .expect("explicit isolated signer target required")
                    .parse()
                    .expect("isolated signer socket address required");
                assert!(
                    address.ip().is_loopback(),
                    "protected peers must be loopback"
                );
            }
        }
        let signers =
            SignerClient::from_env(&tls).expect("authenticated signer destinations required");
        let bind = required("MPC_BIND_ADDR")
            .unwrap()
            .parse()
            .expect("invalid bind address");
        let app = if let Some(path) = protected_profile {
            let bind_address: std::net::SocketAddr = bind;
            assert!(
                bind_address.ip().is_loopback(),
                "protected coordinator is isolated-development only"
            );
            let config: wallet_mpc_coordinator::solana_protected::Config = serde_json::from_slice(
                &std::fs::read(path).expect("read protected coordinator profile"),
            )
            .expect("explicit protected coordinator profile");
            let protected =
                wallet_mpc_coordinator::solana_protected::Service::open(config, signers.clone())
                    .expect("verify protected public coordinator history");
            network_app(store, signers)
                .merge(wallet_mpc_coordinator::solana_protected::router(protected))
        } else {
            network_app(store, signers)
        };
        serve(bind, server, app, "custody").await.unwrap();
    }
}
