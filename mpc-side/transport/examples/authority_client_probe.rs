//! Real TLS adversarial acceptance probe. Input is public canary data only.
use anyhow::{ensure, Result};
use wallet_mpc_transport::{AuthorityClient, TlsConfig};
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 5, "ca cert key addr witness-pin required");
    let tls = TlsConfig {
        ca: args[0].clone(),
        cert: args[1].clone(),
        key: args[2].clone(),
    };
    let client = AuthorityClient::new(
        &tls,
        "signer-a",
        args[3].parse()?,
        "localhost".into(),
        &args[4],
    )?;
    let response = client
        .request(
            "/v1/witness/record",
            br#"{"canary":"must-not-reach-an-unpinned-server"}"#.to_vec(),
        )
        .await?;
    ensure!(response == b"{}", "unexpected canary response");
    Ok(())
}
