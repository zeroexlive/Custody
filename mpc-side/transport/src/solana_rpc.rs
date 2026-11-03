//! Bounded loopback-only JSON-RPC for explicitly isolated Solana development.
//! The caller independently pins the genesis artifact; RPC never establishes it.
use anyhow::{ensure, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration};

#[derive(Clone)]
pub struct SolanaRpc {
    address: SocketAddr,
}
impl SolanaRpc {
    pub fn new(address: SocketAddr) -> Result<Self> {
        ensure!(
            address.ip().is_loopback(),
            "isolated RPC must use a pinned loopback destination"
        );
        Ok(Self { address })
    }
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        ensure!(
            [
                "getGenesisHash",
                "getBlockHeight",
                "isBlockhashValid",
                "getFeeForMessage",
                "getMinimumBalanceForRentExemption",
                "getAccountInfo"
            ]
            .contains(&method),
            "unsupported isolated RPC operation"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            let stream = tokio::net::TcpStream::connect(self.address).await?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
            let task = super::AbortOnDrop(tokio::spawn(async move {
                let _ = connection.await;
            }));
            let request = hyper::Request::builder()
                .method("POST")
                .uri("/")
                .header("Host", self.address.to_string())
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
                )?)))?;
            let response = sender.send_request(request).await?;
            ensure!(
                response.status() == hyper::StatusCode::OK,
                "isolated RPC HTTP failure"
            );
            let body = Limited::new(response.into_body(), 1024 * 1024)
                .collect()
                .await
                .map_err(|_| anyhow::anyhow!("isolated RPC response bounds"))?
                .to_bytes();
            let value: Value = serde_json::from_slice(&body)?;
            ensure!(
                value["jsonrpc"] == "2.0"
                    && value["id"] == 1
                    && value.get("error").is_none()
                    && value.get("result").is_some(),
                "invalid isolated RPC response"
            );
            drop(task);
            Ok(value["result"].clone())
        })
        .await?
    }
}
