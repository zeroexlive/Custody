//! Independent finalized account/fee/rent checks before every private round.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use wallet_mpc_protocol::{
    solana_intent::{Action, Intent},
    solana_provisioning::Asset,
    solana_seeded::{associated_address, key},
};
use wallet_mpc_transport::solana_rpc::SolanaRpc;

const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SYSTEM: &str = "11111111111111111111111111111111";
async fn account(rpc: &SolanaRpc, address: &str) -> Result<Option<Value>> {
    let value = rpc
        .call(
            "getAccountInfo",
            json!([address,{"commitment":"finalized","encoding":"base64"}]),
        )
        .await?;
    let value = value.get("value").context("missing account value")?;
    if value.is_null() {
        return Ok(None);
    }
    ensure!(
        value.is_object() && value["executable"] == false && value["lamports"].is_u64(),
        "invalid account evidence"
    );
    Ok(Some(value.clone()))
}
fn data(account: &Value, owner: &str, len: usize) -> Result<Vec<u8>> {
    ensure!(
        account["owner"] == owner
            && account["data"].as_array().is_some_and(|a| a.len() == 2)
            && account["data"][1] == "base64",
        "unexpected account program/encoding"
    );
    let bytes = base64::decode(
        account["data"][0]
            .as_str()
            .context("account data encoding")?,
    )?;
    ensure!(bytes.len() == len, "unexpected account size");
    Ok(bytes)
}
fn token(account: &Value, mint: &str, owner: &str) -> Result<u64> {
    let b = data(account, TOKEN, 165)?;
    ensure!(
        b[..32] == key(mint)? && b[32..64] == key(owner)? && b[108] == 1,
        "token mint/authority/state mismatch"
    );
    Ok(u64::from_le_bytes(b[64..72].try_into()?))
}
pub(super) async fn verify(rpc: &SolanaRpc, i: &Intent, payload: &[u8]) -> Result<()> {
    ensure!(
        rpc.call("getGenesisHash", json!([])).await?.as_str() == Some(&i.claim.root.genesis_hash),
        "independent genesis mismatch"
    );
    let height = rpc
        .call("getBlockHeight", json!([{"commitment":"finalized"}]))
        .await?
        .as_u64()
        .context("block height")?;
    ensure!(
        height <= i.last_valid_block_height,
        "original blockhash height expired"
    );
    ensure!(
        rpc.call(
            "isBlockhashValid",
            json!([i.recent_blockhash,{"commitment":"finalized"}])
        )
        .await?["value"]
            == true,
        "blockhash not currently valid"
    );
    let fee = rpc
        .call(
            "getFeeForMessage",
            json!([base64::encode(payload),{"commitment":"finalized"}]),
        )
        .await?["value"]
        .as_u64()
        .context("missing current fee")?;
    ensure!(fee == i.expected_fee_lamports, "independent fee mismatch");
    let payer = account(rpc, &i.fee_payer)
        .await?
        .context("base fee payer absent")?;
    data(&payer, SYSTEM, 0)?;
    ensure!(
        payer["lamports"].as_u64().context("base balance")?
            >= fee
                .checked_add(i.expected_rent_lamports)
                .context("fee/rent overflow")?,
        "insufficient base fee/rent funds"
    );
    let source = account(rpc, &i.financial_source).await?;
    match (&i.action, &i.claim.asset) {
        (Action::NativeTransfer { amount, .. }, Asset::Native) => {
            let source = source.context("native source absent")?;
            data(&source, SYSTEM, 0)?;
            ensure!(
                source["lamports"].as_u64().context("source balance")? >= *amount,
                "insufficient financial source funds"
            );
        }
        (action, Asset::ClassicToken { mint, decimals }) => {
            let mint_account = account(rpc, mint).await?.context("mint absent")?;
            let mint_data = data(&mint_account, TOKEN, 82)?;
            ensure!(
                mint_data[44] == *decimals && mint_data[45] == 1,
                "mint precision/initialization mismatch"
            );
            match action {
                Action::CreateClassicToken { rent_lamports } => {
                    ensure!(
                        source.is_none(),
                        "existing token address requires original transaction reconciliation"
                    );
                    let rent = rpc
                        .call(
                            "getMinimumBalanceForRentExemption",
                            json!([165,{"commitment":"finalized"}]),
                        )
                        .await?
                        .as_u64()
                        .context("current rent")?;
                    ensure!(
                        rent == *rent_lamports && rent == i.expected_rent_lamports,
                        "independent token creation rent mismatch"
                    );
                }
                Action::ClassicTransfer {
                    destination_owner,
                    amount,
                    create_ata,
                } => {
                    ensure!(
                        token(&source.context("token source absent")?, mint, &i.fee_payer)?
                            >= *amount,
                        "insufficient token source"
                    );
                    let address =
                        bs58::encode(associated_address(&key(destination_owner)?, &key(mint)?)?)
                            .into_string();
                    let target = account(rpc, &address).await?;
                    let required = if let Some(t) = target {
                        token(&t, mint, destination_owner)?;
                        0
                    } else {
                        ensure!(*create_ata, "token destination absent without creation");
                        rpc.call(
                            "getMinimumBalanceForRentExemption",
                            json!([165,{"commitment":"finalized"}]),
                        )
                        .await?
                        .as_u64()
                        .context("ATA rent")?
                    };
                    ensure!(
                        required == i.expected_rent_lamports,
                        "independent ATA rent mismatch"
                    );
                }
                _ => anyhow::bail!("token action mismatch"),
            }
        }
        _ => anyhow::bail!("financial source asset mismatch"),
    }
    Ok(())
}
