//! Public-message acceptance helper; never signs or loads a private share.
use serde_json::Value;
use std::io::Read;
use wallet_mpc_protocol::{
    sign::decode_hex,
    solana_seeded::{self as w, Operation},
};
fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let c: Value = serde_json::from_str(&input).unwrap();
    let key = |field: &str| w::key(c[field].as_str().unwrap()).unwrap();
    let op = match c["kind"].as_str().unwrap() {
        "native" => Operation::Native {
            destination: key("destination"),
            amount: c["amount"].as_u64().unwrap(),
        },
        "create_token" => Operation::CreateToken {
            mint: key("mint"),
            rent: c["amount"].as_u64().unwrap(),
        },
        "token" => Operation::Token {
            mint: key("mint"),
            destination_owner: key("destination"),
            amount: c["amount"].as_u64().unwrap(),
            decimals: u8::try_from(c["decimals"].as_u64().unwrap()).unwrap(),
            create_ata: c["create_ata"].as_bool().unwrap(),
        },
        _ => panic!("unsupported public operation"),
    };
    let raw = decode_hex(c["message_hex"].as_str().unwrap()).unwrap();
    w::validate(
        &raw,
        key("base"),
        c["index"].as_u64().unwrap(),
        key("blockhash"),
        &op,
    )
    .unwrap();
    println!("verified");
}
