use serde_json::Value;
use wallet_mpc_protocol::{
    sign::decode_hex,
    solana_seeded::{self as wire, Operation},
};
#[test]
fn independent_solders_sdk_wire_and_addresses() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/solana-seeded-sdk.json")).unwrap();
    assert_eq!(cases.len(), 15, "preserve the complete SDK fixture matrix");
    for c in cases {
        let base = wire::key(c["base"].as_str().unwrap()).unwrap();
        let block = wire::key(c["blockhash"].as_str().unwrap()).unwrap();
        let index = c["index"].as_u64().unwrap();
        let op = match c["kind"].as_str().unwrap() {
            "native" => Operation::Native {
                destination: wire::key(c["destination"].as_str().unwrap()).unwrap(),
                amount: c["amount"].as_u64().unwrap(),
            },
            "create_token" => Operation::CreateToken {
                mint: wire::key(c["mint"].as_str().unwrap()).unwrap(),
                rent: c["amount"].as_u64().unwrap(),
            },
            _ => Operation::Token {
                mint: wire::key(c["mint"].as_str().unwrap()).unwrap(),
                destination_owner: wire::key(c["destination"].as_str().unwrap()).unwrap(),
                amount: c["amount"].as_u64().unwrap(),
                decimals: u8::try_from(c["decimals"].as_u64().unwrap()).unwrap(),
                create_ata: c["create_ata"].as_bool().unwrap(),
            },
        };
        let source = wire::address(&base, index, c["kind"] != "native").unwrap();
        assert_eq!(
            bs58::encode(source).into_string(),
            c["source"].as_str().unwrap()
        );
        let raw = decode_hex(c["message_hex"].as_str().unwrap()).unwrap();
        wire::validate(&raw, base, index, block, &op)
            .unwrap_or_else(|e| panic!("kind={} index={index}: {e}", c["kind"]));
        assert!(wire::validate(&raw, base, index ^ 1, block, &op).is_err());
        let mut wrongblock = block;
        wrongblock[0] ^= 1;
        assert!(wire::validate(&raw, base, index, wrongblock, &op).is_err());
        let mut wrong_op = op.clone();
        match &mut wrong_op {
            Operation::Native { amount, .. } | Operation::Token { amount, .. } => *amount += 1,
            Operation::CreateToken { rent, .. } => *rent += 1,
        }
        assert!(wire::validate(&raw, base, index, block, &wrong_op).is_err());
        assert!(wire::validate(&raw, [0; 32], index, block, &op).is_err());
        assert!(wire::validate(&raw, base, u64::MAX, block, &op).is_err());
        for short in [
            vec![raw[3] | 128, 0],
            vec![128, 128, 4],
            vec![128, 128, 128, 0],
        ] {
            let mut malformed = raw.clone();
            malformed.splice(3..4, short);
            assert!(wire::validate(&malformed, base, index, block, &op).is_err());
        }
        if let Some(permuted) = permute_same_permission_keys(&raw) {
            assert!(wire::validate(&permuted, base, index, block, &op).is_err());
        }
        for n in 0..raw.len() {
            assert!(wire::validate(&raw[..n], base, index, block, &op).is_err());
        }
        let mut extra = raw.clone();
        extra.push(0);
        assert!(wire::validate(&extra, base, index, block, &op).is_err());
        for i in 0..raw.len() {
            let mut changed = raw.clone();
            changed[i] ^= 1;
            assert!(
                wire::validate(&changed, base, index, block, &op).is_err(),
                "accepted byte change at {i}"
            );
        }
    }
}

// Coordinated permutation preserves public instruction meaning and permission
// groups. It still must not replace the exact SDK-compiled approved bytes.
fn permute_same_permission_keys(raw: &[u8]) -> Option<Vec<u8>> {
    let count = usize::from(raw[3]);
    assert!(count < 128); // These fixed SDK fixtures use single-byte shortvecs.
    let readonly = usize::from(raw[2]);
    let (a, b) = if readonly >= 2 {
        (count - 2, count - 1)
    } else if count - readonly >= 3 {
        (1, 2)
    } else {
        return None;
    };
    let mut out = raw.to_vec();
    for i in 0..32 {
        out.swap(4 + a * 32 + i, 4 + b * 32 + i);
    }
    fn remap(index: &mut u8, a: usize, b: usize) {
        if usize::from(*index) == a {
            *index = b as u8;
        } else if usize::from(*index) == b {
            *index = a as u8;
        }
    }
    let mut cursor = 4 + count * 32 + 32;
    let instructions = out[cursor];
    cursor += 1;
    for _ in 0..instructions {
        remap(&mut out[cursor], a, b);
        cursor += 1;
        let accounts = usize::from(out[cursor]);
        cursor += 1;
        for index in &mut out[cursor..cursor + accounts] {
            remap(index, a, b);
        }
        cursor += accounts;
        let data = usize::from(out[cursor]);
        assert!(data < 128);
        cursor += 1 + data;
    }
    assert_eq!(cursor, out.len());
    Some(out)
}
