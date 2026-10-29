//! Public contract/SDK fixtures only, not accepted signing grants or live witness tests.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::hex,
    solana_intent::{Action, BusinessOperation, Intent, ValidationPolicy},
    solana_provisioning::Asset,
};

fn fixtures() -> Vec<Value> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/solana-seeded-intent-sdk.json")).unwrap();
    let mut cases = fixture["cases"].as_array().unwrap().clone();
    for case in &mut cases {
        case["intent"]["claim"]["root"] = fixture["root"].clone();
    }
    cases
}
fn policy(intent: &Intent) -> ValidationPolicy {
    ValidationPolicy {
        genesis_hash: intent.claim.root.genesis_hash.clone(),
        version: 7,
        max_fee_lamports: 20000,
        max_rent_lamports: 3000000,
        max_lifetime_seconds: 120,
    }
}
#[test]
fn sdk_wire_and_python_canonical_intent_match() {
    let cases = fixtures();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let intent: Intent = serde_json::from_value(case["intent"].clone()).unwrap();
        let payload = case["message_hex"].as_str().unwrap();
        let raw = wallet_mpc_protocol::sign::decode_hex(payload).unwrap();
        intent
            .validate_shape_and_wire(
                &raw,
                &intent.claim.root.public_key_package,
                1000,
                &policy(&intent),
            )
            .unwrap();
        assert_eq!(
            hex(&Sha256::digest(intent.custody_message(payload).unwrap())),
            case["custody_message_sha256"].as_str().unwrap(),
        );
    }
}
#[test]
fn source_authority_network_policy_and_time_fail_closed() {
    for case in fixtures() {
        let original: Intent = serde_json::from_value(case["intent"].clone()).unwrap();
        let raw =
            wallet_mpc_protocol::sign::decode_hex(case["message_hex"].as_str().unwrap()).unwrap();
        for field in ["financial_source", "fee_payer", "recent_blockhash"] {
            let mut changed = case["intent"].clone();
            changed[field] = json!(bs58::encode([2; 32]).into_string());
            let intent: Intent = serde_json::from_value(changed).unwrap();
            assert!(
                intent
                    .validate_shape_and_wire(
                        &raw,
                        &original.claim.root.public_key_package,
                        1000,
                        &policy(&original)
                    )
                    .is_err(),
                "accepted {field}"
            );
        }
        let mut changed = original.clone();
        changed.generation.public_key_package_sha256 = "00".repeat(32);
        assert!(changed
            .validate_shape_and_wire(
                &raw,
                &original.claim.root.public_key_package,
                1000,
                &policy(&original)
            )
            .is_err());
        for now in [0, 994, 1075, u64::MAX] {
            assert!(original
                .validate_shape_and_wire(
                    &raw,
                    &original.claim.root.public_key_package,
                    now,
                    &policy(&original)
                )
                .is_err());
        }
        let mut wrong_policy = policy(&original);
        wrong_policy.version += 1;
        assert!(original
            .validate_shape_and_wire(
                &raw,
                &original.claim.root.public_key_package,
                1000,
                &wrong_policy
            )
            .is_err());
        wrong_policy = policy(&original);
        wrong_policy.genesis_hash = bs58::encode([1; 32]).into_string();
        assert!(original
            .validate_shape_and_wire(
                &raw,
                &original.claim.root.public_key_package,
                1000,
                &wrong_policy
            )
            .is_err());
        wrong_policy = policy(&original);
        wrong_policy.max_fee_lamports = 4999;
        assert!(original
            .validate_shape_and_wire(
                &raw,
                &original.claim.root.public_key_package,
                1000,
                &wrong_policy
            )
            .is_err());
    }
}
#[test]
fn unknown_fields_and_bad_claim_semantics_are_rejected() {
    let case = fixtures().remove(0);
    let original: Intent = serde_json::from_value(case["intent"].clone()).unwrap();
    let raw = wallet_mpc_protocol::sign::decode_hex(case["message_hex"].as_str().unwrap()).unwrap();
    for path in [
        vec!["extra"],
        vec!["claim", "extra"],
        vec!["generation", "extra"],
        vec!["action", "extra"],
    ] {
        let mut value = case["intent"].clone();
        let mut leaf = &mut value;
        for k in &path[..path.len() - 1] {
            leaf = &mut leaf[*k];
        }
        leaf[path[path.len() - 1]] = json!(true);
        assert!(serde_json::from_value::<Intent>(value).is_err());
    }
    for (field, bad) in [
        ("attempt_id", json!(0)),
        ("operation_id", json!(0)),
        ("session_id", json!(Uuid::nil())),
        ("crypto_execution_id", json!(original.session_id)),
        ("asset_key", json!("nul\0key")),
        ("policy_version", json!(0)),
        ("expected_fee_lamports", json!(0)),
        ("last_valid_block_height", json!(0)),
        ("expected_rent_lamports", json!(1)),
        ("operation_type", json!("PROVISION")),
    ] {
        let mut value = case["intent"].clone();
        value[field] = bad;
        let intent: Intent = serde_json::from_value(value).unwrap();
        assert!(
            intent
                .validate_shape_and_wire(
                    &raw,
                    &original.claim.root.public_key_package,
                    1000,
                    &policy(&original)
                )
                .is_err(),
            "accepted {field}"
        );
    }
    for owner in ["unscoped-owner", "p1:00000000-0000-0000-0000-000000000000"] {
        let mut value = original.clone();
        value.claim.owner_ref = owner.into();
        assert!(value
            .validate_shape_and_wire(
                &raw,
                &original.claim.root.public_key_package,
                1000,
                &policy(&original)
            )
            .is_err());
    }
}
#[test]
fn matching_hash_does_not_bypass_independent_wire_decoding() {
    for case in fixtures() {
        let original: Intent = serde_json::from_value(case["intent"].clone()).unwrap();
        let raw =
            wallet_mpc_protocol::sign::decode_hex(case["message_hex"].as_str().unwrap()).unwrap();
        let mut changed = original.clone();
        let mut wire = raw.clone();
        let last = wire.len() - 1;
        wire[last] ^= 1;
        changed.message_fingerprint = hex(&Sha256::digest(&wire));
        assert!(changed
            .validate_shape_and_wire(
                &wire,
                &original.claim.root.public_key_package,
                1000,
                &policy(&original)
            )
            .is_err());
        changed = original.clone();
        changed.claim.index ^= 1;
        changed.financial_source = changed.claim.address().unwrap();
        assert!(changed
            .validate_shape_and_wire(
                &raw,
                &original.claim.root.public_key_package,
                1000,
                &policy(&original)
            )
            .is_err());
        if matches!(&changed.claim.asset, Asset::ClassicToken { .. }) {
            changed = original.clone();
            if let Asset::ClassicToken { mint, .. } = &mut changed.claim.asset {
                *mint = bs58::encode([3; 32]).into_string();
            }
            assert!(changed
                .validate_shape_and_wire(
                    &raw,
                    &original.claim.root.public_key_package,
                    1000,
                    &policy(&original)
                )
                .is_err());
        }
    }
}
#[test]
fn withdrawals_share_wire_but_have_a_distinct_machine_intent() {
    for case in fixtures() {
        let original: Intent = serde_json::from_value(case["intent"].clone()).unwrap();
        let payload = case["message_hex"].as_str().unwrap();
        let raw = wallet_mpc_protocol::sign::decode_hex(payload).unwrap();
        let mut withdrawal = original.clone();
        withdrawal.operation_type = BusinessOperation::Withdrawal;
        let result = withdrawal.validate_shape_and_wire(
            &raw,
            &original.claim.root.public_key_package,
            1000,
            &policy(&original),
        );
        if matches!(withdrawal.action, Action::CreateClassicToken { .. }) {
            assert!(result.is_err());
        } else {
            result.unwrap();
            assert_ne!(
                original.custody_message(payload).unwrap(),
                withdrawal.custody_message(payload).unwrap()
            );
        }
    }
}
#[test]
fn rent_lifetime_package_and_ceremony_bounds_are_enforced() {
    for case in fixtures() {
        let intent: Intent = serde_json::from_value(case["intent"].clone()).unwrap();
        let raw =
            wallet_mpc_protocol::sign::decode_hex(case["message_hex"].as_str().unwrap()).unwrap();
        let mut limited = policy(&intent);
        limited.max_lifetime_seconds = 79;
        assert!(intent
            .validate_shape_and_wire(&raw, &intent.claim.root.public_key_package, 1000, &limited)
            .is_err());
        if intent.expected_rent_lamports > 0 {
            limited = policy(&intent);
            limited.max_rent_lamports = intent.expected_rent_lamports - 1;
            assert!(intent
                .validate_shape_and_wire(
                    &raw,
                    &intent.claim.root.public_key_package,
                    1000,
                    &limited
                )
                .is_err());
        }
        let mut corrupt = intent.claim.root.public_key_package.clone();
        corrupt[0] ^= 1;
        assert!(intent
            .validate_shape_and_wire(&raw, &corrupt, 1000, &policy(&intent))
            .is_err());
        for ceremony in [Uuid::nil(), Uuid::new_v4()] {
            let mut changed = intent.clone();
            changed.generation.ceremony_id = ceremony;
            assert!(changed
                .validate_shape_and_wire(
                    &raw,
                    &intent.claim.root.public_key_package,
                    1000,
                    &policy(&intent)
                )
                .is_err());
        }
    }
}
#[test]
fn machine_message_requires_canonical_bounded_original_payload() {
    for case in fixtures() {
        let intent: Intent = serde_json::from_value(case["intent"].clone()).unwrap();
        let payload = case["message_hex"].as_str().unwrap();
        assert_ne!(payload, payload.to_ascii_uppercase());
        assert!(intent
            .custody_message(&payload.to_ascii_uppercase())
            .is_err());
        assert!(intent.custody_message("").is_err());
        assert!(intent.custody_message("☃").is_err());
        let mut oversized = intent.clone();
        oversized.message_fingerprint = hex(&Sha256::digest([0; 1232]));
        assert!(oversized.custody_message(&"00".repeat(1232)).is_err());
    }
}
#[test]
fn generation_reference_is_not_a_freshness_permit() {
    let case = fixtures().remove(0);
    let mut intent: Intent = serde_json::from_value(case["intent"].clone()).unwrap();
    let raw = wallet_mpc_protocol::sign::decode_hex(case["message_hex"].as_str().unwrap()).unwrap();
    intent.generation.epoch = 99;
    intent.generation.ceremony_id = Uuid::new_v4();
    // This helper checks a reference's structure, not whether an epoch is
    // active. Future signer code must require the independent live witness.
    // No route currently consumes this value or produces nonce permission.
    intent
        .validate_shape_and_wire(
            &raw,
            &intent.claim.root.public_key_package,
            1000,
            &policy(&intent),
        )
        .unwrap();
}
#[test]
fn every_top_level_field_is_committed_by_the_original_machine_message() {
    for case in fixtures() {
        let original: Intent = serde_json::from_value(case["intent"].clone()).unwrap();
        let payload = case["message_hex"].as_str().unwrap();
        let previous = original.custody_message(payload).unwrap();
        for (field, value) in case["intent"].as_object().unwrap() {
            let mut changed = case["intent"].clone();
            changed[field] = match value {
                Value::String(v) if field == "operation_type" => {
                    json!(if v == "WITHDRAWAL" {
                        "SWEEP"
                    } else {
                        "WITHDRAWAL"
                    })
                }
                Value::String(v) => json!(if field.ends_with("id") {
                    Uuid::new_v4().to_string()
                } else {
                    format!("{v}x")
                }),
                Value::Number(v) => json!(v.as_u64().unwrap() + 1),
                Value::Null => json!("different"),
                Value::Object(_) if field == "claim" => {
                    let mut v = value.clone();
                    v["owner_ref"] = json!("different");
                    v
                }
                Value::Object(_) if field == "generation" => {
                    let mut v = value.clone();
                    v["epoch"] = json!(1);
                    v
                }
                Value::Object(_) => {
                    let mut v = value.clone();
                    if v.get("amount").is_some() {
                        v["amount"] = json!(1)
                    } else {
                        v["rent_lamports"] = json!(1)
                    };
                    v
                }
                _ => continue,
            };
            if let Ok(intent) = serde_json::from_value::<Intent>(changed) {
                if let Ok(message) = intent.custody_message(payload) {
                    assert_ne!(
                        previous, message,
                        "field omitted from original proof: {field}"
                    );
                }
            }
        }
    }
}
