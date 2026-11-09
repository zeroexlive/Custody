//! Pure verification tests: synthetic dealer shares and detached Life signature
//! bytes are deliberately not genuine node/RPC/W authorization acceptance.
use super::*;
use crate::{
    sign::CustodyAuthorization, solana_intent::Intent, solana_seeded, witness::AuthorizedIntent,
};
use frost_ed25519 as frost;
pub(crate) fn request() -> FinalityRequest {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/solana-seeded-intent-sdk.json"
    ))
    .unwrap();
    let mut value = fixture["cases"][0]["intent"].clone();
    value["claim"]["root"] = fixture["root"].clone();
    let mut intent: Intent = serde_json::from_value(value).unwrap();
    let mut raw = decode_hex(fixture["cases"][0]["message_hex"].as_str().unwrap()).unwrap();
    let old_base = intent.claim.root.base().unwrap();
    let old_source = solana_seeded::key(&intent.financial_source).unwrap();
    let mut rng = rand_core::OsRng;
    let (secret, package) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng).unwrap();
    let keys: BTreeMap<_, _> = secret
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let new_base: [u8; 32] = package
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let new_source = solana_seeded::address(&new_base, intent.claim.index, false).unwrap();
    for (old, new) in [(old_base, new_base), (old_source, new_source)] {
        let positions: Vec<_> = raw
            .windows(32)
            .enumerate()
            .filter_map(|(n, w)| (w == old).then_some(n))
            .collect();
        for n in positions {
            raw[n..n + 32].copy_from_slice(&new);
        }
    }
    // The SDK orders unsigned writable accounts by key bytes. Regenerating
    // a FROST base changes the seeded source and may swap its key position.
    // Rebuild the table AND all instruction indices before signing it.
    let count = usize::from(raw[3]);
    assert!(count < 128);
    let original: Vec<[u8; 32]> = raw[4..4 + 32 * count]
        .chunks_exact(32)
        .map(|b| b.try_into().unwrap())
        .collect();
    let mut ordered = original.clone();
    let signed = usize::from(raw[0]);
    let readonly = usize::from(raw[2]);
    ordered[signed..count - readonly].sort();
    ordered[count - readonly..].sort();
    let mapping: Vec<u8> = original
        .iter()
        .map(|k| u8::try_from(ordered.iter().position(|v| v == k).unwrap()).unwrap())
        .collect();
    for (n, key) in ordered.iter().enumerate() {
        raw[4 + n * 32..4 + (n + 1) * 32].copy_from_slice(key);
    }
    fn short(raw: &[u8], at: &mut usize) -> usize {
        let mut result = 0;
        for shift in [0, 7, 14] {
            let b = raw[*at];
            *at += 1;
            result |= usize::from(b & 127) << shift;
            if b & 128 == 0 {
                return result;
            }
        }
        panic!("invalid fixture compact length")
    }
    let mut at = 4 + count * 32 + 32;
    let instructions = short(&raw, &mut at);
    for _ in 0..instructions {
        raw[at] = mapping[usize::from(raw[at])];
        at += 1;
        let accounts = short(&raw, &mut at);
        for n in at..at + accounts {
            raw[n] = mapping[usize::from(raw[n])];
        }
        at += accounts;
        let data = short(&raw, &mut at);
        at += data;
    }
    assert_eq!(at, raw.len());
    intent.claim.root.group_public_key = hex(&new_base);
    intent.claim.root.public_key_package = package.serialize().unwrap();
    intent.generation.public_key_package_sha256 = hash(&intent.claim.root.public_key_package);
    intent.financial_source = bs58::encode(new_source).into_string();
    intent.fee_payer = bs58::encode(new_base).into_string();
    intent.message_fingerprint = hash(&raw);
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, key) in keys.iter().take(2) {
        let (nonce, commit) = frost::round1::commit(key.signing_share(), &mut rng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commit);
    }
    let signing = frost::SigningPackage::new(commitments, &raw);
    let shares = nonces
        .iter()
        .map(|(id, nonce)| {
            (
                *id,
                frost::round2::sign(&signing, nonce, &keys[id]).unwrap(),
            )
        })
        .collect();
    let signature = frost::aggregate(&signing, &shares, &package).unwrap();
    let empty = CustodyAuthorization {
        certificate_chain_der_hex: vec![],
        signature_der_hex: String::new(),
    };
    let binding = Binding {
        authorized: AuthorizedIntent {
            intent: intent.clone(),
            payload_hex: hex(&raw),
            claim_evidence: crate::solana_provisioning::Evidence {
                statement: intent.claim.clone(),
                participant_agreement: vec![],
                authority: None,
            },
            custody_authorization: empty.clone(),
            operator_authorization: empty,
        },
        selected_signers: vec![PARTIES[0].into(), PARTIES[1].into()],
    };
    let plan = FinalityPlan {
        version: 1,
        observation_id: Uuid::new_v4(),
        witness_anchor: Uuid::new_v4(),
        root: intent.claim.root.clone(),
        observing_generation: intent.generation.clone(),
        observing_node_keys: PARTIES
            .iter()
            .enumerate()
            .map(|(n, p)| ((*p).into(), format!("{:064x}", n + 1)))
            .collect(),
        expected_revision: 9,
        execution_id: intent.crypto_execution_id,
        binding_fingerprint: binding.identity().unwrap(),
        signature_hex: hex(&signature.serialize().unwrap()),
        expires_at: 1200,
    };
    FinalityRequest {
        authorization: Signed {
            key_id: "11".repeat(32),
            value: plan,
            signature: "30".repeat(8),
        },
        binding,
        signing_public_key_package: package.serialize().unwrap(),
    }
}
fn rpc(r: &FinalityRequest) -> (Value, Value) {
    let raw = r.validate_archived_wire().unwrap();
    let account_count = usize::from(raw[68]);
    assert!(account_count < 128);
    let before = vec![10000000u64; account_count];
    let mut after = before.clone();
    after[0] -= r.binding.authorized.intent.expected_fee_lamports;
    let source = solana_seeded::key(&r.binding.authorized.intent.financial_source).unwrap();
    let crate::solana_intent::Action::NativeTransfer {
        destination,
        amount,
    } = &r.binding.authorized.intent.action
    else {
        panic!()
    };
    let destination = solana_seeded::key(destination).unwrap();
    for (index, key) in raw[69..69 + account_count * 32]
        .chunks_exact(32)
        .enumerate()
    {
        if key == source {
            after[index] -= amount;
        }
        if key == destination {
            after[index] += amount;
        }
    }
    (
        json!({"context":{"slot":500},"value":[{"slot":400,"err":null,"confirmationStatus":"finalized","confirmations":null}]}),
        json!({"slot":400,"transaction":[base64::encode(raw),"base64"],"meta":{"err":null,"fee":r.binding.authorized.intent.expected_fee_lamports,
            "preBalances":before,"postBalances":after,"preTokenBalances":[],"postTokenBalances":[],"innerInstructions":[]}}),
    )
}
#[test]
fn expired_original_intent_has_valid_archived_wire_without_new_authorization() {
    let r = request();
    assert!(r.binding.authorized.intent.expires_at < 2000);
    let wire = r.validate_archived_wire().unwrap();
    assert_eq!(wire.len(), 65 + r.binding.authorized.payload_hex.len() / 2);
    let (statuses, tx) = rpc(&r);
    let observed =
        FinalityObservation::verify_rpc(&r, &statuses, &tx, &r.plan().root.genesis_hash).unwrap();
    assert_eq!(observed.fact.outcome, FinalityOutcome::Succeeded {});
    assert_eq!(observed.fact.wire_fingerprint, hash(&wire));
    assert_eq!(observed.status_context_slot, 500);
    // This contract is not a fresh Life approval or a private permit.
    assert!(r.plan().validate(2000).is_err());
}
#[test]
fn arbitrary_signature_binding_package_or_payload_cannot_substitute_old_wire() {
    let r = request();
    for fault in 0..4 {
        let mut changed = r.clone();
        match fault {
            0 => changed.authorization.value.signature_hex = "00".repeat(64),
            1 => changed.binding.authorized.intent.operation_id += 1,
            2 => changed.signing_public_key_package[0] ^= 1,
            3 => changed.binding.authorized.payload_hex.push_str("00"),
            _ => unreachable!(),
        }
        assert!(changed.validate_archived_wire().is_err(), "fault {fault}");
    }
}
#[test]
fn missing_unfinalized_or_inconsistent_rpc_never_becomes_a_fact() {
    let r = request();
    let (statuses, tx) = rpc(&r);
    for fault in 0..12 {
        let (mut s, mut t) = (statuses.clone(), tx.clone());
        match fault {
            0 => s["value"][0] = Value::Null,
            1 => s["value"][0]["confirmationStatus"] = json!("confirmed"),
            2 => s["value"][0]["slot"] = json!(401),
            3 => s["context"]["slot"] = json!(399),
            4 => t = Value::Null,
            5 => t["transaction"][0] = json!(base64::encode([0u8; 65])),
            6 => t["transaction"][1] = json!("json"),
            7 => t["meta"]["fee"] = json!("5000"),
            8 => t["meta"]["fee"] = json!(r.binding.authorized.intent.expected_fee_lamports + 1),
            9 => t["meta"]["err"] = json!({"InstructionError":[0,"Custom"]}),
            10 => t["meta"]["postBalances"] = json!([]),
            11 => t["meta"]["preBalances"][0] = json!(-1),
            _ => unreachable!(),
        }
        assert!(
            FinalityObservation::verify_rpc(&r, &s, &t, &r.plan().root.genesis_hash).is_err(),
            "fault {fault}"
        );
    }
}
#[test]
fn failed_finalized_wire_is_distinct_and_observer_context_is_not_one_bank() {
    let r = request();
    let (mut statuses, mut tx) = rpc(&r);
    let success =
        FinalityObservation::verify_rpc(&r, &statuses, &tx, &r.plan().root.genesis_hash).unwrap();
    statuses["context"]["slot"] = json!(600);
    let later =
        FinalityObservation::verify_rpc(&r, &statuses, &tx, &r.plan().root.genesis_hash).unwrap();
    assert_eq!(success.fact, later.fact);
    assert_ne!(success.status_context_slot, later.status_context_slot);
    let error = json!({"InstructionError":[0,{"Custom":1}]});
    statuses["value"][0]["err"] = error.clone();
    tx["meta"]["err"] = error;
    tx["meta"]["postBalances"] = tx["meta"]["preBalances"].clone();
    let payer = tx["meta"]["postBalances"][0].as_u64().unwrap()
        - r.binding.authorized.intent.expected_fee_lamports;
    tx["meta"]["postBalances"][0] = json!(payer);

    let failed =
        FinalityObservation::verify_rpc(&r, &statuses, &tx, &r.plan().root.genesis_hash).unwrap();
    assert!(matches!(
        failed.fact.outcome,
        FinalityOutcome::Failed { .. }
    ));
    assert_ne!(success.fact, failed.fact);
}

#[test]
fn wrong_rpc_genesis_is_never_normalized_into_a_fact() {
    let r = request();
    let (s, t) = rpc(&r);
    assert!(
        FinalityObservation::verify_rpc(&r, &s, &t, &bs58::encode([91u8; 32]).into_string())
            .is_err()
    );
}
#[test]
fn current_observer_context_is_separate_from_original_signing_generation() {
    let mut r = request();
    let original = r.binding.authorized.intent.generation.clone();
    r.authorization.value.observing_generation = Generation {
        epoch: original.epoch + 1,
        ceremony_id: Uuid::new_v4(),
        public_key_package_sha256: hash(b"new independently verified current package"),
    };
    // Shape/content is not proof that this observer context is actually current.
    // W and each node must authenticate an own fresh query before any ACK.
    r.plan().validate_shape().unwrap();
    r.validate_archived_wire().unwrap();
    assert_eq!(r.binding.authorized.intent.generation, original);
}
#[test]
fn live_finality_plan_rejects_missing_duplicate_or_shared_observer_context() {
    let original = request();
    for fault in 0..6 {
        let mut p = original.plan().clone();
        match fault {
            0 => p.observation_id = p.execution_id,
            1 => p.observing_node_keys.remove(PARTIES[0]).map(drop).unwrap(),
            2 => p
                .observing_node_keys
                .insert(PARTIES[0].into(), p.observing_node_keys[PARTIES[1]].clone())
                .map(drop)
                .unwrap(),
            3 => p.binding_fingerprint = "00".repeat(32),
            4 => p.signature_hex.push_str("00"),
            5 => p.observing_generation.public_key_package_sha256 = "00".repeat(32),
            _ => unreachable!(),
        }
        assert!(p.validate_shape().is_err(), "fault {fault}");
    }
    original.plan().validate(1000).unwrap();
    assert!(original.plan().validate(1200).is_err());
}
#[test]
fn only_exact_frozen_signed_pending_current_source_view_is_eligible() {
    let r = request();
    let p = r.plan();
    let value = json!({"query":{"anchor_id":p.witness_anchor,"root_identity":p.root.identity().unwrap(),
        "challenge":"11".repeat(32),"execution_id":p.execution_id},"sequence":100,
        "root":{"original":p.root,"revision":p.expected_revision,"phase":"Frozen","generation":p.observing_generation,
            "public_key_package":p.root.public_key_package,"node_keys":p.observing_node_keys,"prepared":null,"next_claim_index":1},
        "execution":{"binding_fingerprint":p.binding_fingerprint,"status":"SignedPending","signature":p.signature_hex,"reports":{}},
        "abandoned":false,"claim":null});
    let view: QueryReply = serde_json::from_value(value.clone()).unwrap();
    p.validate_view(&view).unwrap();
    for fault in 0..7 {
        let mut changed = value.clone();
        match fault {
            0 => changed["execution"]["status"] = json!("Open"),
            1 => changed["execution"]["signature"] = Value::Null,
            2 => changed["root"]["phase"] = json!("Active"),
            3 => changed["root"]["revision"] = json!(p.expected_revision + 1),
            4 => changed["execution"]["binding_fingerprint"] = json!("22".repeat(32)),
            5 => changed["root"]["node_keys"][PARTIES[0]] = json!("33".repeat(32)),
            6 => changed["abandoned"] = json!(true),
            _ => unreachable!(),
        }
        let changed: QueryReply = serde_json::from_value(changed).unwrap();
        assert!(p.validate_view(&changed).is_err(), "fault {fault}");
    }
}

#[test]
fn failed_status_with_successful_principal_metadata_is_rejected() {
    let r = request();
    let (mut statuses, mut tx) = rpc(&r);
    let error = json!({"InstructionError":[0,{"Custom":1}]});
    statuses["value"][0]["err"] = error.clone();
    tx["meta"]["err"] = error;
    assert!(
        FinalityObservation::verify_rpc(&r, &statuses, &tx, &r.plan().root.genesis_hash).is_err()
    );
}
#[test]
fn previously_admitted_historical_uuid_overlap_does_not_destroy_public_truth() {
    let mut r = request();
    r.binding.authorized.intent.crypto_execution_id = r.plan().root.dkg.keyset_id;
    r.authorization.value.execution_id = r.binding.authorized.intent.crypto_execution_id;
    r.authorization.value.binding_fingerprint = r.binding.identity().unwrap();
    r.validate_archived_wire().unwrap();
}

#[test]
fn malformed_confirmations_effects_or_oversized_archival_wrappers_are_rejected() {
    let r = request();
    let (statuses, tx) = rpc(&r);
    for fault in 0..5 {
        let (mut s, mut t) = (statuses.clone(), tx.clone());
        match fault {
            0 => s["value"][0]["confirmations"] = json!(1),
            1 => {
                s["value"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("confirmations");
            }
            2 => t["meta"]["postBalances"][0] = json!(1),
            3 => {
                t["meta"]["preBalances"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(0));
                t["meta"]["postBalances"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(0));
            }
            4 => t["meta"]["innerInstructions"] = json!({"unexpected":true}),
            _ => unreachable!(),
        }
        assert!(
            FinalityObservation::verify_rpc(&r, &s, &t, &r.plan().root.genesis_hash).is_err(),
            "fault {fault}"
        );
    }
    let mut oversized = r;
    oversized
        .binding
        .authorized
        .custody_authorization
        .certificate_chain_der_hex = vec!["00".repeat(MAX_REQUEST_BYTES)];
    assert!(oversized.validate_archived_wire().is_err());
}
