//! State-machine tests only: synthetic detached receipts deliberately bypass
//! Trust. Real-process acceptance separately verifies authentic original DKG,
//! custody/policy proofs, TLS identities and crash recovery.
use super::*;
use serde::Serialize;
use serde_json::Value;
use wallet_mpc_protocol::{
    sign::CustodyAuthorization, solana_intent::Intent, solana_provisioning::Report,
    witness::AuthorizedIntent,
};

fn evidence<T: Clone>(value: T) -> Evidence<T> {
    Evidence {
        statement: value.clone(),
        participant_agreement: PARTIES
            .iter()
            .map(|p| Report {
                statement: value.clone(),
                party_id: (*p).into(),
                durable: true,
                signer_signature: "00".repeat(70),
            })
            .collect(),
    }
}
fn signed<T>(party: &str, value: T) -> Signed<T> {
    Signed {
        key_id: node_keys()[party].clone(),
        value,
        signature: "00".repeat(70),
    }
}
fn node_keys() -> BTreeMap<String, String> {
    PARTIES
        .iter()
        .enumerate()
        .map(|(n, p)| ((*p).into(), format!("{:064x}", n + 1)))
        .collect()
}
fn binding() -> Binding {
    let f: Value = serde_json::from_str(include_str!(
        "../../../protocol/tests/fixtures/solana-seeded-intent-sdk.json"
    ))
    .unwrap();
    let mut v = f["cases"][0]["intent"].clone();
    v["claim"]["root"] = f["root"].clone();
    let intent: Intent = serde_json::from_value(v).unwrap();
    let proof = CustodyAuthorization {
        certificate_chain_der_hex: vec![],
        signature_der_hex: String::new(),
    };
    Binding {
        authorized: AuthorizedIntent {
            claim_evidence: evidence(intent.claim.clone()),
            intent,
            payload_hex: f["cases"][0]["message_hex"].as_str().unwrap().into(),
            custody_authorization: proof.clone(),
            operator_authorization: proof,
        },
        selected_signers: vec![PARTIES[0].into(), PARTIES[1].into()],
    }
}
fn command(s: &Snapshot, b: &Binding, action: CommandAction) -> Command {
    let root_identity = b.authorized.intent.claim.root.identity().unwrap();
    Command {
        anchor_id: s.anchor_id,
        request_id: Uuid::new_v4(),
        expected_revision: s.roots.get(&root_identity).map_or(0, |r| r.revision),
        root_identity,
        expires_at: 1010,
        action,
    }
}
fn setup() -> (Snapshot, Binding) {
    let b = binding();
    let mut s = Snapshot::empty(Uuid::new_v4()).unwrap();
    s.command(&command(
        &s,
        &b,
        CommandAction::Enroll {
            evidence: Box::new(evidence(b.authorized.intent.claim.root.clone())),
            node_keys: node_keys(),
        },
    ))
    .unwrap();
    register(&mut s, &b);
    (s, b)
}
fn register(s: &mut Snapshot, b: &Binding) {
    s.command(&command(
        s,
        b,
        CommandAction::RegisterClaim {
            evidence: Box::new(evidence(b.authorized.intent.claim.clone())),
        },
    ))
    .unwrap();
}
fn request(s: &Snapshot, b: &Binding, party: &str, round: u16) -> PermitRequest {
    PermitRequest {
        anchor_id: s.anchor_id,
        binding: b.clone(),
        party_id: party.into(),
        round,
        challenge: hash(Uuid::new_v4().as_bytes()),
        expires_at: 1010,
        signing_package: None,
    }
}
pub(crate) fn admission_request() -> PermitRequest {
    let (s, b) = setup();
    request(&s, &b, PARTIES[0], 1)
}
fn grant(s: &mut Snapshot, b: &Binding, party: &str) -> PermitRequest {
    let req = request(s, b, party, 1);
    s.permit(&req, &node_keys()[party], 1000).unwrap();
    req
}
fn retry(b: &Binding) -> Binding {
    let mut b = b.clone();
    b.authorized.intent.crypto_execution_id = Uuid::new_v4();
    b.authorized.intent.session_id = Uuid::new_v4();
    b.authorized.intent.attempt_id += 1;
    b
}
fn json<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap()
}

#[test]
fn grant_is_one_use_even_with_a_fresh_challenge_and_new_execution() {
    let (mut s, b) = setup();
    let req = grant(&mut s, &b, PARTIES[0]);
    let before = json(&s);
    for req in [
        req,
        request(&s, &b, PARTIES[0], 1),
        request(&s, &retry(&b), PARTIES[0], 1),
    ] {
        let mut candidate = s.clone();
        assert!(candidate
            .permit(&req, &node_keys()[PARTIES[0]], 1000)
            .is_err());
        assert_eq!(json(&s), before);
    }
    grant(&mut s, &b, PARTIES[1]);
    assert_eq!(s.executions.len(), 1);
}

#[test]
fn exact_wire_can_never_be_attached_to_another_operation_even_after_no_signature() {
    let (mut s, b) = setup();
    grant(&mut s, &b, PARTIES[0]);
    let mut other = retry(&b);
    other.authorized.intent.operation_id += 1;
    other.authorized.intent.attempt_id += 100;
    let req = request(&s, &other, PARTIES[0], 1);
    assert!(s
        .clone()
        .permit(&req, &node_keys()[PARTIES[0]], 1000)
        .is_err());
    s.command(&command(
        &s,
        &b,
        CommandAction::CloseNoSignature {
            execution_id: b.authorized.intent.crypto_execution_id,
        },
    ))
    .unwrap();
    assert!(s
        .clone()
        .permit(&req, &node_keys()[PARTIES[0]], 1000)
        .is_err());
    let original_retry = retry(&b);
    grant(&mut s, &original_retry, PARTIES[0]);
    assert_eq!(s.wires.len(), 1);
}

#[test]
fn active_zero_r2_closure_is_terminal_but_allows_same_business_retry() {
    let (mut s, b) = setup();
    grant(&mut s, &b, PARTIES[0]);
    let close = command(
        &s,
        &b,
        CommandAction::CloseNoSignature {
            execution_id: b.authorized.intent.crypto_execution_id,
        },
    );
    assert!(s.command(&close).unwrap());
    assert!(!s.command(&close).unwrap());
    assert_eq!(s.roots[&close.root_identity].phase, Phase::Active);
    assert!(s
        .permit(
            &request(&s, &b, PARTIES[1], 1),
            &node_keys()[PARTIES[1]],
            1000
        )
        .is_err());
    let next = retry(&b);
    grant(&mut s, &next, PARTIES[0]);
    assert_eq!(s.executions.len(), 2);
}

#[test]
fn absence_is_a_global_tombstone_against_late_requests() {
    let (mut s, b) = setup();
    let id = b.authorized.intent.crypto_execution_id;
    s.command(&command(
        &s,
        &b,
        CommandAction::CloseNoSignature { execution_id: id },
    ))
    .unwrap();
    assert!(s.executions.is_empty());
    assert!(s.abandoned.contains_key(&id));
    assert!(s
        .permit(
            &request(&s, &b, PARTIES[0], 1),
            &node_keys()[PARTIES[0]],
            1000
        )
        .is_err());
    let mut other = b.clone();
    other.authorized.intent.claim.root.dkg.keyset_id = Uuid::new_v4();
    other.authorized.intent.claim.root.group_public_key =
        b.authorized.intent.claim.root.group_public_key.clone();
    // A late execution UUID cannot be made live by substituting a root either.
    assert!(s
        .permit(
            &request(&s, &other, PARTIES[0], 1),
            &node_keys()[PARTIES[0]],
            1000
        )
        .is_err());
}

#[test]
fn lifecycle_cas_fences_concurrent_permits_and_freezes() {
    let (mut s, b) = setup();
    let freeze = command(&s, &b, CommandAction::Freeze);
    let close = command(
        &s,
        &b,
        CommandAction::CloseNoSignature {
            execution_id: Uuid::new_v4(),
        },
    );
    grant(&mut s, &b, PARTIES[0]);
    assert!(s.command(&freeze).is_err());
    assert!(s.command(&close).is_err());
    s.command(&command(&s, &b, CommandAction::Freeze)).unwrap();
    assert!(s
        .permit(
            &request(&s, &b, PARTIES[1], 1),
            &node_keys()[PARTIES[1]],
            1000
        )
        .is_err());
    assert!(s
        .command(&command(&s, &b, CommandAction::Activate))
        .is_err());
    assert!(s
        .command(&command(
            &s,
            &b,
            CommandAction::Prepare {
                ready: vec![],
                node_keys: node_keys()
            }
        ))
        .is_err());
}

#[test]
fn operation_aliases_and_business_ownership_are_permanent() {
    let (mut s, b) = setup();
    grant(&mut s, &b, PARTIES[0]);
    s.command(&command(
        &s,
        &b,
        CommandAction::CloseNoSignature {
            execution_id: b.authorized.intent.crypto_execution_id,
        },
    ))
    .unwrap();
    for mutate in 0..5 {
        let mut n = retry(&b);
        match mutate {
            0 => n.authorized.intent.financial_source.push('x'),
            1 => n.authorized.intent.claim.owner_ref.push('x'),
            2 => n.authorized.intent.claim.reservation_id = Uuid::new_v4(),
            3 => {
                n.authorized.intent.operation_id += 1;
                n.authorized.intent.attempt_id = b.authorized.intent.attempt_id;
            }
            _ => {
                n.authorized.intent.operation_id += 1;
                n.authorized.intent.session_id = b.authorized.intent.session_id;
            }
        }
        assert!(s
            .clone()
            .permit(
                &request(&s, &n, PARTIES[0], 1),
                &node_keys()[PARTIES[0]],
                1000
            )
            .is_err());
    }
}

#[test]
fn claim_aliases_are_permanent_before_any_spending_or_signature() {
    let (s, b) = setup();
    let original = &b.authorized.intent.claim;
    assert!(s.executions.is_empty());
    let root = original.root.identity().unwrap();
    assert_eq!(s.roots[&root].next_claim_index, 1);
    for kind in 0..6 {
        let mut c = original.clone();
        c.reservation_id = Uuid::new_v4();
        c.idempotency_key = Uuid::new_v4().to_string();
        c.owner_ref = format!("p1:{}", Uuid::new_v4());
        c.index = 1;
        match kind {
            0 => c.index = 0,
            1 => c.owner_ref = original.owner_ref.clone(),
            2 => c.idempotency_key = original.idempotency_key.clone(),
            3 => c.reservation_id = original.reservation_id,
            4 => c.index = 2,
            _ => {
                c.index = 0;
                c.asset = wallet_mpc_protocol::solana_provisioning::Asset::ClassicToken {
                    mint: c.root.genesis_hash.clone(),
                    decimals: 6,
                };
            }
        }
        let cmd = command(
            &s,
            &b,
            CommandAction::RegisterClaim {
                evidence: Box::new(evidence(c)),
            },
        );
        assert!(s.clone().command(&cmd).is_err());
    }
    let cmd = command(
        &s,
        &b,
        CommandAction::RegisterClaim {
            evidence: Box::new(evidence(original.clone())),
        },
    );
    let mut retry = s.clone();
    retry.command(&cmd).unwrap();
    assert_eq!(retry.claims.len(), 1);
    assert_eq!(retry.roots[&root].next_claim_index, 1);
    let mut unregistered = s.clone();
    unregistered.claims.clear();
    assert!(unregistered
        .permit(
            &request(&s, &b, PARTIES[0], 1),
            &node_keys()[PARTIES[0]],
            1000
        )
        .is_err());
}

/// Three upstream DKG participants, never a dealer or a reconstructed key.
fn keys() -> (
    BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    frost::keys::PublicKeyPackage,
) {
    let mut secrets = BTreeMap::new();
    let mut public = BTreeMap::new();
    for p in PARTIES {
        let id = identifier(p).unwrap();
        let (s, p) = frost::keys::dkg::part1(id, 3, 2, rand_core::OsRng).unwrap();
        secrets.insert(id, s);
        public.insert(id, p);
    }
    let mut round2 = BTreeMap::new();
    let mut packets = BTreeMap::new();
    for (id, s) in secrets {
        let others = public
            .iter()
            .filter(|(i, _)| **i != id)
            .map(|(i, p)| (*i, p.clone()))
            .collect();
        let (s, p) = frost::keys::dkg::part2(s, &others).unwrap();
        round2.insert(id, s);
        packets.insert(id, p);
    }
    let mut keys = BTreeMap::new();
    let mut package = None;
    for (id, s) in round2 {
        let others = public
            .iter()
            .filter(|(i, _)| **i != id)
            .map(|(i, p)| (*i, p.clone()))
            .collect();
        let received = packets
            .iter()
            .filter(|(i, _)| **i != id)
            .map(|(i, p)| (*i, p[&id].clone()))
            .collect();
        let (k, p) = frost::keys::dkg::part3(&s, &others, &received).unwrap();
        if let Some(old) = &package {
            assert_eq!(old, &p);
        } else {
            package = Some(p);
        }
        keys.insert(id, k);
    }
    (keys, package.unwrap())
}

fn refreshed(
    keys: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: &frost::keys::PublicKeyPackage,
) -> frost::keys::PublicKeyPackage {
    let mut secrets = BTreeMap::new();
    let mut first = BTreeMap::new();
    for id in keys.keys() {
        let (secret, package) =
            frost::keys::refresh::refresh_dkg_part1(*id, 3, 2, rand_core::OsRng).unwrap();
        secrets.insert(*id, secret);
        first.insert(*id, package);
    }
    let mut secrets2 = BTreeMap::new();
    let mut packets = BTreeMap::new();
    for (id, secret) in secrets {
        let others = first
            .iter()
            .filter(|(i, _)| **i != id)
            .map(|(i, p)| (*i, p.clone()))
            .collect();
        let (secret, packages) = frost::keys::refresh::refresh_dkg_part2(secret, &others).unwrap();
        secrets2.insert(id, secret);
        packets.insert(id, packages);
    }
    let mut next = None;
    for (id, secret) in secrets2 {
        let others = first
            .iter()
            .filter(|(i, _)| **i != id)
            .map(|(i, p)| (*i, p.clone()))
            .collect();
        let received = packets
            .iter()
            .filter(|(i, _)| **i != id)
            .map(|(i, p)| (*i, p[&id].clone()))
            .collect();
        let (key, package) = frost::keys::refresh::refresh_dkg_shares(
            &secret,
            &others,
            &received,
            public.clone(),
            keys[&id].clone(),
        )
        .unwrap();
        assert_ne!(key.signing_share(), keys[&id].signing_share());
        assert_eq!(key.verifying_key(), public.verifying_key());
        if let Some(old) = &next {
            assert_eq!(old, &package);
        } else {
            next = Some(package);
        }
    }
    let next = next.unwrap();
    assert_ne!(&next, public);
    next
}

#[test]
fn all_three_refresh_agreement_activates_without_rewriting_original_identity() {
    let (keys, public) = keys();
    let next = refreshed(&keys, &public);
    let mut b = binding();
    let root = &mut b.authorized.intent.claim.root;
    root.group_public_key = hex(&public.verifying_key().serialize().unwrap());
    root.public_key_package = public.serialize().unwrap();
    b.authorized.intent.generation.public_key_package_sha256 = hash(&public.serialize().unwrap());
    let original = b.authorized.intent.claim.root.clone();
    let mut s = Snapshot::empty(Uuid::new_v4()).unwrap();
    s.command(&command(
        &s,
        &b,
        CommandAction::Enroll {
            evidence: Box::new(evidence(original.clone())),
            node_keys: node_keys(),
        },
    ))
    .unwrap();
    let root_id = original.identity().unwrap();
    register(&mut s, &b);
    grant(&mut s, &b, PARTIES[0]);
    s.command(&command(
        &s,
        &b,
        CommandAction::CloseNoSignature {
            execution_id: b.authorized.intent.crypto_execution_id,
        },
    ))
    .unwrap();
    s.command(&command(&s, &b, CommandAction::Freeze)).unwrap();
    let generation = Generation {
        epoch: 1,
        ceremony_id: Uuid::new_v4(),
        public_key_package_sha256: hash(&next.serialize().unwrap()),
    };
    let mut roster = node_keys();
    roster.insert(PARTIES[0].into(), format!("{:064x}", 4));
    let ready: Vec<_> = PARTIES
        .iter()
        .map(|p| Signed {
            key_id: roster[*p].clone(),
            signature: "00".repeat(70),
            value: GenerationReady {
                root_identity: root_id.clone(),
                previous_generation: b.authorized.intent.generation.clone(),
                generation: generation.clone(),
                public_key_package: next.serialize().unwrap(),
                party_id: (*p).into(),
            },
        })
        .collect();
    let implicit = command(
        &s,
        &b,
        CommandAction::Prepare {
            ready: ready.clone(),
            node_keys: roster.clone(),
        },
    );
    assert!(s.clone().command(&implicit).is_err());
    // A historical journal may already contain this earlier accepted rule.
    // Replay preserves its original meaning; HTTP admission cannot select it.
    assert!(s.clone().command_legacy(&implicit).is_ok());
    let replacement = wallet_mpc_protocol::solana_recovery::ReplacementPlan {
        refresh: wallet_mpc_protocol::solana_generation::RefreshPlan {
            anchor_id: s.anchor_id,
            root: original.clone(),
            previous: s.roots[&root_id].generation.clone(),
            previous_public_key_package: public.serialize().unwrap(),
            session_id: Uuid::new_v4(),
            ceremony_id: generation.ceremony_id,
            next_epoch: 1,
            node_keys: roster.clone(),
            expires_at: 1010,
        },
        previous_node_keys: node_keys(),
        party_id: PARTIES[0].into(),
        recipient_anchor_id: Uuid::new_v4(),
        recipient_profile_sha256: hash(b"synthetic-state-test-profile"),
        repair_session_id: Uuid::new_v4(),
        repair_ceremony_id: Uuid::new_v4(),
    };
    s.command(&command(
        &s,
        &b,
        CommandAction::ReserveReplacement {
            plan: Box::new(replacement),
        },
    ))
    .unwrap();
    for kind in 0..4 {
        let mut bad = ready.clone();
        match kind {
            0 => {
                bad.pop();
            }
            1 => bad[1].value.generation.ceremony_id = Uuid::new_v4(),
            2 => bad[2].value.previous_generation.epoch += 1,
            _ => bad[0].value.root_identity = "00".repeat(32),
        }
        assert!(s
            .clone()
            .command(&command(
                &s,
                &b,
                CommandAction::Prepare {
                    ready: bad,
                    node_keys: roster.clone()
                }
            ))
            .is_err());
    }
    s.command(&command(
        &s,
        &b,
        CommandAction::Prepare {
            ready,
            node_keys: roster.clone(),
        },
    ))
    .unwrap();
    assert_eq!(s.roots[&root_id].phase, Phase::Prepared);
    s.command(&command(&s, &b, CommandAction::Activate))
        .unwrap();
    assert_eq!(s.roots[&root_id].evidence.statement, original);
    assert_eq!(s.roots[&root_id].next_claim_index, 1);
    assert_eq!(
        s.claims[&b.authorized.intent.claim.reservation_id].statement,
        b.authorized.intent.claim
    );
    assert_eq!(s.roots[&root_id].generation, generation);
    let mut fresh = retry(&b);
    fresh.authorized.intent.generation = generation;
    let req = request(&s, &fresh, PARTIES[0], 1);
    assert!(s
        .clone()
        .permit(&req, &node_keys()[PARTIES[0]], 1000)
        .is_err());
    assert!(s
        .clone()
        .permit(&request(&s, &b, PARTIES[0], 1), &roster[PARTIES[0]], 1000)
        .is_err());
    s.permit(&req, &roster[PARTIES[0]], 1000).unwrap();

    // Public state-machine identity checks, with deliberately synthetic node
    // signatures as elsewhere in this module. Reusing any older ceremony must
    // fail even when its epoch and public package have been changed.
    let mut history = s.clone();
    history.executions.clear();
    history
        .command(&command(&history, &b, CommandAction::Freeze))
        .unwrap();
    let mut second: Vec<_> = PARTIES
        .iter()
        .map(|p| Signed {
            key_id: roster[*p].clone(),
            signature: "00".repeat(70),
            value: GenerationReady {
                root_identity: root_id.clone(),
                previous_generation: history.roots[&root_id].generation.clone(),
                generation: Generation {
                    epoch: 2,
                    ceremony_id: original.dkg.execution_id,
                    public_key_package_sha256: hash(&original.public_key_package),
                },
                public_key_package: original.public_key_package.clone(),
                party_id: (*p).into(),
            },
        })
        .collect();
    assert!(history
        .clone()
        .command(&command(
            &history,
            &b,
            CommandAction::Prepare {
                ready: second.clone(),
                node_keys: roster.clone(),
            },
        ))
        .is_err());
    let ceremony = Uuid::new_v4();
    for r in &mut second {
        r.value.generation.ceremony_id = ceremony;
    }
    history
        .command(&command(
            &history,
            &b,
            CommandAction::Prepare {
                ready: second,
                node_keys: roster.clone(),
            },
        ))
        .unwrap();
    history
        .command(&command(&history, &b, CommandAction::Activate))
        .unwrap();
    history
        .command(&command(&history, &b, CommandAction::Freeze))
        .unwrap();
    let third: Vec<_> = PARTIES
        .iter()
        .map(|p| Signed {
            key_id: roster[*p].clone(),
            signature: "00".repeat(70),
            value: GenerationReady {
                root_identity: root_id.clone(),
                previous_generation: history.roots[&root_id].generation.clone(),
                generation: Generation {
                    epoch: 3,
                    ceremony_id: s.roots[&root_id].generation.ceremony_id,
                    public_key_package_sha256: hash(&next.serialize().unwrap()),
                },
                public_key_package: next.serialize().unwrap(),
                party_id: (*p).into(),
            },
        })
        .collect();
    assert!(history
        .clone()
        .command(&command(
            &history,
            &b,
            CommandAction::Prepare {
                ready: third,
                node_keys: roster,
            },
        ))
        .is_err());
}

#[test]
fn no_release_closure_uses_every_actual_grantee_and_fences_late_results() {
    use wallet_mpc_protocol::witness::{Cancellation, NoRelease};
    let (keys, public) = keys();
    let mut b = binding();
    b.authorized.intent.claim.root.group_public_key =
        hex(&public.verifying_key().serialize().unwrap());
    b.authorized.intent.claim.root.public_key_package = public.serialize().unwrap();
    b.authorized.intent.generation.public_key_package_sha256 = hash(&public.serialize().unwrap());
    let mut base = Snapshot::empty(Uuid::new_v4()).unwrap();
    base.command(&command(
        &base,
        &b,
        CommandAction::Enroll {
            evidence: Box::new(evidence(b.authorized.intent.claim.root.clone())),
            node_keys: node_keys(),
        },
    ))
    .unwrap();
    register(&mut base, &b);
    let mut commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();
    for p in &b.selected_signers {
        grant(&mut base, &b, p);
        let id = identifier(p).unwrap();
        let (n, c) = frost::round1::commit(keys[&id].signing_share(), &mut rand_core::OsRng);
        base.record(&signed(
            p,
            PublicRound {
                anchor_id: base.anchor_id,
                execution_id: b.authorized.intent.crypto_execution_id,
                binding_fingerprint: b.identity().unwrap(),
                party_id: p.clone(),
                round: 1,
                commitments: Some(c.serialize().unwrap()),
                signature_share: None,
                signing_package: None,
            },
        ))
        .unwrap();
        commitments.insert(id, c);
        nonces.insert(id, n);
    }
    let package =
        frost::SigningPackage::new(commitments, &decode_hex(&b.authorized.payload_hex).unwrap());
    let execution_id = b.authorized.intent.crypto_execution_id;
    let party = PARTIES[0];
    let id = identifier(party).unwrap();
    let late = signed(
        party,
        PublicRound {
            anchor_id: base.anchor_id,
            execution_id,
            binding_fingerprint: b.identity().unwrap(),
            party_id: party.into(),
            round: 2,
            commitments: None,
            signature_share: Some(
                frost::round2::sign(&package, &nonces[&id], &keys[&id])
                    .unwrap()
                    .serialize(),
            ),
            signing_package: Some(package.serialize().unwrap()),
        },
    );
    for count in 1..=2 {
        let mut s = base.clone();
        let mut proofs = Vec::new();
        for p in &b.selected_signers[..count] {
            let mut req = request(&s, &b, p, 2);
            req.signing_package = Some(package.serialize().unwrap());
            s.permit(&req, &node_keys()[p], 1000).unwrap();
            let original = signed(p, req);
            let auth = Cancellation {
                anchor_id: s.anchor_id,
                root_identity: b.authorized.intent.claim.root.identity().unwrap(),
                execution_id,
                binding_fingerprint: b.identity().unwrap(),
                request_fingerprint: hash(
                    &original
                        .signing_message("WITNESS_PERMIT_REQUEST_V1")
                        .unwrap(),
                ),
                expires_at: 1010,
            };
            // This state-only test uses synthetic detached signatures; genuine
            // process tests verify both independent lifecycle and node keys.
            proofs.push(signed(
                p,
                NoRelease {
                    request: original,
                    authorization: signed(p, auth),
                },
            ));
        }
        let action = |proofs| CommandAction::CloseUnreleased {
            execution_id,
            attestations: proofs,
        };
        assert!(s
            .clone()
            .command(&command(&s, &b, action(proofs.clone())))
            .is_err());
        s.command(&command(&s, &b, CommandAction::Freeze)).unwrap();
        assert!(s
            .clone()
            .command(&command(
                &s,
                &b,
                CommandAction::CloseNoSignature { execution_id }
            ))
            .is_err());
        let mut bad_key = proofs.clone();
        bad_key[0].key_id = "ab".repeat(32);
        let mut wrong_request = proofs.clone();
        wrong_request[0].value.request.value.challenge = "cd".repeat(32);
        for bad in [
            vec![],
            proofs[..count - 1].to_vec(),
            vec![proofs[0].clone(); count + 1],
            bad_key,
            wrong_request,
        ] {
            assert!(s.clone().command(&command(&s, &b, action(bad))).is_err());
        }
        let mut contradicted = s.clone();
        contradicted.record(&late).unwrap();
        assert!(contradicted
            .clone()
            .command(&command(&contradicted, &b, action(proofs.clone())))
            .is_err());
        s.command(&command(&s, &b, action(proofs))).unwrap();
        assert_eq!(
            s.executions[&execution_id].status,
            ExecutionStatus::NoSignature
        );
        assert!(s.record(&late).is_err());
    }
}

#[test]
fn native_publication_requires_registered_claim_and_unique_active_grant() {
    let (mut s, b) = setup();
    let reservation = b.authorized.intent.claim.reservation_id;
    let issuance = Uuid::new_v4();
    let action = |reservation_id, issuance_id| CommandAction::IssueNativeClaim {
        reservation_id,
        issuance_id,
    };
    assert!(s
        .clone()
        .command(&command(&s, &b, action(Uuid::new_v4(), issuance)))
        .is_err());
    let first = command(&s, &b, action(reservation, issuance));
    s.command(&first).unwrap();
    assert_eq!(s.claim_issuances[&reservation].issuance_id, issuance);
    assert_eq!(s.claim_issuances[&reservation].command_id, first.request_id);
    assert!(!s.command(&first).unwrap());
    assert!(s
        .clone()
        .command(&command(&s, &b, action(reservation, Uuid::new_v4())))
        .is_err());
    let mut other = b.clone();
    other.authorized.intent.claim.reservation_id = Uuid::new_v4();
    other.authorized.intent.claim.index = 1;
    other.authorized.intent.claim.owner_ref = format!("p1:{}", Uuid::new_v4());
    other.authorized.intent.claim.idempotency_key = "other-native".into();
    register(&mut s, &other);
    let second = other.authorized.intent.claim.reservation_id;
    assert!(s
        .clone()
        .command(&command(&s, &b, action(second, issuance)))
        .is_err());
    let mut frozen = s.clone();
    frozen
        .command(&command(&frozen, &b, CommandAction::Freeze))
        .unwrap();
    assert!(frozen
        .command(&command(&frozen, &b, action(second, Uuid::new_v4())))
        .is_err());
    assert_eq!(
        frozen.claim_issuances[&reservation],
        s.claim_issuances[&reservation]
    );
    s.command(&command(&s, &b, action(second, Uuid::new_v4())))
        .unwrap();
    let mut token = other.clone();
    token.authorized.intent.claim.reservation_id = Uuid::new_v4();
    token.authorized.intent.claim.index = 2;
    token.authorized.intent.claim.idempotency_key = "token-not-yet-initialized".into();
    token.authorized.intent.claim.asset =
        wallet_mpc_protocol::solana_provisioning::Asset::ClassicToken {
            mint: "So11111111111111111111111111111111111111112".into(),
            decimals: 9,
        };
    register(&mut s, &token);
    assert!(s
        .clone()
        .command(&command(
            &s,
            &b,
            action(token.authorized.intent.claim.reservation_id, Uuid::new_v4())
        ))
        .is_err());
}

#[test]
fn exact_signature_is_recovered_without_reopening_the_payout() {
    let (keys, public) = keys();
    let mut b = binding();
    b.authorized.intent.claim.root.group_public_key =
        hex(&public.verifying_key().serialize().unwrap());
    b.authorized.intent.claim.root.public_key_package = public.serialize().unwrap();
    b.authorized.intent.generation.public_key_package_sha256 = hash(&public.serialize().unwrap());
    let mut s = Snapshot::empty(Uuid::new_v4()).unwrap();
    s.command(&command(
        &s,
        &b,
        CommandAction::Enroll {
            evidence: Box::new(evidence(b.authorized.intent.claim.root.clone())),
            node_keys: node_keys(),
        },
    ))
    .unwrap();
    let mut nonces = BTreeMap::new();
    register(&mut s, &b);
    let mut commitments = BTreeMap::new();
    for p in &b.selected_signers {
        grant(&mut s, &b, p);
        let id = identifier(p).unwrap();
        let (n, c) = frost::round1::commit(keys[&id].signing_share(), &mut rand_core::OsRng);
        let frame = signed(
            p,
            PublicRound {
                anchor_id: s.anchor_id,
                execution_id: b.authorized.intent.crypto_execution_id,
                binding_fingerprint: b.identity().unwrap(),
                party_id: p.clone(),
                round: 1,
                commitments: Some(c.serialize().unwrap()),
                signature_share: None,
                signing_package: None,
            },
        );
        assert!(s.record(&frame).unwrap());
        assert!(!s.record(&frame).unwrap());
        nonces.insert(id, n);
        commitments.insert(id, c);
    }
    let pkg =
        frost::SigningPackage::new(commitments, &decode_hex(&b.authorized.payload_hex).unwrap());
    for p in &b.selected_signers {
        let mut req = request(&s, &b, p, 2);
        req.signing_package = Some(pkg.serialize().unwrap());
        s.permit(&req, &node_keys()[p], 1000).unwrap();
        assert!(s.clone().permit(&req, &node_keys()[p], 1000).is_err());
        assert!(s
            .command(&command(
                &s,
                &b,
                CommandAction::CloseNoSignature {
                    execution_id: b.authorized.intent.crypto_execution_id
                }
            ))
            .is_err());
        let id = identifier(p).unwrap();
        let share = frost::round2::sign(&pkg, &nonces[&id], &keys[&id]).unwrap();
        let frame = signed(
            p,
            PublicRound {
                anchor_id: s.anchor_id,
                execution_id: b.authorized.intent.crypto_execution_id,
                binding_fingerprint: b.identity().unwrap(),
                party_id: p.clone(),
                round: 2,
                commitments: None,
                signature_share: Some(share.serialize()),
                signing_package: Some(pkg.serialize().unwrap()),
            },
        );
        let mut bad = frame.clone();
        bad.value.signature_share.as_mut().unwrap()[0] ^= 1;
        assert!(s.clone().record(&bad).is_err());
        s.record(&frame).unwrap();
    }
    let e = &s.executions[&b.authorized.intent.crypto_execution_id];
    assert_eq!(e.status, ExecutionStatus::SignedPending);
    public
        .verifying_key()
        .verify(
            pkg.message(),
            &frost::Signature::deserialize(&decode_hex(e.signature.as_ref().unwrap()).unwrap())
                .unwrap(),
        )
        .unwrap();
    assert!(s
        .clone()
        .permit(
            &request(&s, &retry(&b), PARTIES[0], 1),
            &node_keys()[PARTIES[0]],
            1000
        )
        .is_err());
    s.command(&command(&s, &b, CommandAction::Freeze)).unwrap();
    // A recovered signature drains cryptography but still reserves business execution.
    assert_eq!(
        s.executions[&b.authorized.intent.crypto_execution_id].status,
        ExecutionStatus::SignedPending
    );
}

fn replacement_plan(
    s: &Snapshot,
    b: &Binding,
    key: u64,
) -> wallet_mpc_protocol::solana_recovery::ReplacementPlan {
    use wallet_mpc_protocol::{solana_generation::RefreshPlan, solana_recovery::ReplacementPlan};
    let r = &s.roots[&b.authorized.intent.claim.root.identity().unwrap()];
    let mut roster = r.node_keys.clone();
    roster.insert(PARTIES[0].into(), format!("{key:064x}"));
    ReplacementPlan {
        refresh: RefreshPlan {
            anchor_id: s.anchor_id,
            root: r.evidence.statement.clone(),
            previous: r.generation.clone(),
            previous_public_key_package: r.public_key_package.clone(),
            session_id: Uuid::new_v4(),
            ceremony_id: Uuid::new_v4(),
            next_epoch: r.generation.epoch + 1,
            node_keys: roster,
            expires_at: 1010,
        },
        previous_node_keys: r.node_keys.clone(),
        party_id: PARTIES[0].into(),
        recipient_anchor_id: Uuid::new_v4(),
        recipient_profile_sha256: hash(b"state-profile"),
        repair_session_id: Uuid::new_v4(),
        repair_ceremony_id: Uuid::new_v4(),
    }
}

#[test]
fn replacement_reservation_requires_frozen_exact_current_history_and_drained_executions() {
    let (mut s, b) = setup();
    let plan = replacement_plan(&s, &b, 17);
    assert!(s
        .clone()
        .command(&command(
            &s,
            &b,
            CommandAction::ReserveReplacement {
                plan: Box::new(plan.clone()),
            }
        ))
        .is_err());
    grant(&mut s, &b, PARTIES[0]);
    s.command(&command(&s, &b, CommandAction::Freeze)).unwrap();
    assert!(s
        .clone()
        .command(&command(
            &s,
            &b,
            CommandAction::ReserveReplacement {
                plan: Box::new(plan.clone()),
            }
        ))
        .is_err());
    s.command(&command(
        &s,
        &b,
        CommandAction::CloseNoSignature {
            execution_id: b.authorized.intent.crypto_execution_id,
        },
    ))
    .unwrap();
    for variant in 0..5 {
        let mut changed = plan.clone();
        match variant {
            0 => changed.refresh.root.ownership_scope = "another-owner".into(),
            1 => changed.refresh.previous.epoch += 1,
            2 => {
                changed
                    .previous_node_keys
                    .insert(PARTIES[1].into(), hash(b"wrong-helper"));
            }
            3 => changed.refresh.anchor_id = Uuid::new_v4(),
            _ => changed.refresh.previous_public_key_package.push(0),
        }
        assert!(s
            .clone()
            .command(&command(
                &s,
                &b,
                CommandAction::ReserveReplacement {
                    plan: Box::new(changed),
                }
            ))
            .is_err());
    }
    let original = command(
        &s,
        &b,
        CommandAction::ReserveReplacement {
            plan: Box::new(plan.clone()),
        },
    );
    assert!(s.command(&original).unwrap());
    assert!(!s.command(&original).unwrap());
    let id = b.authorized.intent.claim.root.identity().unwrap();
    assert_eq!(s.roots[&id].phase, Phase::Frozen);
    assert_eq!(s.roots[&id].node_keys, plan.previous_node_keys);
    assert_eq!(s.replacements[&id].command_id, original.request_id);
    assert_eq!(s.replacements[&id].plan, plan);
    assert_eq!(
        s.claims[&b.authorized.intent.claim.reservation_id].statement,
        b.authorized.intent.claim
    );
}

#[test]
fn abandoned_replacement_never_releases_identity_or_resurrects_from_old_ack() {
    let (mut s, b) = setup();
    s.command(&command(&s, &b, CommandAction::Freeze)).unwrap();
    let plan = replacement_plan(&s, &b, 17);
    let reserve = command(
        &s,
        &b,
        CommandAction::ReserveReplacement {
            plan: Box::new(plan.clone()),
        },
    );
    s.command(&reserve).unwrap();
    assert!(s
        .clone()
        .command(&command(
            &s,
            &b,
            CommandAction::AbandonReplacement {
                repair_ceremony_id: Uuid::new_v4(),
            }
        ))
        .is_err());
    s.command(&command(
        &s,
        &b,
        CommandAction::AbandonReplacement {
            repair_ceremony_id: plan.repair_ceremony_id,
        },
    ))
    .unwrap();
    assert!(s.replacements.is_empty());
    assert!(!s.command(&reserve).unwrap());
    assert!(s.replacements.is_empty()); // An old ACK is never current authority.
    let ids = [
        plan.repair_session_id,
        plan.repair_ceremony_id,
        plan.refresh.session_id,
        plan.refresh.ceremony_id,
        plan.recipient_anchor_id,
    ];
    for id in ids {
        let mut new = replacement_plan(&s, &b, 18);
        new.repair_session_id = id;
        assert!(s
            .clone()
            .command(&command(
                &s,
                &b,
                CommandAction::ReserveReplacement {
                    plan: Box::new(new),
                }
            ))
            .is_err());
        let mut retry = retry(&b);
        retry.authorized.intent.crypto_execution_id = id;
        let error = s
            .clone()
            .permit(
                &request(&s, &retry, PARTIES[0], 1),
                &node_keys()[PARTIES[0]],
                1000,
            )
            .unwrap_err();
        assert!(error.to_string().contains("replacement identities"));
    }
    for field in 0..2 {
        let mut new = replacement_plan(&s, &b, 18);
        if field == 0 {
            new.refresh.node_keys = plan.refresh.node_keys.clone();
        } else {
            new.recipient_anchor_id = plan.recipient_anchor_id;
        }
        assert!(s
            .clone()
            .command(&command(
                &s,
                &b,
                CommandAction::ReserveReplacement {
                    plan: Box::new(new),
                }
            ))
            .is_err());
    }
    let fresh = replacement_plan(&s, &b, 18);
    s.command(&command(
        &s,
        &b,
        CommandAction::ReserveReplacement {
            plan: Box::new(fresh.clone()),
        },
    ))
    .unwrap();
    assert_eq!(s.replacements.values().next().unwrap().plan, fresh);
}
