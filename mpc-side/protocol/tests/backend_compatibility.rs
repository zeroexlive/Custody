//! Public known-input vectors only: never a custody key/share/signing fallback.
use cggmp24::generic_ec::coords::{HasAffineX, HasAffineXAndParity, HasAffineXY};
use cggmp24::{
    generic_ec::{Curve, Point, Scalar},
    hd_wallet::{ExtendedPublicKey, HdWallet, Slip10},
    supported_curves::Secp256k1,
};
use serde_json::{json, Value};
use wallet_mpc_protocol::{dkg::hex, hd::fingerprint, sign::decode_hex};
type E = Secp256k1;
fn public_vectors() -> Value {
    let mut scalars = Vec::new();
    for n in [0, 1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 129, 257, 1024] {
        let input: Vec<_> = (0..n).map(|i| (i * 73 + 19) as u8).collect();
        let a = Scalar::<E>::from_be_bytes_mod_order(&input);
        let b = Scalar::<E>::from_le_bytes_mod_order(&input);
        scalars.push(json!({
            "input": hex(&input),
            "be": hex(a.to_be_bytes().as_ref()),
            "le": hex(b.to_le_bytes().as_ref()),
            "serialized": a, "sum": a+b, "sub": a-b, "mul": a*b, "neg": -a,
            "inv": a.invert().map(|x| hex(x.to_be_bytes().as_ref()))
        }));
    }
    let mut points = Vec::new();
    for scalar in &scalars {
        let a: Scalar<E> = serde_json::from_value(scalar["serialized"].clone()).unwrap();
        let p = Point::<E>::generator() * a;
        if let Some(coords) = p.coords() {
            assert_eq!(Point::<E>::from_coords(&coords), Some(p));
        }
        if let Some((x, parity)) = p.x_and_parity() {
            assert_eq!(Point::<E>::from_x_and_parity(&x, parity), Some(p));
        }
        points.push(json!({
            "compressed": hex(p.to_bytes(true).as_ref()),
            "uncompressed": hex(p.to_bytes(false).as_ref()), "json": p,
            "x": p.x().map(|x| hex(x.as_be_bytes())),
            "coords": p.coords().map(|xy| json!({
                "x": hex(xy.x.as_be_bytes()), "y": hex(xy.y.as_be_bytes())
            })),
            "parity": p.x_and_parity().map(|(x, odd)| json!({
                "x": hex(x.as_be_bytes()), "odd": odd
            }))
        }));
    }
    let epub = ExtendedPublicKey::<E> {
        public_key: Point::<E>::generator() * Scalar::<E>::from(7u16),
        chain_code: [0x91; 32],
    };
    let mut hd = Vec::new();
    for index in [0, 1, 7, 65535, (1 << 31) - 1] {
        let child = Slip10::derive_child_public_key_with_path(
            &epub,
            [0, index].map(|i: u32| i.try_into().unwrap()),
        );
        hd.push(json!({
            "index": index, "public": hex(child.public_key.to_bytes(true).as_ref()),
            "chain_code": hex(&child.chain_code)
        }));
    }
    let mut validation = Vec::new();
    for b in [
        vec![],
        vec![0],
        vec![0; 32],
        vec![255; 32],
        vec![0; 33],
        vec![255; 33],
        vec![0; 65],
        vec![255; 65],
    ] {
        validation.push(json!({
            "input": hex(&b), "point": Point::<E>::from_bytes(&b).is_ok(),
            "scalar_be": Scalar::<E>::from_be_bytes(&b).is_ok(),
            "scalar_le": Scalar::<E>::from_le_bytes(&b).is_ok()
        }));
    }
    let zero = Point::<E>::zero();
    let vectors = json!({
        "curve": E::CURVE_NAME, "scalars": scalars, "points": points,
        "hd": hd, "validation": validation,
        "zero": { "compressed": hex(zero.to_bytes(true).as_ref()),
                  "uncompressed": hex(zero.to_bytes(false).as_ref()), "json": zero }
    });
    for p in vectors["points"].as_array().unwrap() {
        let parsed: Point<E> = serde_json::from_value(p["json"].clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), p["json"]);
        for encoding in ["compressed", "uncompressed"] {
            let bytes = decode_hex(p[encoding].as_str().unwrap()).unwrap();
            assert_eq!(Point::<E>::from_bytes(bytes).unwrap(), parsed);
        }
    }
    json!({
        "fingerprint": fingerprint("Custody/CRYPTO_BACKEND_PUBLIC_COMPAT_V1", &vectors).unwrap(),
        "vectors": vectors
    })
}

#[test]
fn original_rustcrypto013_public_encoding_and_hd_fingerprints() {
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/rustcrypto013-public-vectors.json")).unwrap();
    assert_eq!(public_vectors(), expected);
}

#[test]
fn scalar_order_boundaries_and_endian_round_trips() {
    let cases = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            true,
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            true,
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        (
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            true,
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        ),
        (
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            false,
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
            false,
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            false,
            "000000000000000000000000000000014551231950b75fc4402da1732fc9bebe",
        ),
    ];
    for (encoded, canonical, reduced) in cases {
        let bytes = decode_hex(encoded).unwrap();
        let mut little = bytes.clone();
        little.reverse();
        assert_eq!(Scalar::<E>::from_be_bytes(&bytes).is_ok(), canonical);
        assert_eq!(Scalar::<E>::from_le_bytes(&little).is_ok(), canonical);
        let scalar = Scalar::<E>::from_be_bytes_mod_order(&bytes);
        assert_eq!(hex(scalar.to_be_bytes().as_ref()), reduced);
        assert_eq!(scalar, Scalar::<E>::from_le_bytes_mod_order(&little));
        assert_eq!(
            serde_json::from_value::<Scalar<E>>(serde_json::to_value(scalar).unwrap()).unwrap(),
            scalar
        );
    }
}

#[test]
fn original_recoverable_signature_and_high_s_rejection() {
    use wallet_mpc_protocol::cggmp::{verified_signature, SigningExecution};
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/rustcrypto013-signature.json")).unwrap();
    let execution: SigningExecution = serde_json::from_value(fixture["execution"].clone()).unwrap();
    let low = decode_hex(fixture["signature"]["signature_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        verified_signature(&execution, &low).unwrap(),
        fixture["signature"]
    );
    let high = decode_hex(fixture["high_s_signature"].as_str().unwrap()).unwrap();
    assert_eq!(
        verified_signature(&execution, &high)
            .unwrap_err()
            .to_string(),
        "high-s signature rejected"
    );
    for invalid in [vec![], vec![0; 64], vec![255; 64], low[..63].to_vec()] {
        assert!(verified_signature(&execution, &invalid).is_err());
    }
    let mut wrong = execution;
    wrong.request.payload_hex = "11".repeat(32);
    use sha2::{Digest, Sha256};
    wrong.request.message_fingerprint = hex(&Sha256::digest([0x11; 32]));
    assert!(verified_signature(&wrong, &low).is_err());
}
