//! Immutable encrypted staging of ONE repaired participant share. Staging is
//! never an active generation and cannot replace an original DKG record.
use anyhow::{ensure, Context, Result};
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use wallet_mpc_protocol::{
    dkg::identifier, sign::public_package, solana_recovery::ReplacementPlan,
};
use wallet_mpc_storage::{
    atomic_create_secret, confirm_parent_durability, LocalAesWrapper, ShareIdentity, Wrapper,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    version: u16,
    plan: ReplacementPlan,
    party: String,
    key_package: Vec<u8>,
}

impl Drop for Blob {
    fn drop(&mut self) {
        self.key_package.zeroize();
    }
}

pub struct Store {
    directory: PathBuf,
    party: String,
    wrapper: LocalAesWrapper,
}
impl Store {
    pub fn open(storage: &Path, wrapping_key: &Path, party: String) -> Result<Self> {
        ensure!(identifier(&party).is_some(), "unknown repair participant");
        let directory = storage.join("solana-repair-staging");
        fs::create_dir_all(&directory)?;
        ensure!(
            fs::symlink_metadata(&directory)?.file_type().is_dir(),
            "repair staging cannot be a symlink"
        );
        confirm_parent_durability(&directory)?;
        Ok(Self {
            directory,
            party,
            wrapper: LocalAesWrapper::from_key_file(wrapping_key)?,
        })
    }
    fn validate(&self, plan: &ReplacementPlan, key: &frost::keys::KeyPackage) -> Result<()> {
        plan.validate_shape()?;
        let public = public_package(
            &plan.refresh.previous_public_key_package,
            &plan.refresh.root.group_public_key,
        )?;
        ensure!(
            self.party == plan.party_id
                && *key.identifier() == identifier(&self.party).context("repair participant")?
                && *key.min_signers() == 2
                && key.verifying_key() == public.verifying_key()
                && public.verifying_shares().get(key.identifier()) == Some(key.verifying_share())
                && frost::keys::VerifyingShare::from(*key.signing_share())
                    == *key.verifying_share(),
            "exact current-generation participant share required; no full-key reconstruction"
        );
        Ok(())
    }
    fn path(&self, plan: &ReplacementPlan) -> Result<PathBuf> {
        plan.validate_shape()?;
        Ok(self.directory.join(format!(
            "{}-{}.enc",
            plan.refresh.root.identity()?,
            plan.repair_ceremony_id
        )))
    }
    fn identity(&self, plan: &ReplacementPlan) -> Result<ShareIdentity> {
        Ok(ShareIdentity {
            keyset_id: plan.refresh.root.dkg.keyset_id,
            party_id: self.party.clone(),
            algorithm: format!("FROST_ED25519_REPAIR_V1:{}", plan.identity()?),
        })
    }
    pub fn persist(&self, plan: &ReplacementPlan, key: &frost::keys::KeyPackage) -> Result<()> {
        self.validate(plan, key)?;
        let path = self.path(plan)?;
        let bytes = Zeroizing::new(key.serialize()?);
        if path.try_exists()? {
            let previous = self.load(plan)?;
            let previous_bytes = Zeroizing::new(previous.serialize()?);
            ensure!(
                previous_bytes.as_slice() == bytes.as_slice(),
                "repair staging cannot change"
            );
            confirm_parent_durability(&path)?;
            return Ok(());
        }
        let blob = Blob {
            version: 1,
            plan: plan.clone(),
            party: self.party.clone(),
            key_package: bytes.to_vec(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&blob)?);
        let encrypted = self.wrapper.wrap(&self.identity(plan)?, &plain)?;
        atomic_create_secret(&path, &encrypted)?;
        Ok(())
    }
    pub fn present(&self, plan: &ReplacementPlan) -> Result<bool> {
        let exists = self.path(plan)?.try_exists()?;
        if exists {
            self.load(plan)?;
        }
        Ok(exists)
    }
    pub fn load(&self, plan: &ReplacementPlan) -> Result<frost::keys::KeyPackage> {
        let path = self.path(plan)?;
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_file() && metadata.len() <= 1024 * 1024,
            "invalid/bounded repaired-share staging file required"
        );
        let plain = self
            .wrapper
            .unwrap(&self.identity(plan)?, &fs::read(&path)?)?;
        let blob: Blob = serde_json::from_slice(&plain)?;
        ensure!(
            blob.version == 1 && blob.plan == *plan && blob.party == self.party,
            "exact original repair provenance required"
        );
        let key = frost::keys::KeyPackage::deserialize(&blob.key_package)?;
        self.validate(plan, &key)?;
        confirm_parent_durability(&path)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;
    use wallet_mpc_protocol::{
        dkg::{hex, PARTIES},
        solana_generation::RefreshStart,
        witness::hash,
    };

    // Upstream distributed DKG, never generate_with_dealer or key reconstruction.
    // This in-process storage negative is separate from genuine TLS acceptance.
    fn packages() -> (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ) {
        let ids = PARTIES.map(|p| identifier(p).unwrap());
        let mut s1 = BTreeMap::new();
        let mut p1 = BTreeMap::new();
        for id in ids {
            let (secret, public) = frost::keys::dkg::part1(id, 3, 2, rand_core::OsRng).unwrap();
            s1.insert(id, secret);
            p1.insert(id, public);
        }
        let mut s2 = BTreeMap::new();
        let mut p2: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();
        for id in ids {
            let incoming = p1
                .iter()
                .filter(|(p, _)| **p != id)
                .map(|(p, v)| (*p, v.clone()))
                .collect();
            let (secret, outgoing) =
                frost::keys::dkg::part2(s1.remove(&id).unwrap(), &incoming).unwrap();
            s2.insert(id, secret);
            for (recipient, package) in outgoing {
                p2.entry(recipient).or_default().insert(id, package);
            }
        }
        let mut keys = BTreeMap::new();
        let mut public = None;
        for id in ids {
            let incoming = p1
                .iter()
                .filter(|(p, _)| **p != id)
                .map(|(p, v)| (*p, v.clone()))
                .collect();
            let (key, package) = frost::keys::dkg::part3(&s2[&id], &incoming, &p2[&id]).unwrap();
            keys.insert(id, key);
            public = Some(package);
        }
        (keys, public.unwrap())
    }

    #[test]
    fn actual_upstream_repair_accepts_one_exact_share_and_rejects_forged_sigma() {
        let (keys, public) = packages();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/tests/fixtures/solana-refresh-pre-issuance.json"
        ))
        .unwrap();
        let start: RefreshStart = serde_json::from_value(fixture["start"].clone()).unwrap();
        let mut refresh = start.plan.value;
        let bytes = public.serialize().unwrap();
        refresh.root.group_public_key = hex(&public.verifying_key().serialize().unwrap());
        refresh.root.public_key_package = bytes.clone();
        refresh.previous.public_key_package_sha256 = hash(&bytes);
        refresh.previous_public_key_package = bytes;
        let previous_node_keys = refresh.node_keys.clone();
        refresh
            .node_keys
            .insert(PARTIES[0].into(), hash(b"unit replacement identity"));
        let plan = ReplacementPlan {
            refresh,
            previous_node_keys,
            party_id: PARTIES[0].into(),
            recipient_anchor_id: Uuid::new_v4(),
            recipient_profile_sha256: hash(b"unit explicit profile"),
            repair_session_id: Uuid::new_v4(),
            repair_ceremony_id: Uuid::new_v4(),
        };
        plan.validate_shape().unwrap();
        let recipient = identifier(PARTIES[0]).unwrap();
        let helpers = [
            identifier(PARTIES[1]).unwrap(),
            identifier(PARTIES[2]).unwrap(),
        ];
        let first: Vec<_> = helpers
            .iter()
            .map(|p| {
                frost::keys::repairable::repair_share_part1::<frost::Ed25519Sha512, _>(
                    &helpers,
                    &keys[p],
                    &mut rand_core::OsRng,
                    recipient,
                )
                .unwrap()
            })
            .collect();
        let sigmas: Vec<_> = helpers
            .iter()
            .map(|p| frost::keys::repairable::repair_share_part2(&[first[0][p], first[1][p]]))
            .collect();
        let repaired =
            frost::keys::repairable::repair_share_part3(&sigmas, recipient, &public).unwrap();
        assert_eq!(repaired.signing_share(), keys[&recipient].signing_share());
        let directory =
            std::env::temp_dir().join(format!("custody-repair-unit-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let wrapping = directory.join("unit-wrapping.key");
        fs::write(&wrapping, [42u8; 32]).unwrap();
        fs::set_permissions(&wrapping, fs::Permissions::from_mode(0o600)).unwrap();
        let store = Store::open(&directory.join("shares"), &wrapping, PARTIES[0].into()).unwrap();
        store.persist(&plan, &repaired).unwrap();
        let path = store.path(&plan).unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            store.load(&plan).unwrap().signing_share(),
            repaired.signing_share()
        );
        // Upstream part3 performs addition, not proof against the public share.
        // Canonical zero Sigmas therefore parse, but must never be persisted.
        let forged = [frost::keys::repairable::Sigma::deserialize(&[0; 32]).unwrap(); 2];
        let invalid =
            frost::keys::repairable::repair_share_part3(&forged, recipient, &public).unwrap();
        assert!(store.persist(&plan, &invalid).is_err());
        assert!(store.persist(&plan, &keys[&helpers[0]]).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        let mut transplanted = plan.clone();
        transplanted.recipient_anchor_id = Uuid::new_v4();
        fs::write(store.path(&transplanted).unwrap(), &before).unwrap();
        assert!(store.load(&transplanted).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
