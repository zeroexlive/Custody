//! Immutable encrypted generations. Original DKG bytes are never overwritten.
//! These storage helpers do not establish lifecycle authority or active epoch.
use anyhow::{ensure, Context, Result};
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use wallet_mpc_protocol::{
    dkg::identifier, sign::public_package, solana_generation::RefreshPlan,
    solana_intent::Generation, solana_provisioning::Root, witness::hash,
};
use wallet_mpc_storage::{
    atomic_create_secret, confirm_parent_durability, LocalAesWrapper, ShareIdentity, Wrapper,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    version: u16,
    plan: RefreshPlan,
    generation: Generation,
    party: String,
    public_package: Vec<u8>,
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
fn validate(
    root: &Root,
    generation: &Generation,
    party: &str,
    public: &[u8],
    key: &frost::keys::KeyPackage,
) -> Result<()> {
    root.validate()?;
    ensure!(
        generation.epoch > 0
            && !generation.ceremony_id.is_nil()
            && generation.ceremony_id != root.dkg.execution_id
            && public.len() <= 4096
            && generation.public_key_package_sha256 == hash(public)
            && *key.identifier() == identifier(party).context("fixed generation party")?
            && *key.min_signers() == 2,
        "original root/current generation/party mismatch"
    );
    let package = public_package(public, &root.group_public_key)?;
    ensure!(
        package.verifying_shares().get(key.identifier()) == Some(key.verifying_share())
            && key.verifying_key() == package.verifying_key()
            && frost::keys::VerifyingShare::from(*key.signing_share()) == *key.verifying_share(),
        "generation private/public share mismatch"
    );
    Ok(())
}
impl Store {
    pub fn open(storage: &Path, wrapping_key: &Path, party: String) -> Result<Self> {
        ensure!(identifier(&party).is_some(), "unknown generation party");
        let directory = storage.join("solana-generations");
        fs::create_dir_all(&directory)?;
        ensure!(
            fs::symlink_metadata(&directory)?.file_type().is_dir(),
            "generation store cannot be a symlink"
        );
        confirm_parent_durability(&directory)?;
        Ok(Self {
            directory,
            party,
            wrapper: LocalAesWrapper::from_key_file(wrapping_key)?,
        })
    }
    fn path(&self, root: &Root, generation: &Generation) -> Result<PathBuf> {
        ensure!(
            generation.epoch > 0 && !generation.ceremony_id.is_nil(),
            "explicit nonoriginal generation required"
        );
        Ok(self.directory.join(format!(
            "{}-{}-{}.enc",
            root.identity()?,
            generation.epoch,
            generation.ceremony_id
        )))
    }
    fn identity(&self, root: &Root, generation: &Generation) -> Result<ShareIdentity> {
        Ok(ShareIdentity {
            keyset_id: root.dkg.keyset_id,
            party_id: self.party.clone(),
            algorithm: format!(
                "FROST_ED25519_GENERATION_V1:{}:{}:{}",
                root.identity()?,
                generation.epoch,
                generation.ceremony_id
            ),
        })
    }
    pub fn persist(
        &self,
        plan: &RefreshPlan,
        key: &frost::keys::KeyPackage,
        public: &frost::keys::PublicKeyPackage,
    ) -> Result<Generation> {
        plan.validate_shape()?;
        let bytes = public.serialize()?;
        let generation = Generation {
            epoch: plan.next_epoch,
            ceremony_id: plan.ceremony_id,
            public_key_package_sha256: hash(&bytes),
        };
        validate(&plan.root, &generation, &self.party, &bytes, key)?;
        ensure!(
            bytes != plan.previous_public_key_package,
            "refresh must change public verification shares"
        );
        let blob = Blob {
            version: 1,
            plan: plan.clone(),
            generation: generation.clone(),
            party: self.party.clone(),
            public_package: bytes,
            key_package: key.serialize()?,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&blob)?);
        let encrypted = self
            .wrapper
            .wrap(&self.identity(&plan.root, &generation)?, &plain)?;
        let path = self.path(&plan.root, &generation)?;
        if path.exists() {
            let (old, old_public) = self.load(&plan.root, &generation)?;
            ensure!(
                old.serialize()? == blob.key_package
                    && old_public == blob.public_package
                    && self.plan(&plan.root, &generation)? == *plan,
                "original generation cannot change"
            );
            confirm_parent_durability(&path)?;
        } else {
            atomic_create_secret(&path, &encrypted)?;
        }
        Ok(generation)
    }
    fn blob(&self, root: &Root, generation: &Generation) -> Result<Blob> {
        let blob = self.read_blob(root, generation)?;
        ensure!(
            blob.version == 1
                && blob.party == self.party
                && blob.plan.root == *root
                && blob.generation == *generation
                && blob.plan.ceremony_id == generation.ceremony_id
                && blob.plan.next_epoch == generation.epoch,
            "encrypted generation identity mismatch"
        );
        blob.plan.validate_shape()?;
        let key = frost::keys::KeyPackage::deserialize(&blob.key_package)?;
        validate(root, generation, &self.party, &blob.public_package, &key)?;
        Ok(blob)
    }
    fn read_blob(&self, root: &Root, generation: &Generation) -> Result<Blob> {
        let path = self.path(root, generation)?;
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            meta.file_type().is_file() && meta.len() <= 128 * 1024,
            "invalid encrypted generation file"
        );
        let encrypted = fs::read(&path)?;
        let plain = self
            .wrapper
            .unwrap(&self.identity(root, generation)?, &encrypted)?;
        let blob: Blob = serde_json::from_slice(&plain)?;
        confirm_parent_durability(&path)?;
        Ok(blob)
    }
    /// Recover only an already completed encrypted artifact. Missing material
    /// is not permission to rerun the consumed private ceremony.
    pub fn finished(&self, plan: &RefreshPlan) -> Result<Option<(Generation, Vec<u8>)>> {
        let hint = Generation {
            epoch: plan.next_epoch,
            ceremony_id: plan.ceremony_id,
            public_key_package_sha256: String::new(),
        };
        let path = self.path(&plan.root, &hint)?;
        if let Err(e) = fs::symlink_metadata(path) {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            } else {
                return Err(e.into());
            }
        }
        let data = self.read_blob(&plan.root, &hint)?;
        ensure!(
            data.plan == *plan,
            "completed generation belongs to another lifecycle plan"
        );
        let verified = self.blob(&plan.root, &data.generation)?;
        Ok(Some((
            verified.generation.clone(),
            verified.public_package.clone(),
        )))
    }
    pub fn load(
        &self,
        root: &Root,
        generation: &Generation,
    ) -> Result<(frost::keys::KeyPackage, Vec<u8>)> {
        let blob = self.blob(root, generation)?;
        Ok((
            frost::keys::KeyPackage::deserialize(&blob.key_package)?,
            blob.public_package.clone(),
        ))
    }
    pub fn plan(&self, root: &Root, generation: &Generation) -> Result<RefreshPlan> {
        Ok(self.blob(root, generation)?.plan.clone())
    }
}
