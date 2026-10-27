//! Collect the three original signer receipts. This neither allocates a custody
//! wallet nor substitutes transport identity for custody's detached receipt pins.
use super::*;
use axum::extract::DefaultBodyLimit;
use serde::de::DeserializeOwned;
use wallet_mpc_protocol::solana_provisioning::{Approval, Claim, Evidence, Report, Root};
use wallet_mpc_storage::{atomic_create_secret, confirm_parent_durability};
use wallet_mpc_transport::SignerClient;

impl DurableStore {
    pub(super) fn seeded_allocation_fenced(&self, keyset: Uuid) -> Result<bool> {
        for suffix in ["pending", "root"] {
            let path = self
                .path
                .with_extension("solana-seeded")
                .join(format!("{keyset}.{suffix}"));
            if path.try_exists()? {
                confirm_parent_durability(&path)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct Service {
    store: Arc<DurableStore>,
    peers: SignerClient,
    lock: Mutex<()>,
}
impl Service {
    fn path(&self, name: &str) -> PathBuf {
        self.store.path.with_extension("solana-seeded").join(name)
    }
    fn read<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = self.path(name);
        if !path.exists() {
            return Ok(None);
        }
        let value = serde_json::from_slice(&fs::read(&path)?)?;
        confirm_parent_durability(&path)?;
        Ok(Some(value))
    }
    fn pin<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let path = self.path(name);
        let parent = path.parent().context("missing seeded parent")?;
        fs::create_dir_all(parent)?;
        confirm_parent_durability(parent)?;
        let bytes = serde_json::to_vec(value)?;
        if !path.exists() {
            atomic_create_secret(&path, &bytes)?;
        }
        ensure!(
            fs::read(&path)? == bytes,
            "immutable seeded agreement conflict"
        );
        confirm_parent_durability(&path)?;
        Ok(())
    }
    async fn collect<T: Serialize + DeserializeOwned + PartialEq + Clone>(
        &self,
        action: &str,
        approval: &Approval<T>,
    ) -> Result<Evidence<T>> {
        let mut reports = Vec::new();
        for party in PARTIES {
            let bytes = self
                .peers
                .request(
                    party,
                    "POST",
                    &format!("/internal/v1/solana/seeded/{action}"),
                    serde_json::to_vec(approval)?,
                )
                .await?;
            let report: Report<T> = serde_json::from_slice(&bytes)?;
            ensure!(
                report.party_id == party
                    && report.statement == approval.statement
                    && report.durable,
                "wrong authenticated seeded response"
            );
            reports.push(report);
        }
        let evidence = Evidence {
            statement: approval.statement.clone(),
            participant_agreement: reports,
        };
        evidence.validate()?;
        Ok(evidence)
    }
    async fn root(&self, keyset: Uuid, approval: Approval<Root>) -> Result<Evidence<Root>> {
        let root = &approval.statement;
        root.validate()?;
        ensure!(root.dkg.keyset_id == keyset, "wrong root path identity");
        let original = self
            .store
            .get_keyset(keyset)
            .await
            .map_err(|_| anyhow::anyhow!("unavailable DKG"))?
            .context("missing original DKG")?;
        ensure!(
            original.request == root.dkg
                && original.status == SessionStatus::Completed
                && original.group_public_key.as_ref() == Some(&root.group_public_key)
                && original.participant_agreement.len() == 3,
            "root differs from original completed DKG"
        );
        for (report, party) in original.participant_agreement.iter().zip(PARTIES) {
            ensure!(
                report.request == root.dkg
                    && report.party_id == party
                    && report.status == "COMPLETED"
                    && report.durable
                    && report.group_public_key.as_ref() == Some(&root.group_public_key)
                    && report.public_key_package.as_ref() == Some(&root.public_key_package),
                "incomplete original DKG agreement"
            );
        }
        let name = format!("{keyset}.root");
        if let Some(previous) = self.read::<Evidence<Root>>(&name)? {
            previous.validate()?;
            ensure!(previous.statement == *root, "original root cannot change");
            return Ok(previous);
        }
        // Serialize against create_sign under its original durable-state lock.
        // There are no coordinator callbacks in these bounded signer RPCs.
        // Conservatively reject even never-executed historical signing claims.
        let data = self.store.data.lock().await;
        ensure!(
            !data.signing.values().any(|s| s.request.keyset_id == keyset),
            "root already has historical signing intent"
        );
        for party in PARTIES {
            let bytes = self
                .peers
                .request(
                    party,
                    "POST",
                    "/internal/v1/solana/seeded/probe",
                    serde_json::to_vec(&approval)?,
                )
                .await?;
            let eligibility: serde_json::Value = serde_json::from_slice(&bytes)?;
            ensure!(
                eligibility
                    == serde_json::json!({"statement": root, "party_id": party, "eligible": true}),
                "ineligible original root participant"
            );
        }
        // A failed/uncertain collection may leave signer dedications. Retain the
        // original intent fence; it can never silently reopen legacy signing.
        self.pin(&format!("{keyset}.pending"), root)?;
        let evidence = self.collect("enroll", &approval).await?;
        self.pin(&name, &evidence)?;
        drop(data);
        Ok(evidence)
    }
    async fn claim(&self, keyset: Uuid, approval: Approval<Claim>) -> Result<Evidence<Claim>> {
        let claim = &approval.statement;
        claim.validate()?;
        let root: Evidence<Root> = self
            .read(&format!("{keyset}.root"))?
            .context("missing original seeded enrollment")?;
        root.validate()?;
        ensure!(
            claim.root == root.statement && claim.root.dkg.keyset_id == keyset,
            "claim namespace/keyset mismatch"
        );
        let name = format!("{}.claim", claim.reservation_id);
        if let Some(previous) = self.read::<Evidence<Claim>>(&name)? {
            previous.validate()?;
            ensure!(
                previous.statement == *claim,
                "original reservation cannot change"
            );
            return Ok(previous);
        }
        let evidence = self.collect("approve", &approval).await?;
        self.pin(&name, &evidence)?;
        Ok(evidence)
    }
}
async fn root(
    State(service): State<Arc<Service>>,
    Path(keyset): Path<Uuid>,
    Json(approval): Json<Approval<Root>>,
) -> Result<Json<Evidence<Root>>, StatusCode> {
    let _guard = service.lock.lock().await;
    service
        .root(keyset, approval)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
async fn claim(
    State(service): State<Arc<Service>>,
    Path(keyset): Path<Uuid>,
    Json(approval): Json<Approval<Claim>>,
) -> Result<Json<Evidence<Claim>>, StatusCode> {
    let _guard = service.lock.lock().await;
    service
        .claim(keyset, approval)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
pub(super) fn router(store: Arc<DurableStore>, peers: SignerClient) -> Router {
    Router::new()
        .route("/v1/keysets/{id}/solana-seeded-root", post(root))
        .route("/v1/keysets/{id}/solana-seeded-claims", post(claim))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(Arc::new(Service {
            store,
            peers,
            lock: Mutex::new(()),
        }))
}
