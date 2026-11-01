//! Explicit offline public profile transition; never an MPC signing fallback.
fn main() -> anyhow::Result<()> {
    wallet_mpc_signer::protected::migration::run(std::env::args().skip(1).collect())
}
