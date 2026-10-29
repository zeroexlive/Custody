//! Independent generation/replay authority. State must be deployed separately
//! from signer backups; rollback of this authority itself is outside that claim.
mod authority;
mod state;
mod trust;
pub use authority::Authority;
pub use state::{Execution, RootState, Snapshot};
pub use trust::{AuthorityConfig, ProfileConfig};
pub use wallet_mpc_protocol::witness::{
    Acknowledgement, ExecutionStatus, ExecutionView, Phase, QueryReply, RootView,
};
