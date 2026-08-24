//! Re-export of the pure simulators. They moved into `bullet-application`
//! so the demo can call them without an adapter dependency; downstream
//! crates keep importing them from here.

pub use bullet_application::simulators::{ProviderSimulator, ScmSimulator, SimulatedInvocation};
