//! Native iOS UI Security Boundary
//! All key entry and activation state transitions are handled exclusively by
//! SwiftUI (`KeyGatekeeperView`) -> `SecCoreBridge` -> `sec_core_activate`.
//! No parallel native alert handlers or redundant `dlsym` stubs live here.
