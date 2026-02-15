//! Plug-and-play PAS authentication middleware for Axum.
//!
//! This module eliminates OAuth2 boilerplate for Axum applications
//! integrating with [PAS](https://accounts.ppoppo.com) (Ppoppo Accounts System).
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use ppoppo_accounts::middleware::{PasAuthConfig, auth_routes, AuthPpnum};
//!
//! // 1. Implement PpnumStore and SessionStore traits for your app
//! // 2. Configure from environment
//! let config = PasAuthConfig::from_env()?;
//!
//! // 3. Mount auth routes
//! let app = axum::Router::new()
//!     .merge(auth_routes(config, ppnum_store, session_store));
//!
//! // 4. Use AuthPpnum extractor in handlers
//! async fn handler(auth: AuthPpnum) -> String {
//!     format!("Hello, {}", auth.ppnum_id)
//! }
//! ```

mod config;
mod cookies;
mod error;
mod extractor;
mod routes;
mod state;
mod traits;
mod types;

pub use config::PasAuthConfig;
pub use error::AuthError;
pub use extractor::AuthPpnum;
pub use routes::auth_routes;
pub use traits::{PpnumStore, SessionStore};
pub use types::NewSession;

/// Re-export cookie key type for builder API.
pub use axum_extra::extract::cookie::Key as CookieKey;
