//! Plug-and-play PAS authentication middleware for Axum.
//!
//! This module eliminates OAuth2 boilerplate for Axum applications
//! integrating with [PAS](https://accounts.ppoppo.com) (Ppoppo Accounts System).
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use ppoppo_accounts::middleware::{PasAuthConfig, auth_routes, AuthUser};
//!
//! // 1. Implement UserStore and SessionStore traits for your app
//! // 2. Configure from environment
//! let config = PasAuthConfig::from_env()?;
//!
//! // 3. Mount auth routes
//! let app = axum::Router::new()
//!     .merge(auth_routes(config, user_store, session_store));
//!
//! // 4. Use AuthUser extractor in handlers
//! async fn handler(user: AuthUser) -> String {
//!     format!("Hello, {}", user.ppnum_id)
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

pub use config::{PasAuthConfig, PasAuthConfigBuilder};
pub use error::AuthError;
pub use extractor::AuthUser;
pub use routes::auth_routes;
pub use traits::{SessionStore, UserStore};
pub use types::NewSession;

/// Re-export cookie key type for builder API.
pub use axum_extra::extract::cookie::Key as CookieKey;
