//! Plug-and-play PAS authentication middleware for Axum.
//!
//! This module eliminates OAuth2 boilerplate for Axum applications
//! integrating with [PAS](https://accounts.ppoppo.com) (Ppoppo Accounts System).
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use ppoppo_accounts::middleware::{PasAuthConfig, auth_routes, resolve_session};
//!
//! // 1. Implement AccountResolver and SessionStore traits for your app
//! // 2. Configure from environment
//! let config = PasAuthConfig::from_env()?;
//!
//! // 3. Mount auth routes
//! let app = axum::Router::new()
//!     .merge(auth_routes(config, account_resolver, session_store));
//!
//! // 4. Use resolve_session() in your middleware
//! let auth = resolve_session(&session_store, &jar, "cookie_name").await;
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
pub use extractor::{AuthPpnum, resolve_session};
pub use routes::auth_routes;
pub use traits::{AccountResolver, SessionStore};
pub use types::NewSession;

/// Re-export cookie key type for builder API.
pub use axum_extra::extract::cookie::Key as CookieKey;
