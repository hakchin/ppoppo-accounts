# ppoppo-accounts Architecture Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Improve ppoppo-accounts (v0.5.0) across 12 architectural issues — error handling, type design, and API ergonomics.

**Architecture:** Holistic refactor touching `error.rs`, `token.rs`, `well_known.rs`, `oauth.rs`, and the `middleware/` module. No backward compatibility; consumers (RCW, CTW) updated to match. Changes are ordered so the crate compiles after each task.

**Tech Stack:** Rust, thiserror, time (serde-well-known), axum/axum-extra, serde, pasetors

**Crate location:** `~/dev/ppo/ppoppo-accounts/`

**Consumer locations:**
- CTW: `~/dev/ppo/classytime/apps/classytime-web/`
- RCW: `~/dev/ppo/rollcall/apps/rollcall-web/`

---

### Task 1: Structured error types + token.rs refactor

**Design refs:** A2 (VerifiedClaims), A3 (Error types), B1 (TryFrom)

**Files:**
- Modify: `src/error.rs`
- Modify: `src/token.rs`

**Step 1: Add `TokenError` enum and update `Error` in `error.rs`**

Replace the entire file with:

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    #[error("invalid token format")]
    InvalidFormat,
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("{claim}: expected '{expected}', got '{actual}'")]
    ClaimMismatch {
        claim: &'static str,
        expected: String,
        actual: String,
    },
    #[error("missing claim: {0}")]
    MissingClaim(&'static str),
    #[error("missing payload")]
    MissingPayload,
    #[error("invalid footer")]
    InvalidFooter,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("OAuth2 error: {0}")]
    OAuth(String),
    #[cfg(feature = "oauth")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("token error: {0}")]
    Token(#[from] TokenError),
    #[error("Invalid ppnum: {0}")]
    InvalidPpnum(String),
    #[cfg(feature = "oauth")]
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
}
```

Key changes:
- NEW `TokenError` enum with 6 variants
- `Error::Token(String)` → `Error::Token(TokenError)` with `#[from]`
- `Error::OAuth(String)` stays unchanged for now (Task 3 will structure it)
- `Error::Token` display changes from "Token verification error: X" to "token error: X"

**Step 2: Update `token.rs` — all Error::Token sites + VerifiedClaims**

Replace the entire file with:

```rust
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pasetors::claims::ClaimsValidationRules;
use pasetors::keys::AsymmetricPublicKey;
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::{public, Public};
use serde_json::Value as JsonValue;

use crate::error::{Error, TokenError};
use crate::types::KeyId;

const TOKEN_PREFIX: &str = "v4.public.";

/// Ed25519 public key (32 bytes) for token verification.
///
/// Independent implementation from `pas-token` — only needs hex parsing
/// and PASETO verification, no PASERK key ID computation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 32],
}

impl PublicKey {
    /// Get the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[cfg(feature = "token")]
impl TryFrom<&crate::well_known::WellKnownPasetoKey> for PublicKey {
    type Error = Error;

    fn try_from(key: &crate::well_known::WellKnownPasetoKey) -> Result<Self, Error> {
        parse_public_key_hex(&key.public_key_hex)
    }
}

/// Parses a hex-encoded Ed25519 public key (32 bytes) into a `PublicKey`.
///
/// # Errors
///
/// Returns `Error::Token` if the hex is invalid or the key length is not 32 bytes.
pub fn parse_public_key_hex(public_key_hex: &str) -> Result<PublicKey, Error> {
    let bytes = hex::decode(public_key_hex)
        .map_err(|e| TokenError::VerificationFailed(format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(TokenError::VerificationFailed(format!(
            "invalid key length: expected 32, got {}",
            bytes.len()
        )).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey { bytes: arr })
}

/// Verified claims from a PASETO token.
///
/// After successful verification, `iss` and `aud` are stored as owned fields.
/// Access them via typed accessors instead of raw JSON lookup.
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    iss: String,
    aud: String,
    inner: JsonValue,
}

impl VerifiedClaims {
    /// Issuer claim (guaranteed present after verification).
    #[must_use]
    pub fn iss(&self) -> &str {
        &self.iss
    }

    /// Audience claim (guaranteed present after verification).
    #[must_use]
    pub fn aud(&self) -> &str {
        &self.aud
    }

    /// Subject claim.
    #[must_use]
    pub fn sub(&self) -> Option<&str> {
        self.inner.get("sub").and_then(|v| v.as_str())
    }

    /// Gets a claim value by key (for dynamic/extra claims).
    #[must_use]
    pub fn get_claim(&self, key: &str) -> Option<&JsonValue> {
        self.inner.get(key)
    }

    /// Gets the inner JSON value.
    #[must_use]
    pub fn as_json(&self) -> &JsonValue {
        &self.inner
    }
}

/// Verifies a PASETO v4.public access token.
///
/// # Errors
///
/// Returns `Error::Token` if the token format is invalid, the signature
/// verification fails, or the `iss`/`aud` claims do not match the expected values.
pub fn verify_v4_public_access_token(
    public_key: &PublicKey,
    token_str: &str,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<VerifiedClaims, Error> {
    if !token_str.starts_with(TOKEN_PREFIX) {
        return Err(TokenError::InvalidFormat.into());
    }

    let pk = AsymmetricPublicKey::<V4>::from(&public_key.bytes[..])
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

    let validation_rules = ClaimsValidationRules::new();

    let untrusted_token = UntrustedToken::<Public, V4>::try_from(token_str)
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

    let trusted_token = public::verify(&pk, &untrusted_token, &validation_rules, None, None)
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

    let payload = trusted_token
        .payload_claims()
        .ok_or(TokenError::MissingPayload)?;
    let payload_str = payload
        .to_string()
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;
    let json_value: JsonValue = serde_json::from_str(&payload_str)
        .map_err(|e| TokenError::VerificationFailed(e.to_string()))?;

    let iss = validate_claim(&json_value, "iss", expected_issuer)?;
    let aud = validate_claim(&json_value, "aud", expected_audience)?;

    Ok(VerifiedClaims {
        iss,
        aud,
        inner: json_value,
    })
}

/// Validates a JSON claim matches expected value; returns the actual value on success.
fn validate_claim(
    claims: &JsonValue,
    key: &'static str,
    expected: &str,
) -> Result<String, TokenError> {
    let actual = claims
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or(TokenError::MissingClaim(key))?;
    if actual != expected {
        return Err(TokenError::ClaimMismatch {
            claim: key,
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(actual.to_string())
}

/// Extract key ID from a PASETO token without verifying signature.
///
/// # Errors
///
/// Returns `Error::Token` if the token format is invalid or the footer
/// does not contain a `kid` claim.
pub fn extract_kid_from_token(token_str: &str) -> Result<KeyId, Error> {
    let footer_bytes = extract_footer_from_token(token_str)?;
    extract_kid_from_untrusted_footer(&footer_bytes)
}

/// Extracts the key ID (kid) from an untrusted token's footer.
pub(crate) fn extract_kid_from_untrusted_footer(footer_bytes: &[u8]) -> Result<KeyId, Error> {
    let footer_str = std::str::from_utf8(footer_bytes)
        .map_err(|_| TokenError::InvalidFooter)?;

    let footer_json: JsonValue = serde_json::from_str(footer_str)
        .map_err(|_| TokenError::InvalidFooter)?;

    let kid = footer_json
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or(TokenError::MissingClaim("kid"))?
        .to_owned();

    Ok(KeyId(kid))
}

/// Extracts the footer bytes from a PASETO token string.
pub(crate) fn extract_footer_from_token(token_str: &str) -> Result<Vec<u8>, Error> {
    if !token_str.starts_with(TOKEN_PREFIX) {
        return Err(TokenError::InvalidFormat.into());
    }

    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() != 4 {
        return Err(TokenError::InvalidFormat.into());
    }

    let footer_b64 = parts[3];
    if footer_b64.is_empty() {
        return Ok(Vec::new());
    }

    URL_SAFE_NO_PAD
        .decode(footer_b64)
        .map_err(|_| TokenError::InvalidFooter.into())
}
```

Key changes from original `token.rs`:
- All `Error::Token("message".into())` → specific `TokenError` variants
- `VerifiedClaims` stores `iss: String` and `aud: String` as owned fields (no more `.expect()`)
- `validate_claim()` returns `Result<String, TokenError>` (returns value on success)
- `TryFrom<&WellKnownPasetoKey> for PublicKey` added
- Import changed: `use crate::error::{Error, TokenError};`

**Step 3: Run tests**

Run: `cargo test -p ppoppo-accounts`
Expected: All existing tests pass (types, oauth, pkce tests are unaffected).

**Step 4: Commit**

```bash
git add src/error.rs src/token.rs
git commit -m "refactor: structured TokenError + VerifiedClaims owned fields

- Add TokenError enum with 6 specific variants
- Error::Token(String) → Error::Token(TokenError) with #[from]
- VerifiedClaims stores iss/aud as owned String fields (no .expect())
- Add TryFrom<&WellKnownPasetoKey> for PublicKey"
```

---

### Task 2: Typed timestamps (time dependency + well_known + oauth)

**Design refs:** B2 (timestamps)

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/well_known.rs`
- Modify: `src/oauth.rs`

**Step 1: Update `Cargo.toml` — make `time` non-optional**

Change the `time` dependency from optional to required with serde features:

```toml
# Replace:
# time = { version = "0.3", optional = true }
# With:
time = { version = "0.3", features = ["serde", "serde-well-known"] }
```

Remove `"dep:time"` from the `axum` feature list:

```toml
# Replace:
# axum = ["oauth", "dep:axum", "dep:axum-extra", "dep:tracing", "dep:time", "dep:urlencoding"]
# With:
axum = ["oauth", "dep:axum", "dep:axum-extra", "dep:tracing", "dep:urlencoding"]
```

**Step 2: Update `src/well_known.rs` — typed timestamp**

Replace the entire file with:

```rust
use serde::{Deserialize, Serialize};

use crate::types::KeyId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WellKnownPasetoDocument {
    pub issuer: String,
    pub version: String,
    pub keys: Vec<WellKnownPasetoKey>,
    pub cache_ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WellKnownPasetoKey {
    pub kid: KeyId,
    pub public_key_hex: String,
    pub status: WellKnownKeyStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum WellKnownKeyStatus {
    Active,
    Retiring,
    Revoked,
}
```

**Step 3: Update `src/oauth.rs` — UserInfo typed timestamp + with_http_client + structured OAuth error**

Changes to `oauth.rs`:

a) Update `UserInfo` struct — change `created_at` type:

```rust
/// User info from Ppoppo Accounts userinfo endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UserInfo {
    pub sub: PpnumId,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub ppnum: Option<Ppnum>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created_at: Option<time::OffsetDateTime>,
}
```

b) Add `with_http_client` to `AuthClient`:

```rust
impl AuthClient {
    /// Create a new Ppoppo Accounts auth client.
    #[must_use]
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Use a custom HTTP client (for connection pool reuse or testing).
    #[must_use]
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http = client;
        self
    }

    // ... rest unchanged
}
```

c) Update `ensure_success` to use structured `Error::OAuth`:

```rust
    async fn ensure_success(
        response: reqwest::Response,
        operation: &'static str,
    ) -> Result<reqwest::Response, Error> {
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        Err(Error::OAuth {
            operation,
            status: Some(status),
            detail: body,
        })
    }
```

d) Update `Error::OAuth` in `src/error.rs`:

```rust
    // Replace:
    // #[error("OAuth2 error: {0}")]
    // OAuth(String),
    // With:
    #[error("OAuth2 {operation} failed: {detail}")]
    OAuth {
        operation: &'static str,
        status: Option<u16>,
        detail: String,
    },
```

e) Update `ensure_success` callers — the `operation` parameter changes from `&str` to `&'static str`.

In `exchange_code`:
```rust
        let response = Self::ensure_success(response, "token exchange").await?;
```

In `get_user_info`:
```rust
        let response = Self::ensure_success(response, "userinfo request").await?;
```

Both already pass string literals, so no change needed in the callers.

f) Update `src/middleware/error.rs` — the `From<Error> for AuthError` impl:

```rust
impl From<crate::error::Error> for AuthError {
    fn from(e: crate::error::Error) -> Self {
        Self::OAuth(e.to_string())
    }
}
```

This stays the same — `e.to_string()` calls Display which formats the new structured OAuth error correctly.

g) Update the `UserInfo::with_email` test builder (if used in tests) — check oauth.rs tests reference `created_at`:

The existing tests in `oauth.rs` don't reference `created_at`, so no test changes needed.

**Step 4: Update `lib.rs` re-export**

Add `TokenError` to the token re-exports:

```rust
#[cfg(feature = "token")]
pub use token::{
    PublicKey, VerifiedClaims, extract_kid_from_token, parse_public_key_hex,
};
```

Also add the TokenError re-export from error.rs:

```rust
pub use error::{Error, TokenError};
```

Wait — `TokenError` is defined in `error.rs` which is always available (no feature gate). So re-export it from root:

In `lib.rs`, change:
```rust
pub use error::Error;
```
to:
```rust
pub use error::{Error, TokenError};
```

**Step 5: Run tests**

Run: `cargo test -p ppoppo-accounts`
Expected: All tests pass. OAuth tests still work because they don't test error variants.

**Step 6: Commit**

```bash
git add Cargo.toml src/error.rs src/well_known.rs src/oauth.rs src/lib.rs
git commit -m "refactor: typed timestamps + structured OAuth error + injectable HTTP client

- time is now a non-optional dependency with serde-well-known
- WellKnownPasetoKey.created_at: String → time::OffsetDateTime
- UserInfo.created_at: Option<String> → Option<time::OffsetDateTime>
- Error::OAuth(String) → OAuth { operation, status, detail }
- AuthClient::with_http_client() for testability and pool reuse
- TokenError re-exported from crate root"
```

---

### Task 3: Middleware — AuthSettings extraction + route fixes

**Design refs:** C1 (AuthSettings), A4 (login_error), A5 (dev_login dead code)

**Files:**
- Modify: `src/middleware/config.rs`
- Modify: `src/middleware/state.rs`
- Modify: `src/middleware/routes.rs`
- Modify: `src/middleware/mod.rs`

All middleware changes must be in one task because `AuthState` field access in `routes.rs` changes when `AuthSettings` is introduced.

**Step 1: Extract `AuthSettings` in `config.rs`**

Replace the entire file with:

```rust
use axum_extra::extract::cookie::Key;
use url::Url;

use super::error::AuthError;
use crate::oauth::{AuthClient, OAuthConfig};

/// Shared auth settings used by both config and runtime state.
#[derive(Clone)]
pub(crate) struct AuthSettings {
    pub(crate) cookie_key: Key,
    pub(crate) session_cookie_name: String,
    pub(crate) session_ttl_days: i64,
    pub(crate) secure_cookies: bool,
    pub(crate) auth_path: String,
    pub(crate) login_redirect: String,
    pub(crate) logout_redirect: String,
    pub(crate) error_redirect: String,
    pub(crate) dev_login_enabled: bool,
}

impl AuthSettings {
    fn defaults() -> Self {
        Self {
            cookie_key: Key::generate(),
            session_cookie_name: "__ppoppo_session".into(),
            session_ttl_days: 30,
            secure_cookies: true,
            auth_path: "/api/auth".into(),
            login_redirect: "/".into(),
            logout_redirect: "/".into(),
            error_redirect: "/login".into(),
            dev_login_enabled: false,
        }
    }
}

/// PAS authentication configuration.
///
/// Required field (`client`) is a constructor parameter — no runtime "missing field" errors.
///
/// Use [`from_env()`](PasAuthConfig::from_env) for convention-based setup,
/// or [`new()`](PasAuthConfig::new) with `with_*` methods for full control.
pub struct PasAuthConfig {
    pub(super) client: AuthClient,
    pub(super) settings: AuthSettings,
}

impl PasAuthConfig {
    /// Create config with the required `AuthClient`.
    ///
    /// All optional fields use sensible defaults. Override with `with_*` methods.
    #[must_use]
    pub fn new(client: AuthClient) -> Self {
        Self {
            client,
            settings: AuthSettings::defaults(),
        }
    }

    /// Create config from environment variables.
    ///
    /// # Required env vars
    /// - `PAS_CLIENT_ID`: OAuth2 client ID
    /// - `PAS_REDIRECT_URI`: OAuth2 callback URI (must be a valid URL)
    ///
    /// # Optional env vars
    /// - `PAS_AUTH_URL`: Override PAS authorize endpoint
    /// - `PAS_TOKEN_URL`: Override PAS token endpoint
    /// - `PAS_USERINFO_URL`: Override PAS userinfo endpoint
    /// - `PAS_SCOPES`: Comma-separated OAuth2 scopes
    /// - `DEV_AUTH`: Set to `"1"` or `"true"` to enable dev-login route and disable secure cookies
    /// - `COOKIE_KEY`: Cookie encryption key bytes
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Config`] if required env vars are missing or URLs are invalid.
    pub fn from_env() -> Result<Self, AuthError> {
        let client_id = std::env::var("PAS_CLIENT_ID")
            .map_err(|_| AuthError::Config("PAS_CLIENT_ID is required".into()))?;
        let redirect_uri_str = std::env::var("PAS_REDIRECT_URI")
            .map_err(|_| AuthError::Config("PAS_REDIRECT_URI is required".into()))?;
        let redirect_uri: Url = redirect_uri_str
            .parse()
            .map_err(|e| AuthError::Config(format!("PAS_REDIRECT_URI: {e}")))?;

        let mut config = OAuthConfig::new(client_id, redirect_uri);

        if let Ok(url_str) = std::env::var("PAS_AUTH_URL") {
            let url: Url = url_str
                .parse()
                .map_err(|e| AuthError::Config(format!("PAS_AUTH_URL: {e}")))?;
            config = config.with_auth_url(url);
        }
        if let Ok(url_str) = std::env::var("PAS_TOKEN_URL") {
            let url: Url = url_str
                .parse()
                .map_err(|e| AuthError::Config(format!("PAS_TOKEN_URL: {e}")))?;
            config = config.with_token_url(url);
        }
        if let Ok(url_str) = std::env::var("PAS_USERINFO_URL") {
            let url: Url = url_str
                .parse()
                .map_err(|e| AuthError::Config(format!("PAS_USERINFO_URL: {e}")))?;
            config = config.with_userinfo_url(url);
        }
        if let Ok(scopes) = std::env::var("PAS_SCOPES") {
            config =
                config.with_scopes(scopes.split(',').map(|s| s.trim().to_string()).collect());
        }

        let dev_auth = matches!(
            std::env::var("DEV_AUTH").as_deref(),
            Ok("1") | Ok("true"),
        );

        let cookie_key = std::env::var("COOKIE_KEY")
            .ok()
            .and_then(|k| {
                let bytes = k.as_bytes();
                Key::try_from(bytes).ok()
            })
            .unwrap_or_else(Key::generate);

        Ok(Self::new(AuthClient::new(config))
            .with_cookie_key(cookie_key)
            .with_secure_cookies(!dev_auth)
            .with_dev_login_enabled(dev_auth))
    }

    /// Set the cookie encryption key. If not set, a random key is generated.
    #[must_use]
    pub fn with_cookie_key(mut self, key: Key) -> Self {
        self.settings.cookie_key = key;
        self
    }

    /// Set the session cookie name (default: `"__ppoppo_session"`).
    #[must_use]
    pub fn with_session_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.settings.session_cookie_name = name.into();
        self
    }

    /// Set the session cookie TTL in days (default: 30).
    #[must_use]
    pub fn with_session_ttl_days(mut self, days: i64) -> Self {
        self.settings.session_ttl_days = days;
        self
    }

    /// Set whether to use secure cookies (default: true).
    #[must_use]
    pub fn with_secure_cookies(mut self, secure: bool) -> Self {
        self.settings.secure_cookies = secure;
        self
    }

    /// Set the auth routes base path (default: `"/api/auth"`).
    #[must_use]
    pub fn with_auth_path(mut self, path: impl Into<String>) -> Self {
        self.settings.auth_path = path.into();
        self
    }

    /// Set the post-login redirect path (default: `"/"`).
    #[must_use]
    pub fn with_login_redirect(mut self, path: impl Into<String>) -> Self {
        self.settings.login_redirect = path.into();
        self
    }

    /// Set the post-logout redirect path (default: `"/"`).
    #[must_use]
    pub fn with_logout_redirect(mut self, path: impl Into<String>) -> Self {
        self.settings.logout_redirect = path.into();
        self
    }

    /// Set the error redirect path for OAuth failures (default: `"/login"`).
    #[must_use]
    pub fn with_error_redirect(mut self, path: impl Into<String>) -> Self {
        self.settings.error_redirect = path.into();
        self
    }

    /// Enable the dev-login route (default: false).
    #[must_use]
    pub fn with_dev_login_enabled(mut self, enabled: bool) -> Self {
        self.settings.dev_login_enabled = enabled;
        self
    }
}
```

**Step 2: Update `state.rs` — embed `AuthSettings`**

Replace the entire file with:

```rust
use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;

use super::config::AuthSettings;
use super::traits::{AccountResolver, SessionStore};
use crate::oauth::AuthClient;

/// Shared state for auth route handlers.
///
/// Generic over `U` (AccountResolver) and `S` (SessionStore) for compile-time
/// monomorphic dispatch — no `dyn` trait objects or `Pin<Box<dyn Future>>`.
pub(super) struct AuthState<U, S> {
    pub(super) client: Arc<AuthClient>,
    pub(super) account_resolver: Arc<U>,
    pub(super) session_store: Arc<S>,
    pub(super) settings: AuthSettings,
}

// Manual Clone: avoid derive adding `U: Clone, S: Clone` bounds.
impl<U, S> Clone for AuthState<U, S> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            account_resolver: self.account_resolver.clone(),
            session_store: self.session_store.clone(),
            settings: self.settings.clone(),
        }
    }
}

// PrivateCookieJar requires Key to be extractable from state
impl<U: AccountResolver, S: SessionStore> FromRef<AuthState<U, S>> for Key {
    fn from_ref(state: &AuthState<U, S>) -> Self {
        state.settings.cookie_key.clone()
    }
}
```

**Step 3: Update `routes.rs` — use `settings.*`, fix `login_error`, remove dead code**

Replace the entire file with:

```rust
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header::USER_AGENT};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_extra::extract::PrivateCookieJar;
use serde::Deserialize;

use super::config::PasAuthConfig;
use super::cookies;
use super::state::AuthState;
use super::traits::{AccountResolver, SessionStore};
use super::types::NewSession;
use crate::types::PpnumId;

/// Create the PAS authentication router.
///
/// Mounts the following routes under `config.auth_path` (default: `/api/auth`):
/// - `GET /login` — Redirect to PAS with PKCE
/// - `GET /callback` — Handle PAS OAuth2 callback
/// - `GET|POST /logout` — Destroy session and clear cookie
/// - `GET /dev-login` — Dev-only test login (if enabled)
pub fn auth_routes<U, S>(config: PasAuthConfig, account_resolver: U, session_store: S) -> Router
where
    U: AccountResolver,
    S: SessionStore,
{
    let auth_path = config.settings.auth_path.clone();

    let state = AuthState {
        client: Arc::new(config.client),
        account_resolver: Arc::new(account_resolver),
        session_store: Arc::new(session_store),
        settings: config.settings,
    };

    let mut router = Router::new()
        .route(&format!("{auth_path}/login"), get(login::<U, S>))
        .route(&format!("{auth_path}/callback"), get(callback::<U, S>))
        .route(
            &format!("{auth_path}/logout"),
            get(logout::<U, S>).post(logout::<U, S>),
        );

    if state.settings.dev_login_enabled {
        router = router.route(&format!("{auth_path}/dev-login"), get(dev_login::<U, S>));
    }

    router.with_state(state)
}

// ── Login ──────────────────────────────────────────────────────────

async fn login<U: AccountResolver, S: SessionStore>(
    State(state): State<AuthState<U, S>>,
    jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, Redirect), Response> {
    let auth_req = state.client.authorization_url();

    let (pkce_cookie, state_cookie) = cookies::pkce_cookies(
        &auth_req.code_verifier,
        &auth_req.state,
        state.settings.secure_cookies,
        &state.settings.auth_path,
    );

    let jar = jar.add(pkce_cookie).add(state_cookie);

    Ok((jar, Redirect::to(&auth_req.url)))
}

// ── Callback ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback<U: AccountResolver, S: SessionStore>(
    State(state): State<AuthState<U, S>>,
    jar: PrivateCookieJar,
    Query(params): Query<CallbackParams>,
    headers: HeaderMap,
) -> Result<(PrivateCookieJar, Redirect), Response> {
    // Handle OAuth error response
    if let Some(error) = &params.error {
        let desc = params.error_description.as_deref().unwrap_or("Unknown error");
        tracing::warn!(error = %error, description = %desc, "OAuth2 error from PAS");
        return Err(login_error(&state.settings.error_redirect, desc));
    }

    // Extract authorization code
    let code = params
        .code
        .ok_or_else(|| login_error(&state.settings.error_redirect, "missing_code"))?;

    // Validate CSRF state
    let received_state = params
        .state
        .ok_or_else(|| login_error(&state.settings.error_redirect, "state_mismatch"))?;

    let stored_state = cookies::get_state(&jar)
        .ok_or_else(|| login_error(&state.settings.error_redirect, "state_mismatch"))?;

    if received_state != stored_state {
        tracing::warn!("OAuth state mismatch");
        return Err(login_error(&state.settings.error_redirect, "state_mismatch"));
    }

    // Retrieve PKCE verifier
    let code_verifier = cookies::get_pkce_verifier(&jar)
        .ok_or_else(|| login_error(&state.settings.error_redirect, "missing_verifier"))?;

    // Exchange code for tokens
    let token_response = state
        .client
        .exchange_code(&code, &code_verifier)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Token exchange failed");
            login_error(&state.settings.error_redirect, "token_exchange_failed")
        })?;

    // Fetch ppnum identity info
    let user_info = state
        .client
        .get_user_info(&token_response.access_token)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Userinfo request failed");
            login_error(&state.settings.error_redirect, "userinfo_failed")
        })?;

    let ppnum_id = user_info.sub;

    // Resolve consumer user for ppnum
    let user_id = state
        .account_resolver
        .resolve(&ppnum_id, &user_info)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Account resolution failed");
            login_error(&state.settings.error_redirect, "account_resolution_failed")
        })?;

    // Create session
    let session = NewSession {
        ppnum_id,
        user_id,
        refresh_token: token_response.refresh_token,
        user_agent: extract_user_agent(&headers),
        ip_address: extract_client_ip(&headers),
        user_info,
    };

    let session_id = state
        .session_store
        .create(session)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Session creation failed");
            login_error(&state.settings.error_redirect, "session_failed")
        })?;

    // Set session cookie + clear PKCE cookies
    let session_cookie = cookies::session_cookie(
        &state.settings.session_cookie_name,
        &session_id.to_string(),
        state.settings.session_ttl_days,
        state.settings.secure_cookies,
    );

    let (clear_pkce, clear_state) = cookies::clear_pkce_cookies(&state.settings.auth_path);

    let jar = jar
        .add(session_cookie)
        .add(clear_pkce)
        .add(clear_state);

    tracing::info!(session_id = %session_id, "PAS OAuth2 login successful");

    Ok((jar, Redirect::to(&state.settings.login_redirect)))
}

// ── Logout ─────────────────────────────────────────────────────────

async fn logout<U: AccountResolver, S: SessionStore>(
    State(state): State<AuthState<U, S>>,
    jar: PrivateCookieJar,
) -> (PrivateCookieJar, Redirect) {
    if let Some(cookie) = jar.get(&state.settings.session_cookie_name) {
        let session_id = crate::types::SessionId(cookie.value().to_string());
        if let Err(e) = state.session_store.delete(&session_id).await {
            tracing::warn!(error = %e, "Session deletion failed during logout");
        }
    }

    let clear_cookie = cookies::clear_session_cookie(&state.settings.session_cookie_name);
    (jar.remove(clear_cookie), Redirect::to(&state.settings.logout_redirect))
}

// ── Dev Login ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DevLoginParams {
    ppnum: Option<String>,
}

async fn dev_login<U: AccountResolver, S: SessionStore>(
    State(state): State<AuthState<U, S>>,
    jar: PrivateCookieJar,
    Query(params): Query<DevLoginParams>,
    headers: HeaderMap,
) -> Result<(PrivateCookieJar, Redirect), Response> {
    // No runtime guard needed — route is only registered when dev_login_enabled is true

    let test_ppnum = params
        .ppnum
        .filter(|p| p.parse::<crate::types::Ppnum>().is_ok())
        .unwrap_or_else(|| "77700000001".to_string());

    let test_ppnum_id: PpnumId = format!("{test_ppnum:0>26}")
        .parse()
        .expect("zero-padded digits are valid Crockford Base32");

    let test_ppnum_parsed: crate::types::Ppnum = test_ppnum
        .parse()
        .expect("test_ppnum already validated above");

    let user_info = crate::oauth::UserInfo::new(test_ppnum_id)
        .with_email(format!("{test_ppnum}@dev.local"))
        .with_ppnum(test_ppnum_parsed)
        .with_email_verified(true);

    let user_id = state
        .account_resolver
        .resolve(&test_ppnum_id, &user_info)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Dev account resolution failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Dev login failed").into_response()
        })?;

    let session = NewSession {
        ppnum_id: test_ppnum_id,
        user_id,
        refresh_token: None,
        user_agent: extract_user_agent(&headers),
        ip_address: extract_client_ip(&headers),
        user_info,
    };

    let session_id = state
        .session_store
        .create(session)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Dev session creation failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Dev login failed").into_response()
        })?;

    let session_cookie = cookies::session_cookie(
        &state.settings.session_cookie_name,
        &session_id.to_string(),
        state.settings.session_ttl_days,
        state.settings.secure_cookies,
    );

    tracing::info!(session_id = %session_id, "Dev login successful");

    Ok((jar.add(session_cookie), Redirect::to(&state.settings.login_redirect)))
}

// ── Helpers ────────────────────────────────────────────────────────

fn login_error(error_redirect: &str, code: &str) -> Response {
    let encoded = urlencoding::encode(code);
    Redirect::to(&format!("{error_redirect}?error={encoded}")).into_response()
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}
```

Key changes in `routes.rs`:
- All `state.field` → `state.settings.field` (session_cookie_name, secure_cookies, auth_path, etc.)
- `state.client` remains direct (not in settings)
- `login_error` uses `urlencoding::encode()`
- `dev_login` handler: removed `if !state.dev_login_enabled` guard (dead code — route is only registered conditionally)

**Step 4: Run check**

Run: `cargo check -p ppoppo-accounts --features axum`
Expected: Compiles without errors.

**Step 5: Commit**

```bash
git add src/middleware/config.rs src/middleware/state.rs src/middleware/routes.rs
git commit -m "refactor: extract AuthSettings + fix login_error encoding + remove dead code

- Extract AuthSettings from PasAuthConfig (eliminates 9-field duplication)
- AuthState embeds AuthSettings instead of copying fields
- login_error() now URL-encodes error parameter
- Remove redundant dev_login runtime guard (route conditionally registered)"
```

---

### Task 4: Middleware extractor — resolve_session Result + AuthPpnum

**Design refs:** A1 (resolve_session), B3 (AuthPpnum)

**Files:**
- Modify: `src/middleware/extractor.rs`
- Modify: `src/middleware/mod.rs`

**Step 1: Update `extractor.rs` — Result return + FromRequestParts**

Replace the entire file with:

```rust
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum_extra::extract::PrivateCookieJar;

use super::traits::SessionStore;
use crate::types::{PpnumId, SessionId, UserId};

/// Minimal authenticated identity from PAS.
///
/// Consumers can use this as their `SessionStore::AuthContext` if they
/// don't need richer auth context (e.g., roles, academy).
///
/// For consumers that need more context, implement `SessionStore::AuthContext`
/// with your own type and use [`resolve_session()`] in custom middleware.
///
/// Can be used as an Axum extractor when inserted into request extensions.
#[derive(Debug, Clone)]
pub struct AuthPpnum {
    /// Session ID (from cookie).
    pub session_id: SessionId,
    /// App-specific user ID (from `SessionStore::find`).
    pub user_id: UserId,
    /// PAS ppnum_id (immutable ULID, = OAuth `sub` claim).
    pub ppnum_id: PpnumId,
}

impl<S: Send + Sync> FromRequestParts<S> for AuthPpnum {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthPpnum>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

/// Resolve the authenticated user from a session cookie.
///
/// Reads the encrypted session cookie, looks up the session via
/// [`SessionStore::find()`], and returns the consumer's auth context type.
///
/// Use this in custom Axum middleware to inject auth context into request
/// extensions.
///
/// Returns `Ok(None)` if the cookie is missing.
/// Returns `Err` if the session store operation fails (e.g., DB error).
///
/// # Example
///
/// ```rust,ignore
/// async fn auth_middleware(
///     State(state): State<MyState>,
///     jar: PrivateCookieJar,
///     mut request: Request,
///     next: Next,
/// ) -> Result<Response, StatusCode> {
///     let auth = ppoppo_accounts::middleware::resolve_session(
///         &*state.session_store,
///         &jar,
///         "session_cookie_name",
///     )
///     .await
///     .map_err(|e| {
///         tracing::error!(error = %e, "Session lookup failed");
///         StatusCode::INTERNAL_SERVER_ERROR
///     })?
///     .ok_or(StatusCode::UNAUTHORIZED)?;
///
///     request.extensions_mut().insert(auth);
///     Ok(next.run(request).await)
/// }
/// ```
pub async fn resolve_session<S: SessionStore>(
    session_store: &S,
    jar: &PrivateCookieJar,
    cookie_name: &str,
) -> Result<Option<S::AuthContext>, S::Error> {
    let session_id = match jar.get(cookie_name) {
        Some(c) => SessionId(c.value().to_string()),
        None => return Ok(None),
    };
    session_store.find(&session_id).await
}
```

Key changes:
- `resolve_session` returns `Result<Option<S::AuthContext>, S::Error>` instead of `Option<S::AuthContext>`
- Removed `.ok()?` — DB errors now propagate
- `AuthPpnum` implements `FromRequestParts<S>` — extractable from request extensions
- Updated doc example to show error handling pattern

**Step 2: Update `mod.rs` re-exports (if needed)**

Check that `AuthPpnum` is already re-exported. Looking at current `mod.rs`:
```rust
pub use extractor::{AuthPpnum, resolve_session};
```

This is already correct — no change needed.

**Step 3: Run check**

Run: `cargo check -p ppoppo-accounts --features axum`
Expected: Compiles. No internal callers of `resolve_session` within the crate.

**Step 4: Commit**

```bash
git add src/middleware/extractor.rs
git commit -m "refactor: resolve_session returns Result + AuthPpnum extractor

- resolve_session: Option → Result<Option<_, _>, S::Error>
- DB errors now propagate instead of being silently swallowed
- AuthPpnum implements FromRequestParts for direct extraction"
```

---

### Task 5: RTR documentation

**Design ref:** C3 (RTR guidance)

**Files:**
- Modify: `src/middleware/types.rs`

**Step 1: Add doc comment to `refresh_token` field**

In `src/middleware/types.rs`, replace the `NewSession` struct:

```rust
use crate::oauth::UserInfo;
use crate::types::{PpnumId, UserId};

/// Session data from a successful PAS authentication.
///
/// Passed to [`SessionStore::create`](super::SessionStore::create) for the consumer to persist.
///
/// # Data ownership
///
/// `user_info` is **transient** data from PAS. It should be used for logging or
/// display at login time, but PAS-owned fields (`ppnum`, `email`) must NOT be
/// persisted in the consumer's database. Fetch via PAS userinfo API when needed.
#[derive(Debug, Clone)]
pub struct NewSession {
    /// PAS ppnum identifier (OAuth `sub` claim, ULID format).
    pub ppnum_id: PpnumId,
    /// User ID returned by [`AccountResolver::resolve`](super::AccountResolver::resolve).
    pub user_id: UserId,
    /// PAS refresh token for this OAuth session.
    ///
    /// **OAuth consumers (RCW, CTW):** PAS does NOT apply Refresh Token Rotation
    /// (RTR) for OAuth clients. Store this token as-is in the session; the same
    /// token is reused across refreshes. Lifetime: 180 days of inactivity expiry.
    ///
    /// **1st-party clients (PCS):** RTR is applied — each refresh returns a new
    /// token and invalidates the previous one (token family + replay detection).
    pub refresh_token: Option<String>,
    /// Client `User-Agent` header value.
    pub user_agent: Option<String>,
    /// Client IP address.
    pub ip_address: Option<String>,
    /// PAS UserInfo snapshot (transient — for display, NOT for DB storage).
    pub user_info: UserInfo,
}
```

**Step 2: Commit**

```bash
git add src/middleware/types.rs
git commit -m "docs: add RTR guidance to NewSession::refresh_token"
```

---

### Task 6: Consumer update — CTW middleware

**Design ref:** Consumer Updates Required

**Files:**
- Modify: `~/dev/ppo/classytime/apps/classytime-web/src/infrastructure/auth/middleware.rs`

**Step 1: Update `require_auth` to handle `Result`**

The current code:
```rust
let auth_user = ppoppo_accounts::middleware::resolve_session(
    &session_store,
    &jar,
    SESSION_COOKIE_NAME,
)
.await
.ok_or(StatusCode::UNAUTHORIZED)?;
```

Replace with:
```rust
let auth_user = ppoppo_accounts::middleware::resolve_session(
    &session_store,
    &jar,
    SESSION_COOKIE_NAME,
)
.await
.map_err(|e| {
    tracing::error!(error = %e, "Session lookup failed");
    StatusCode::INTERNAL_SERVER_ERROR
})?
.ok_or(StatusCode::UNAUTHORIZED)?;
```

This properly distinguishes:
- DB error → 500 Internal Server Error (with logging)
- No session / expired → 401 Unauthorized

**Step 2: Run check**

Run: `cargo check -p classytime-web`
Expected: Compiles without errors. (Note: may need to update ppoppo-accounts dependency version or path.)

**Step 3: Commit (in classytime repo)**

```bash
cd ~/dev/ppo/classytime
git add apps/classytime-web/src/infrastructure/auth/middleware.rs
git commit -m "fix: handle session store errors in auth middleware

resolve_session now returns Result — distinguish DB errors (500) from
missing sessions (401) instead of treating both as unauthorized."
```

---

### Task 7: Verification

**Step 1: Check all feature combinations**

```bash
cd ~/dev/ppo/ppoppo-accounts
cargo check                                    # default features (oauth, token)
cargo check --no-default-features              # no features
cargo check --features oauth                   # oauth only
cargo check --features token                   # token only
cargo check --features axum                    # axum (implies oauth)
cargo check --all-features                     # everything
```

Expected: All 6 combinations compile.

**Step 2: Run tests**

```bash
cargo test -p ppoppo-accounts
```

Expected: All existing tests pass.

**Step 3: Check consumers**

```bash
cargo check -p classytime-web
cargo check -p rollcall-web
```

Expected: Both compile. RCW doesn't use `resolve_session` directly, so should be unaffected. CTW was updated in Task 6.

**Step 4: Verify no remaining issues**

```bash
# Check for .expect() in token.rs (should be gone except dev_login test helpers)
grep -n '\.expect(' src/token.rs

# Check for .ok()? pattern (should be gone)
grep -n '\.ok()?' src/

# Check for Error::Token(String) pattern (should be gone)
grep -rn 'Error::Token(' src/ | grep -v 'TokenError'
```

Expected: No matches (or only in test/dev code).
