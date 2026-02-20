# Design: ppoppo-accounts Architecture Improvements

> Date: 2026-02-20
> Status: Approved
> Scope: 12 architectural improvements — error handling, type design, API ergonomics

## Problem

ppoppo-accounts (v0.5.0) has 12 architectural issues identified through codebase analysis:

1. `resolve_session()` silently swallows storage errors (`.ok()?`)
2. `VerifiedClaims` uses `.expect()` on validated fields (panic in public API)
3. `Error` types wrap `String` (loses structured data)
4. `WellKnownPasetoKey` ↔ `PublicKey` conversion is implicit
5. Stringly-typed timestamps (`String` instead of `time::OffsetDateTime`)
6. `AuthPpnum` missing `FromRequestParts` impl
7. `PasAuthConfig` → `AuthState` field duplication (9 fields copied manually)
8. `reqwest::Client` not injectable (testability, pool reuse)
9. `dev_login` runtime guard is dead code
10. `login_error()` missing URL encoding
11. No RTR guidance in docs
12. `cookie_name` string coupling in `resolve_session()`

## Decision

**Holistic refactor** — address all 12 issues in a single pass. No backward compatibility constraints; consumers (RCW, CTW) will be updated to match.

## Changes

### A. Error Handling & Safety

#### A1. `resolve_session()` — Return `Result`

```rust
// Before
pub async fn resolve_session<S: SessionStore>(...) -> Option<S::AuthContext> {
    session_store.find(&session_id).await.ok()?  // BUG: swallows DB errors
}

// After
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

Consumer impact:
- CTW `require_auth`: add `.map_err(|_| INTERNAL_SERVER_ERROR)?` before `.ok_or(UNAUTHORIZED)?`
- RCW: no direct `resolve_session` usage — unaffected

#### A2. `VerifiedClaims` — No `.expect()`

Store `iss`/`aud` as owned fields at construction:

```rust
pub struct VerifiedClaims {
    iss: String,
    aud: String,
    inner: JsonValue,
}

impl VerifiedClaims {
    pub fn iss(&self) -> &str { &self.iss }
    pub fn aud(&self) -> &str { &self.aud }
    pub fn sub(&self) -> Option<&str> { self.inner.get("sub").and_then(|v| v.as_str()) }
    pub fn get_claim(&self, key: &str) -> Option<&JsonValue> { self.inner.get(key) }
    pub fn as_json(&self) -> &JsonValue { &self.inner }
}
```

Construction in `verify_v4_public_access_token()` extracts `iss`/`aud` as `String` after `validate_claim()` succeeds.

#### A3. Structured Error Types

```rust
pub enum Error {
    OAuth { operation: &'static str, status: Option<u16>, detail: String },
    #[cfg(feature = "oauth")]
    Http(#[from] reqwest::Error),
    Token(TokenError),
    InvalidPpnum(String),
    #[cfg(feature = "oauth")]
    InvalidUrl(#[from] url::ParseError),
}

pub enum TokenError {
    InvalidFormat,
    VerificationFailed(String),
    ClaimMismatch { claim: &'static str, expected: String, actual: String },
    MissingClaim(&'static str),
    MissingPayload,
    InvalidFooter,
}
```

Both implement `Display` preserving human-readable messages.

#### A4. `login_error()` URL Encoding

```rust
fn login_error(error_redirect: &str, code: &str) -> Response {
    let encoded = urlencoding::encode(code);
    Redirect::to(&format!("{error_redirect}?error={encoded}")).into_response()
}
```

#### A5. Remove `dev_login` Dead Code

The route is only registered when `dev_login_enabled` is true (line 63-65), so the runtime guard `if !state.dev_login_enabled` inside the handler is dead code. Remove it.

### B. Type Design & Conversions

#### B1. `WellKnownPasetoKey` → `PublicKey`

```rust
#[cfg(feature = "token")]
impl TryFrom<&WellKnownPasetoKey> for PublicKey {
    type Error = Error;

    fn try_from(key: &WellKnownPasetoKey) -> Result<Self, Error> {
        parse_public_key_hex(&key.public_key_hex)
    }
}
```

Gate: `cfg(feature = "token")` because `PublicKey` is token-only.

#### B2. Typed Timestamps

Make `time` a non-optional dependency with serde support:

```toml
# Cargo.toml change
time = { version = "0.3", features = ["serde", "serde-well-known"] }
# Remove from axum feature's optional deps
```

```rust
// well_known.rs
pub struct WellKnownPasetoKey {
    pub kid: KeyId,
    pub public_key_hex: String,
    pub status: WellKnownKeyStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

// oauth.rs
pub struct UserInfo {
    pub sub: PpnumId,
    pub email: Option<String>,
    pub ppnum: Option<Ppnum>,
    pub email_verified: Option<bool>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created_at: Option<time::OffsetDateTime>,
}
```

Aligned with `STANDARDS_TIME.md` §2 (Rust: `time::OffsetDateTime`, JSON: RFC 3339).

#### B3. `AuthPpnum` — `FromRequestParts`

```rust
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AuthPpnum {
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions
            .get::<AuthPpnum>()
            .cloned()
            .ok_or(axum::http::StatusCode::UNAUTHORIZED)
    }
}
```

### C. API Design & Ergonomics

#### C1. `AuthSettings` Extraction

```rust
// config.rs — shared settings struct
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

pub struct PasAuthConfig {
    pub(super) client: AuthClient,
    pub(super) settings: AuthSettings,
}

// state.rs
pub(super) struct AuthState<U, S> {
    pub(super) client: Arc<AuthClient>,
    pub(super) account_resolver: Arc<U>,
    pub(super) session_store: Arc<S>,
    pub(super) settings: AuthSettings,
}
```

All `with_*` builder methods on `PasAuthConfig` delegate to `settings` field. External API unchanged.

#### C2. `reqwest::Client` Injection

```rust
impl AuthClient {
    pub fn new(config: OAuthConfig) -> Self {
        Self { config, http: reqwest::Client::new() }
    }

    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http = client;
        self
    }
}
```

#### C3. RTR Documentation

Add doc comment to `NewSession::refresh_token`:

```rust
/// PAS refresh token for this OAuth session.
///
/// **OAuth consumers**: PAS does NOT apply Refresh Token Rotation (RTR)
/// for OAuth clients. Store as-is; the same token is reused across refreshes.
/// Lifetime: 180 days of inactivity expiry.
///
/// **1st-party (PCS)**: RTR is applied — each refresh returns a new token.
pub refresh_token: Option<String>,
```

## Consumer Updates Required

| Consumer | File | Change |
|----------|------|--------|
| CTW | `infrastructure/auth/middleware.rs` | `resolve_session()` now returns `Result<Option<_>, _>` |
| RCW | (none) | No direct `resolve_session` usage |
| Both | `Cargo.toml` | Bump `ppoppo-accounts` version |

## Files Summary

| File | Action |
|------|--------|
| `Cargo.toml` | `time` non-optional, add `serde-well-known` feature |
| `src/error.rs` | `Error::Token(String)` → `Token(TokenError)`, `OAuth(String)` → structured |
| `src/token.rs` | `VerifiedClaims` fields, `TryFrom<&WellKnownPasetoKey>` |
| `src/well_known.rs` | `created_at: String` → `time::OffsetDateTime` |
| `src/oauth.rs` | `UserInfo.created_at` typed, `AuthClient::with_http_client()` |
| `src/middleware/config.rs` | Extract `AuthSettings`, `PasAuthConfig` embeds it |
| `src/middleware/state.rs` | `AuthState` embeds `AuthSettings` |
| `src/middleware/extractor.rs` | `resolve_session` → `Result`, `AuthPpnum` FromRequestParts |
| `src/middleware/routes.rs` | Use `settings.*`, remove dev_login guard, fix login_error |
| `src/middleware/types.rs` | `NewSession::refresh_token` doc comment |
| `src/middleware/error.rs` | No change |
| `src/middleware/cookies.rs` | No change |

## Verification

1. `cargo check` — all feature combinations (`default`, `oauth`, `token`, `axum`)
2. `cargo test` — existing tests pass
3. `cargo check -p rollcall-web` — consumer compiles after update
4. `cargo check -p classytime-web` — consumer compiles after update
