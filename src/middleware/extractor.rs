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
