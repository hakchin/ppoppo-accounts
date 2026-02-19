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
#[derive(Debug, Clone)]
pub struct AuthPpnum {
    /// Session ID (from cookie).
    pub session_id: SessionId,
    /// App-specific user ID (from `SessionStore::find`).
    pub user_id: UserId,
    /// PAS ppnum_id (immutable ULID, = OAuth `sub` claim).
    pub ppnum_id: PpnumId,
}

/// Resolve the authenticated user from a session cookie.
///
/// Reads the encrypted session cookie, looks up the session via
/// [`SessionStore::find()`], and returns the consumer's auth context type.
///
/// Use this in custom Axum middleware to inject auth context into request
/// extensions. Returns `None` if the cookie is missing or the session is invalid.
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
) -> Option<S::AuthContext> {
    let session_id = jar
        .get(cookie_name)
        .map(|c| SessionId(c.value().to_string()))?;
    session_store.find(&session_id).await.ok()?
}
