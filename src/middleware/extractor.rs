use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::Key;

use super::error::AuthError;
use super::state::AuthState;
use super::traits::{SessionStore, UserStore};
use crate::types::{PpnumId, SessionId, UserId};

/// Authenticated user extracted from session cookie.
///
/// Use as an Axum extractor in route handlers. Returns `401 Unauthorized`
/// if no valid session exists.
///
/// # Example
///
/// ```rust,ignore
/// async fn protected(user: AuthUser) -> impl IntoResponse {
///     format!("Hello, user {} (ppnum_id: {})", user.user_id, user.ppnum_id)
/// }
///
/// // Optional: accessible to both authenticated and anonymous users
/// async fn public(user: Option<AuthUser>) -> impl IntoResponse {
///     match user {
///         Some(u) => format!("Hello, {}", u.user_id),
///         None => "Hello, guest".to_string(),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// Session ID (from cookie).
    pub session_id: SessionId,
    /// App-specific user ID (from `SessionStore::find`).
    pub user_id: UserId,
    /// PAS ppnum_id (immutable ULID, = OAuth `sub` claim).
    pub ppnum_id: PpnumId,
}

impl<U: UserStore, S: SessionStore> FromRequestParts<AuthState<U, S>> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState<U, S>,
    ) -> Result<Self, Self::Rejection> {
        let jar: PrivateCookieJar<Key> =
            PrivateCookieJar::from_request_parts(parts, state)
                .await
                .map_err(|_| AuthError::Unauthenticated)?;

        let session_id = jar
            .get(&state.session_cookie_name)
            .map(|c| SessionId(c.value().to_string()))
            .ok_or(AuthError::Unauthenticated)?;

        state
            .session_store
            .find(&session_id)
            .await
            .map_err(|e| AuthError::Store(e.to_string()))?
            .ok_or(AuthError::SessionExpired)
    }
}
