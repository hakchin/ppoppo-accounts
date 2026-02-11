use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::PrivateCookieJar;
use axum_extra::extract::cookie::Key;

use super::error::AuthError;
use super::state::AuthState;

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
    pub session_id: String,
    /// App-specific user ID (from `SessionStore::find`).
    pub user_id: String,
    /// PAS ppnum_id (immutable ULID, = OAuth `sub` claim).
    pub ppnum_id: String,
}

impl FromRequestParts<AuthState> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> Result<Self, Self::Rejection> {
        let jar: PrivateCookieJar<Key> =
            PrivateCookieJar::from_request_parts(parts, state)
                .await
                .map_err(|_| AuthError::Unauthenticated)?;

        let session_id = jar
            .get(&state.session_cookie_name)
            .map(|c| c.value().to_string())
            .ok_or(AuthError::Unauthenticated)?;

        state
            .session_store
            .find_dyn(&session_id)
            .await
            .map_err(|e| AuthError::Store(e.to_string()))?
            .ok_or(AuthError::SessionExpired)
    }
}

/// Object-safe wrapper for SessionStore (needed for Arc<dyn>).
pub(super) trait SessionStoreDyn: Send + Sync {
    fn find_dyn<'a>(
        &'a self,
        session_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        Option<AuthUser>,
                        Box<dyn std::error::Error + Send + Sync>,
                    >,
                > + Send
                + 'a,
        >,
    >;

    fn create_dyn(
        &self,
        session: super::types::NewSession,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<String, Box<dyn std::error::Error + Send + Sync>>,
                > + Send
                + '_,
        >,
    >;

    fn delete_dyn<'a>(
        &'a self,
        session_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), Box<dyn std::error::Error + Send + Sync>>,
                > + Send
                + 'a,
        >,
    >;
}

impl<T: super::traits::SessionStore> SessionStoreDyn for T {
    fn find_dyn<'a>(
        &'a self,
        session_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        Option<AuthUser>,
                        Box<dyn std::error::Error + Send + Sync>,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(self.find(session_id))
    }

    fn create_dyn(
        &self,
        session: super::types::NewSession,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<String, Box<dyn std::error::Error + Send + Sync>>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(self.create(session))
    }

    fn delete_dyn<'a>(
        &'a self,
        session_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), Box<dyn std::error::Error + Send + Sync>>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(self.delete(session_id))
    }
}
