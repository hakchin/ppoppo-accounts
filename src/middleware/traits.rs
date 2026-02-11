use std::future::Future;

use super::extractor::AuthUser;
use super::types::NewSession;
use crate::oauth::UserInfo;

/// Consumer-provided user management.
///
/// Called during OAuth callback to find or create the authenticated user.
/// The returned `user_id` is stored in the session.
///
/// # Example
///
/// ```rust,ignore
/// impl UserStore for MyAppState {
///     async fn find_or_create(
///         &self,
///         ppnum_id: &str,
///         user_info: &ppoppo_accounts::UserInfo,
///     ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
///         let user = self.repo.find_by_ppnum_id(ppnum_id).await?
///             .unwrap_or(self.repo.create(ppnum_id).await?);
///         Ok(user.id.to_string())
///     }
/// }
/// ```
pub trait UserStore: Send + Sync + 'static {
    /// Find existing user or create a new one by PAS ppnum_id.
    ///
    /// - `ppnum_id`: PAS user identifier (OAuth `sub` claim, ULID format)
    /// - `user_info`: PAS UserInfo (transient — for display/logging, not DB storage)
    ///
    /// Returns the app-specific user ID as a `String`.
    fn find_or_create(
        &self,
        ppnum_id: &str,
        user_info: &UserInfo,
    ) -> impl Future<Output = Result<String, Box<dyn std::error::Error + Send + Sync>>> + Send;
}

/// Consumer-provided session persistence.
///
/// Sessions are identified by opaque `String` IDs.
/// The consumer chooses the ID format (ULID, UUID, etc.).
///
/// # Example
///
/// ```rust,ignore
/// impl SessionStore for MyAppState {
///     async fn create(&self, session: NewSession) -> Result<String, ...> {
///         let id = Ulid::new().to_string();
///         self.db.insert_session(&id, &session).await?;
///         Ok(id)
///     }
///
///     async fn find(&self, session_id: &str) -> Result<Option<AuthUser>, ...> {
///         self.db.find_session(session_id).await
///     }
///
///     async fn delete(&self, session_id: &str) -> Result<(), ...> {
///         self.db.delete_session(session_id).await
///     }
/// }
/// ```
pub trait SessionStore: Send + Sync + 'static {
    /// Create a new session. Returns the session ID.
    fn create(
        &self,
        session: NewSession,
    ) -> impl Future<Output = Result<String, Box<dyn std::error::Error + Send + Sync>>> + Send;

    /// Look up a session by ID. Returns `AuthUser` if session is valid.
    fn find(
        &self,
        session_id: &str,
    ) -> impl Future<Output = Result<Option<AuthUser>, Box<dyn std::error::Error + Send + Sync>>>
           + Send;

    /// Delete a session (logout).
    fn delete(
        &self,
        session_id: &str,
    ) -> impl Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send;
}
