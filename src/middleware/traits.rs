use std::future::Future;

use super::extractor::AuthPpnum;
use super::types::NewSession;
use crate::oauth::UserInfo;
use crate::types::{PpnumId, SessionId, UserId};

/// Consumer-provided ppnum account management.
///
/// Called during OAuth callback to find or create the consumer's user
/// for the authenticated ppnum identity. The returned [`UserId`] is stored in the session.
///
/// # Example
///
/// ```rust,ignore
/// impl PpnumStore for MyAppState {
///     type Error = MyError;
///
///     async fn find_or_create(
///         &self,
///         ppnum_id: &PpnumId,
///         user_info: &ppoppo_accounts::UserInfo,
///     ) -> Result<UserId, MyError> {
///         let user = self.repo.find_by_ppnum_id(ppnum_id).await?
///             .unwrap_or(self.repo.create(ppnum_id).await?);
///         Ok(UserId(user.id.to_string()))
///     }
/// }
/// ```
pub trait PpnumStore: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find existing consumer user or create a new one by PAS ppnum_id.
    ///
    /// - `ppnum_id`: PAS ppnum identifier (OAuth `sub` claim, ULID format)
    /// - `user_info`: PAS UserInfo (transient — for display/logging, not DB storage)
    fn find_or_create(
        &self,
        ppnum_id: &PpnumId,
        user_info: &UserInfo,
    ) -> impl Future<Output = Result<UserId, Self::Error>> + Send;
}

/// Consumer-provided session persistence.
///
/// Sessions are identified by [`SessionId`] (opaque string wrapper).
/// The consumer chooses the ID format (ULID, UUID, etc.).
///
/// # Example
///
/// ```rust,ignore
/// impl SessionStore for MyAppState {
///     type Error = MyError;
///
///     async fn create(&self, session: NewSession) -> Result<SessionId, MyError> {
///         let id = Ulid::new().to_string();
///         self.db.insert_session(&id, &session).await?;
///         Ok(SessionId(id))
///     }
///
///     async fn find(&self, session_id: &SessionId) -> Result<Option<AuthPpnum>, MyError> {
///         self.db.find_session(session_id).await
///     }
///
///     async fn delete(&self, session_id: &SessionId) -> Result<(), MyError> {
///         self.db.delete_session(session_id).await
///     }
/// }
/// ```
pub trait SessionStore: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Create a new session. Returns the session ID.
    fn create(
        &self,
        session: NewSession,
    ) -> impl Future<Output = Result<SessionId, Self::Error>> + Send;

    /// Look up a session by ID. Returns `AuthPpnum` if session is valid.
    fn find(
        &self,
        session_id: &SessionId,
    ) -> impl Future<Output = Result<Option<AuthPpnum>, Self::Error>> + Send;

    /// Delete a session (logout).
    fn delete(
        &self,
        session_id: &SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
