use std::future::Future;

use super::types::NewSession;
use crate::oauth::UserInfo;
use crate::types::{PpnumId, SessionId, UserId};

/// Consumer-provided account resolution.
///
/// Called during OAuth callback to resolve the PAS identity to a local user account.
/// The returned [`UserId`] is stored in the session.
///
/// # Example
///
/// ```rust,ignore
/// impl AccountResolver for MyAdapter {
///     type Error = MyError;
///
///     async fn resolve(
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
pub trait AccountResolver: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolve a PAS identity to a consumer user account (find or create).
    ///
    /// - `ppnum_id`: PAS ppnum identifier (OAuth `sub` claim, ULID format)
    /// - `user_info`: PAS UserInfo (transient — for display/logging, not DB storage)
    fn resolve(
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
/// The `AuthContext` associated type lets consumers return their own auth type
/// from `find()`, eliminating the need for parallel auth middleware.
///
/// # Example
///
/// ```rust,ignore
/// impl SessionStore for MyAdapter {
///     type Error = MyError;
///     type AuthContext = MyAuthUser; // your handler's auth type
///
///     async fn create(&self, session: NewSession) -> Result<SessionId, MyError> {
///         let id = Ulid::new().to_string();
///         self.db.insert_session(&id, &session).await?;
///         Ok(SessionId(id))
///     }
///
///     async fn find(&self, session_id: &SessionId) -> Result<Option<MyAuthUser>, MyError> {
///         // Return your full auth context directly
///         self.db.find_session_with_context(session_id).await
///     }
///
///     async fn delete(&self, session_id: &SessionId) -> Result<(), MyError> {
///         self.db.delete_session(session_id).await
///     }
/// }
/// ```
pub trait SessionStore: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    type AuthContext: Clone + Send + Sync + 'static;

    /// Create a new session. Returns the session ID.
    fn create(
        &self,
        session: NewSession,
    ) -> impl Future<Output = Result<SessionId, Self::Error>> + Send;

    /// Look up a session by ID. Returns the consumer's auth context if valid.
    fn find(
        &self,
        session_id: &SessionId,
    ) -> impl Future<Output = Result<Option<Self::AuthContext>, Self::Error>> + Send;

    /// Delete a session (logout).
    fn delete(
        &self,
        session_id: &SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
