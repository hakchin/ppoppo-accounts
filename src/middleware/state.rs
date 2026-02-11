use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;

use super::extractor::SessionStoreDyn;
use crate::oauth::AuthClient;
use crate::oauth::UserInfo;

/// Shared state for auth route handlers.
#[derive(Clone)]
pub(super) struct AuthState {
    pub(super) client: Arc<AuthClient>,
    pub(super) user_store: Arc<dyn UserStoreDyn>,
    pub(super) session_store: Arc<dyn SessionStoreDyn>,
    pub(super) cookie_key: Key,
    pub(super) session_cookie_name: String,
    pub(super) session_ttl_days: i64,
    pub(super) secure_cookies: bool,
    pub(super) auth_path: String,
    pub(super) login_redirect: String,
    pub(super) logout_redirect: String,
    pub(super) dev_login_enabled: bool,
}

// PrivateCookieJar requires Key to be extractable from state
impl FromRef<AuthState> for Key {
    fn from_ref(state: &AuthState) -> Self {
        state.cookie_key.clone()
    }
}

/// Object-safe wrapper for UserStore.
pub(super) trait UserStoreDyn: Send + Sync {
    fn find_or_create_dyn<'a>(
        &'a self,
        ppnum_id: &'a str,
        user_info: &'a UserInfo,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<String, Box<dyn std::error::Error + Send + Sync>>,
                > + Send
                + 'a,
        >,
    >;
}

impl<T: super::traits::UserStore> UserStoreDyn for T {
    fn find_or_create_dyn<'a>(
        &'a self,
        ppnum_id: &'a str,
        user_info: &'a UserInfo,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<String, Box<dyn std::error::Error + Send + Sync>>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(self.find_or_create(ppnum_id, user_info))
    }
}
