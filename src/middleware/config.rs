use axum_extra::extract::cookie::Key;
use url::Url;

use super::error::AuthError;
use crate::oauth::{AuthClient, Config as PasConfig};

/// PAS authentication configuration.
///
/// Required field (`client`) is a constructor parameter — no runtime "missing field" errors.
///
/// Use [`from_env()`](PasAuthConfig::from_env) for convention-based setup,
/// or [`new()`](PasAuthConfig::new) with `with_*` methods for full control.
pub struct PasAuthConfig {
    /// ppoppo-accounts OAuth2 client.
    pub(super) client: AuthClient,
    /// Cookie encryption key (for PrivateCookieJar).
    pub(super) cookie_key: Key,
    /// Session cookie name.
    pub(super) session_cookie_name: String,
    /// Session cookie TTL in days.
    pub(super) session_ttl_days: i64,
    /// Use secure cookies (HTTPS only).
    pub(super) secure_cookies: bool,
    /// Auth routes base path.
    pub(super) auth_path: String,
    /// Redirect destination after successful login.
    pub(super) login_redirect: String,
    /// Redirect destination after logout.
    pub(super) logout_redirect: String,
    /// Enable `/dev-login` route.
    pub(super) dev_login_enabled: bool,
}

impl PasAuthConfig {
    /// Create config with the required `AuthClient`.
    ///
    /// All optional fields use sensible defaults. Override with `with_*` methods.
    #[must_use]
    pub fn new(client: AuthClient) -> Self {
        Self {
            client,
            cookie_key: Key::generate(),
            session_cookie_name: "__ppoppo_session".into(),
            session_ttl_days: 30,
            secure_cookies: true,
            auth_path: "/api/auth".into(),
            login_redirect: "/".into(),
            logout_redirect: "/".into(),
            dev_login_enabled: false,
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

        let mut config = PasConfig::new(client_id, redirect_uri);

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
        self.cookie_key = key;
        self
    }

    /// Set the session cookie name (default: `"__ppoppo_session"`).
    #[must_use]
    pub fn with_session_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.session_cookie_name = name.into();
        self
    }

    /// Set the session cookie TTL in days (default: 30).
    #[must_use]
    pub fn with_session_ttl_days(mut self, days: i64) -> Self {
        self.session_ttl_days = days;
        self
    }

    /// Set whether to use secure cookies (default: true).
    #[must_use]
    pub fn with_secure_cookies(mut self, secure: bool) -> Self {
        self.secure_cookies = secure;
        self
    }

    /// Set the auth routes base path (default: `"/api/auth"`).
    #[must_use]
    pub fn with_auth_path(mut self, path: impl Into<String>) -> Self {
        self.auth_path = path.into();
        self
    }

    /// Set the post-login redirect path (default: `"/"`).
    #[must_use]
    pub fn with_login_redirect(mut self, path: impl Into<String>) -> Self {
        self.login_redirect = path.into();
        self
    }

    /// Set the post-logout redirect path (default: `"/"`).
    #[must_use]
    pub fn with_logout_redirect(mut self, path: impl Into<String>) -> Self {
        self.logout_redirect = path.into();
        self
    }

    /// Enable the dev-login route (default: false).
    #[must_use]
    pub fn with_dev_login_enabled(mut self, enabled: bool) -> Self {
        self.dev_login_enabled = enabled;
        self
    }
}
