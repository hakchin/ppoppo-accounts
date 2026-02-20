use axum_extra::extract::cookie::Key;
use url::Url;

use super::error::AuthError;
use crate::oauth::{AuthClient, OAuthConfig};

/// Shared auth settings used by both config and runtime state.
#[derive(Clone)]
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

impl AuthSettings {
    fn defaults() -> Self {
        Self {
            cookie_key: Key::generate(),
            session_cookie_name: "__ppoppo_session".into(),
            session_ttl_days: 30,
            secure_cookies: true,
            auth_path: "/api/auth".into(),
            login_redirect: "/".into(),
            logout_redirect: "/".into(),
            error_redirect: "/login".into(),
            dev_login_enabled: false,
        }
    }
}

/// PAS authentication configuration.
///
/// Required field (`client`) is a constructor parameter — no runtime "missing field" errors.
///
/// Use [`from_env()`](PasAuthConfig::from_env) for convention-based setup,
/// or [`new()`](PasAuthConfig::new) with `with_*` methods for full control.
pub struct PasAuthConfig {
    pub(super) client: AuthClient,
    pub(super) settings: AuthSettings,
}

impl PasAuthConfig {
    /// Create config with the required `AuthClient`.
    ///
    /// All optional fields use sensible defaults. Override with `with_*` methods.
    #[must_use]
    pub fn new(client: AuthClient) -> Self {
        Self {
            client,
            settings: AuthSettings::defaults(),
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

        let mut config = OAuthConfig::new(client_id, redirect_uri);

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

        let cookie_key = match std::env::var("COOKIE_KEY") {
            Ok(k) => Key::try_from(k.as_bytes()).map_err(|_| {
                AuthError::Config(
                    "COOKIE_KEY is set but invalid (must be at least 64 bytes). \
                     Remove the env var to use an ephemeral key, or provide a valid key."
                        .into(),
                )
            })?,
            Err(_) => Key::generate(),
        };

        Ok(Self::new(AuthClient::new(config))
            .with_cookie_key(cookie_key)
            .with_secure_cookies(!dev_auth)
            .with_dev_login_enabled(dev_auth))
    }

    #[must_use]
    pub fn with_cookie_key(mut self, key: Key) -> Self {
        self.settings.cookie_key = key;
        self
    }

    #[must_use]
    pub fn with_session_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.settings.session_cookie_name = name.into();
        self
    }

    #[must_use]
    pub fn with_session_ttl_days(mut self, days: i64) -> Self {
        self.settings.session_ttl_days = days;
        self
    }

    #[must_use]
    pub fn with_secure_cookies(mut self, secure: bool) -> Self {
        self.settings.secure_cookies = secure;
        self
    }

    #[must_use]
    pub fn with_auth_path(mut self, path: impl Into<String>) -> Self {
        self.settings.auth_path = path.into();
        self
    }

    #[must_use]
    pub fn with_login_redirect(mut self, path: impl Into<String>) -> Self {
        self.settings.login_redirect = path.into();
        self
    }

    #[must_use]
    pub fn with_logout_redirect(mut self, path: impl Into<String>) -> Self {
        self.settings.logout_redirect = path.into();
        self
    }

    #[must_use]
    pub fn with_error_redirect(mut self, path: impl Into<String>) -> Self {
        self.settings.error_redirect = path.into();
        self
    }

    #[must_use]
    pub fn with_dev_login_enabled(mut self, enabled: bool) -> Self {
        self.settings.dev_login_enabled = enabled;
        self
    }
}
