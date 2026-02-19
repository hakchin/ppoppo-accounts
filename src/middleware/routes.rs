use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header::USER_AGENT};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_extra::extract::PrivateCookieJar;
use serde::Deserialize;

use super::config::PasAuthConfig;
use super::cookies;
use super::state::AuthState;
use super::traits::{AccountResolver, SessionStore};
use super::types::NewSession;
use crate::types::PpnumId;

/// Create the PAS authentication router.
///
/// Mounts the following routes under `config.auth_path` (default: `/api/auth`):
/// - `GET /login` — Redirect to PAS with PKCE
/// - `GET /callback` — Handle PAS OAuth2 callback
/// - `GET|POST /logout` — Destroy session and clear cookie
/// - `GET /dev-login` — Dev-only test login (if enabled)
///
/// # Example
///
/// ```rust,ignore
/// let config = PasAuthConfig::from_env()?;
/// let app = Router::new()
///     .merge(auth_routes(config, account_resolver, session_store));
/// ```
pub fn auth_routes<U, S>(config: PasAuthConfig, account_resolver: U, session_store: S) -> Router
where
    U: AccountResolver,
    S: SessionStore,
{
    let auth_path = config.auth_path.clone();

    let state = AuthState {
        client: Arc::new(config.client),
        account_resolver: Arc::new(account_resolver),
        session_store: Arc::new(session_store),
        cookie_key: config.cookie_key,
        session_cookie_name: config.session_cookie_name,
        session_ttl_days: config.session_ttl_days,
        secure_cookies: config.secure_cookies,
        auth_path: config.auth_path,
        login_redirect: config.login_redirect,
        logout_redirect: config.logout_redirect,
        error_redirect: config.error_redirect,
        dev_login_enabled: config.dev_login_enabled,
    };

    let mut router = Router::new()
        .route(&format!("{auth_path}/login"), get(login::<U, S>))
        .route(&format!("{auth_path}/callback"), get(callback::<U, S>))
        .route(
            &format!("{auth_path}/logout"),
            get(logout::<U, S>).post(logout::<U, S>),
        );

    if state.dev_login_enabled {
        router = router.route(&format!("{auth_path}/dev-login"), get(dev_login::<U, S>));
    }

    router.with_state(state)
}

// ── Login ──────────────────────────────────────────────────────────

async fn login<U: AccountResolver, S: SessionStore>(
    State(state): State<AuthState<U, S>>,
    jar: PrivateCookieJar,
) -> Result<(PrivateCookieJar, Redirect), Response> {
    let auth_req = state.client.authorization_url();

    let (pkce_cookie, state_cookie) = cookies::pkce_cookies(
        &auth_req.code_verifier,
        &auth_req.state,
        state.secure_cookies,
        &state.auth_path,
    );

    let jar = jar.add(pkce_cookie).add(state_cookie);

    Ok((jar, Redirect::to(&auth_req.url)))
}

// ── Callback ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback<U: AccountResolver, S: SessionStore>(
    State(state): State<AuthState<U, S>>,
    jar: PrivateCookieJar,
    Query(params): Query<CallbackParams>,
    headers: HeaderMap,
) -> Result<(PrivateCookieJar, Redirect), Response> {
    // Handle OAuth error response
    if let Some(error) = &params.error {
        let desc = params.error_description.as_deref().unwrap_or("Unknown error");
        tracing::warn!(error = %error, description = %desc, "OAuth2 error from PAS");
        return Err(login_error(&state.error_redirect, desc));
    }

    // Extract authorization code
    let code = params
        .code
        .ok_or_else(|| login_error(&state.error_redirect, "missing_code"))?;

    // Validate CSRF state
    let received_state = params
        .state
        .ok_or_else(|| login_error(&state.error_redirect, "state_mismatch"))?;

    let stored_state = cookies::get_state(&jar)
        .ok_or_else(|| login_error(&state.error_redirect, "state_mismatch"))?;

    if received_state != stored_state {
        tracing::warn!("OAuth state mismatch");
        return Err(login_error(&state.error_redirect, "state_mismatch"));
    }

    // Retrieve PKCE verifier
    let code_verifier = cookies::get_pkce_verifier(&jar)
        .ok_or_else(|| login_error(&state.error_redirect, "missing_verifier"))?;

    // Exchange code for tokens
    let token_response = state
        .client
        .exchange_code(&code, &code_verifier)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Token exchange failed");
            login_error(&state.error_redirect, "token_exchange_failed")
        })?;

    // Fetch ppnum identity info (ppnum validated by Ppnum newtype during deserialization)
    let user_info = state
        .client
        .get_user_info(&token_response.access_token)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Userinfo request failed");
            login_error(&state.error_redirect, "userinfo_failed")
        })?;

    let ppnum_id = user_info.sub;

    // Resolve consumer user for ppnum (consumer business logic)
    let user_id = state
        .account_resolver
        .resolve(&ppnum_id, &user_info)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Account resolution failed");
            login_error(&state.error_redirect, "account_resolution_failed")
        })?;

    // Create session (consumer persistence)
    let session = NewSession {
        ppnum_id,
        user_id,
        refresh_token: token_response.refresh_token,
        user_agent: extract_user_agent(&headers),
        ip_address: extract_client_ip(&headers),
        user_info,
    };

    let session_id = state
        .session_store
        .create(session)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Session creation failed");
            login_error(&state.error_redirect, "session_failed")
        })?;

    // Set session cookie + clear PKCE cookies
    let session_cookie = cookies::session_cookie(
        &state.session_cookie_name,
        &session_id.to_string(),
        state.session_ttl_days,
        state.secure_cookies,
    );

    let (clear_pkce, clear_state) = cookies::clear_pkce_cookies(&state.auth_path);

    let jar = jar
        .add(session_cookie)
        .add(clear_pkce)
        .add(clear_state);

    tracing::info!(session_id = %session_id, "PAS OAuth2 login successful");

    Ok((jar, Redirect::to(&state.login_redirect)))
}

// ── Logout ─────────────────────────────────────────────────────────

async fn logout<U: AccountResolver, S: SessionStore>(
    State(state): State<AuthState<U, S>>,
    jar: PrivateCookieJar,
) -> (PrivateCookieJar, Redirect) {
    // Delete session if exists
    if let Some(cookie) = jar.get(&state.session_cookie_name) {
        let session_id = crate::types::SessionId(cookie.value().to_string());
        if let Err(e) = state.session_store.delete(&session_id).await {
            tracing::warn!(error = %e, "Session deletion failed during logout");
        }
    }

    let clear_cookie = cookies::clear_session_cookie(&state.session_cookie_name);
    (jar.remove(clear_cookie), Redirect::to(&state.logout_redirect))
}

// ── Dev Login ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DevLoginParams {
    ppnum: Option<String>,
}

async fn dev_login<U: AccountResolver, S: SessionStore>(
    State(state): State<AuthState<U, S>>,
    jar: PrivateCookieJar,
    Query(params): Query<DevLoginParams>,
    headers: HeaderMap,
) -> Result<(PrivateCookieJar, Redirect), Response> {
    if !state.dev_login_enabled {
        return Err((StatusCode::FORBIDDEN, "Dev login not available").into_response());
    }

    let test_ppnum = params
        .ppnum
        .filter(|p| p.parse::<crate::types::Ppnum>().is_ok())
        .unwrap_or_else(|| "77700000001".to_string());

    // Generate a deterministic ULID-formatted ppnum_id for dev.
    // ULID = 26 chars of Crockford Base32 [0-9A-HJKMNP-TV-Z].
    // Digits 0-9 are valid, so zero-pad the 11-digit ppnum to 26 chars.
    let test_ppnum_id: PpnumId = format!("{test_ppnum:0>26}")
        .parse()
        .expect("zero-padded digits are valid Crockford Base32");

    let test_ppnum_parsed: crate::types::Ppnum = test_ppnum
        .parse()
        .expect("test_ppnum already validated above");

    let user_info = crate::oauth::UserInfo::new(test_ppnum_id)
        .with_email(format!("{test_ppnum}@dev.local"))
        .with_ppnum(test_ppnum_parsed)
        .with_email_verified(true);

    // Resolve dev account mapping
    let user_id = state
        .account_resolver
        .resolve(&test_ppnum_id, &user_info)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Dev account resolution failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Dev login failed").into_response()
        })?;

    let session = NewSession {
        ppnum_id: test_ppnum_id,
        user_id,
        refresh_token: None,
        user_agent: extract_user_agent(&headers),
        ip_address: extract_client_ip(&headers),
        user_info,
    };

    let session_id = state
        .session_store
        .create(session)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Dev session creation failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "Dev login failed").into_response()
        })?;

    let session_cookie = cookies::session_cookie(
        &state.session_cookie_name,
        &session_id.to_string(),
        state.session_ttl_days,
        state.secure_cookies,
    );

    tracing::info!(session_id = %session_id, "Dev login successful");

    Ok((jar.add(session_cookie), Redirect::to(&state.login_redirect)))
}

// ── Helpers ────────────────────────────────────────────────────────

fn login_error(error_redirect: &str, code: &str) -> Response {
    Redirect::to(&format!("{error_redirect}?error={code}")).into_response()
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}
