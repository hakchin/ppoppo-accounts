use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

const PKCE_COOKIE_NAME: &str = "__ppoppo_pkce";
const STATE_COOKIE_NAME: &str = "__ppoppo_state";

/// Create PKCE verifier + state cookies for the authorization request.
pub(super) fn pkce_cookies(
    code_verifier: &str,
    state: &str,
    secure: bool,
    auth_path: &str,
) -> (Cookie<'static>, Cookie<'static>) {
    let verifier = Cookie::build((PKCE_COOKIE_NAME, code_verifier.to_string()))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .path(auth_path.to_string())
        .max_age(Duration::minutes(5))
        .build();

    let state = Cookie::build((STATE_COOKIE_NAME, state.to_string()))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .path(auth_path.to_string())
        .max_age(Duration::minutes(5))
        .build();

    (verifier, state)
}

/// Create removal cookies for PKCE verifier + state.
pub(super) fn clear_pkce_cookies(auth_path: &str) -> (Cookie<'static>, Cookie<'static>) {
    let verifier = Cookie::build((PKCE_COOKIE_NAME, ""))
        .path(auth_path.to_string())
        .max_age(Duration::ZERO)
        .build();

    let state = Cookie::build((STATE_COOKIE_NAME, ""))
        .path(auth_path.to_string())
        .max_age(Duration::ZERO)
        .build();

    (verifier, state)
}

/// Create session cookie.
pub(super) fn session_cookie(
    name: &str,
    session_id: &str,
    ttl_days: i64,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build((name.to_string(), session_id.to_string()))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .path("/".to_string())
        .max_age(Duration::days(ttl_days))
        .build()
}

/// Create removal cookie for session.
pub(super) fn clear_session_cookie(name: &str) -> Cookie<'static> {
    Cookie::build((name.to_string(), ""))
        .path("/".to_string())
        .max_age(Duration::ZERO)
        .build()
}

/// Get the PKCE verifier from cookies.
pub(super) fn get_pkce_verifier(
    jar: &axum_extra::extract::PrivateCookieJar,
) -> Option<String> {
    jar.get(PKCE_COOKIE_NAME).map(|c| c.value().to_string())
}

/// Get the state from cookies.
pub(super) fn get_state(
    jar: &axum_extra::extract::PrivateCookieJar,
) -> Option<String> {
    jar.get(STATE_COOKIE_NAME).map(|c| c.value().to_string())
}
