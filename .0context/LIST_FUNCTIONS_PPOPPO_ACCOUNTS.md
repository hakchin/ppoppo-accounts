
## OAuth2 Client (AuthClient)

### Goal

HTTP client for PAS OAuth2 endpoints. Generate authorization URLs with PKCE, exchange authorization codes for tokens, refresh tokens, and fetch userinfo.

## OAuth2 Configuration (OAuthConfig)

### Goal

Builder-pattern configuration for PAS OAuth2 endpoints (authorize, token, userinfo). Defaults to production URLs (`accounts.ppoppo.com`), overridable for dev/staging.

## PKCE S256 Utilities

### Goal

Generate cryptographically random code verifier (64 chars), compute S256 code challenge, and generate OAuth2 state parameter. RFC 7636 compliant.

## PASETO v4.public Token Verification (feature: token)

### Goal

Verify PASETO v4.public access tokens using Ed25519 public keys. Validate iss/aud claims, extract sub and custom claims. Independent from `pas-token` crate.

## Public Key Parsing

### Goal

Parse hex-encoded Ed25519 public keys (32 bytes) into `PublicKey` type. Convert from `WellKnownPasetoKey` for automatic key ingestion.

## Key ID Extraction

### Goal

Extract `kid` from PASETO token footer without verifying signature. Used for key rotation — select the correct public key before verification.

## Well-Known PASETO Document Types

### Goal

Serde types for `/.well-known/paseto.json` document: `WellKnownPasetoDocument`, `WellKnownPasetoKey`, `WellKnownKeyStatus` (active/retiring/revoked). For Resource Servers to fetch and cache public keys.

## Domain Types (Newtypes)

### Goal

Type-safe newtypes preventing ID mixing: `PpnumId` (ULID), `Ppnum` (validated 11-digit 777-prefixed), `UserId` (consumer-defined), `SessionId` (consumer-defined), `KeyId` (PASERK).

## Axum Auth Middleware (feature: axum)

### Goal

Plug-and-play Axum middleware providing OAuth2 PKCE login/callback/logout/dev-login routes. Consumers implement `AccountResolver` and `SessionStore` traits.

## Auth Routes (login, callback, logout, dev-login)

### Goal

Pre-built Axum route handlers: `/login` redirects to PAS with PKCE, `/callback` exchanges code + creates session + sets cookie, `/logout` clears session, `/dev-login` bypasses OAuth for development.

## AccountResolver Trait

### Goal

Consumer-implemented trait for resolving PAS identity (ppnum_id) to a local user account (find-or-create pattern). Called during OAuth callback.

## SessionStore Trait

### Goal

Consumer-implemented trait for session CRUD (create, find, delete). Generic `AuthContext` associated type lets consumers return their own auth type from `find()`.

## AuthPpnum Extractor

### Goal

Axum extractor providing minimal authenticated identity (session_id, user_id, ppnum_id) from request extensions. Default `AuthContext` for consumers without custom auth types.

## resolve_session() Helper

### Goal

Utility function to read encrypted session cookie via `PrivateCookieJar`, look up session via `SessionStore::find()`, and return consumer's `AuthContext`. Used in custom Axum middleware.

## PasAuthConfig (from_env + Builder)

### Goal

Configuration for Axum middleware. `from_env()` reads `PAS_CLIENT_ID`, `PAS_REDIRECT_URI`, `COOKIE_KEY`, `DEV_AUTH`. Builder methods for cookie name, TTL, auth path, redirects, secure cookies.

## Cookie Management (PKCE + Session)

### Goal

Internal cookie helpers: set/get/clear PKCE cookies (`__ppoppo_pkce`, `__ppoppo_state`, 5-min TTL), session cookie (configurable name, encrypted via `PrivateCookieJar`).
