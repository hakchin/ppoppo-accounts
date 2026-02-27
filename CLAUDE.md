# CLAUDE.md

> **Parent instructions**: This project inherits workspace-level context from [`~/dev/ppo/CLAUDE.md`](../CLAUDE.md).
> Shared definitions (ecosystem abbreviations, workspace layout, shared crates, port allocation, architecture terms) are in the parent — consult it for cross-project context.

## Project Overview

ppoppo-accounts is a **public crates.io package** providing OAuth2 PKCE client, PASETO v4.public token verification, and Axum auth middleware for PAS (Ppoppo Accounts System).

- **crates.io**: `ppoppo-accounts`
- **Version**: 0.6.0
- **License**: MIT OR Apache-2.0
- **Rust edition**: 2024 (MSRV 1.85)
- **Repository**: https://github.com/hakchin/ppoppo-accounts
- **Consumers**: RCW, CTW, PCS

## Feature Flags

| Feature | Default | Purpose | Key deps |
|---------|---------|---------|----------|
| `oauth` | yes | OAuth2 PKCE client (`AuthClient`, `OAuthConfig`, PKCE utils) | reqwest, sha2, rand, url |
| `token` | yes | PASETO v4.public verification (`verify_v4_public_access_token`) | pasetors, hex |
| `axum` | no | Plug-and-play Axum middleware (implies `oauth`) | axum 0.8, axum-extra 0.12 |

Typical consumer usage: `ppoppo-accounts = { version = "0.6", features = ["axum"] }`

## Public API Surface

### Core Types (`types`)

- `PpnumId(Ulid)` — PAS identity (OAuth `sub`), SSOT link for consumers
- `Ppnum(String)` — Validated 11-digit 777-prefixed number (parse via `FromStr`)
- `UserId(String)`, `SessionId(String)`, `KeyId(String)` — Opaque newtype wrappers

### OAuth (`oauth` feature)

- `OAuthConfig` — Builder for PAS endpoint URLs (defaults to `accounts.ppoppo.com`)
- `AuthClient` — HTTP client: `authorize_url()`, `exchange_code()`, `refresh_token()`, `userinfo()`
- `TokenResponse`, `UserInfo` — Response types

### Token Verification (`token` feature)

- `verify_v4_public_access_token()` — Verify PASETO v4.public + validate iss/aud
- `extract_kid_from_token()` — Extract `kid` from footer (key rotation)
- `PublicKey`, `VerifiedClaims` — Types

### Axum Middleware (`axum` feature)

Consumer implements two traits, then mounts pre-built routes:

```
AccountResolver  → resolve(ppnum_id, user_info) → UserId
SessionStore     → create(NewSession) → SessionId
                   find(session_id) → Option<AuthContext>
                   delete(session_id) → ()
```

- `PasAuthConfig` — `from_env()` or builder (`new()` + `with_*`)
- `auth_routes()` — Mounts `{auth_path}/login`, `/callback`, `/logout`, `/dev-login`
- `AuthPpnum` — Default `AuthContext` extractor (`session_id`, `user_id`, `ppnum_id`)
- `resolve_session()` — Helper for custom Axum middleware

### Environment Variables (Axum feature)

| Var | Required | Description |
|-----|----------|-------------|
| `PAS_CLIENT_ID` | yes | OAuth2 client ID |
| `PAS_REDIRECT_URI` | yes | Callback URL (must be valid URL) |
| `COOKIE_KEY` | no | Cookie encryption key (>= 64 bytes; ephemeral if unset) |
| `DEV_AUTH` | no | `"1"` or `"true"` enables dev-login, disables secure cookies |
| `PAS_AUTH_URL` | no | Override authorize endpoint |
| `PAS_TOKEN_URL` | no | Override token endpoint |
| `PAS_USERINFO_URL` | no | Override userinfo endpoint |

## Quick Start

```bash
cargo test                    # Run all tests
cargo test --features axum    # Test with Axum middleware
cargo doc --all-features      # Generate docs
```

## Publishing

```bash
cargo publish --dry-run       # Verify before publish
cargo publish                 # Publish to crates.io
```

## Never Do

- Add PAS-internal dependencies (sqlx, tonic, etc.) — this is a public SDK
- Expose PAS database types or internal error variants
- Use `chrono` (use `time` for consistency with consumers)
- Break the `AccountResolver`/`SessionStore` trait signatures without a major version bump

## Reference Docs

- `.0context/LIST_FUNCTIONS_PPOPPO_ACCOUNTS.md` — Full function inventory
- `docs/plans/` — Architecture improvement plans
