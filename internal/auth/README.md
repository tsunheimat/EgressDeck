# Authentication integration

Use `NewOIDC(ctx, config, sessions)` for Authentik or another OIDC provider.
Configure the provider issuer, client ID, client secret, and one exact redirect
URL registered with the identity provider. Production redirect and discovery
endpoints require HTTPS. Callback host and path must reach the controller
unchanged; forwarded host/protocol headers are never authentication authority.

```go
sessions := auth.NewSessionManager(sessionSecret) // at least 32 random bytes
flow, err := auth.NewOIDC(ctx, auth.OIDCConfig{
    IssuerURL: "https://auth.example/application/o/egressdeck/",
    ClientID: clientID,
    ClientSecret: clientSecret,
    RedirectURL: "https://egress.example/api/v1/auth/oidc/callback",
    GroupRoles: map[string]auth.Role{
        "egress-operators": auth.RoleOperator,
        "egress-admins": auth.RoleAdmin,
    },
}, sessions)
// Handle err before accepting requests.
mux.HandleFunc("GET /api/v1/auth/oidc/login", flow.Login)
mux.HandleFunc("GET /api/v1/auth/oidc/callback", flow.Callback)
```

Configure the Authentik scope mapping to emit the `groups` claim in the ID
token; `GroupsClaim` changes the claim name and `Scopes` can request additional
configured scopes. Group names match exactly. The strongest explicitly mapped
role wins and unmapped users receive viewer access. Raw `role` claims and
browser-provided roles are not used. Only a verified email is stored.

Wrap protected routes in `NewMiddleware(sessions).Require(role)` and wrap all
mutating endpoints, including logout, in its `CSRF` middleware. The browser
sends the `egressdeck_csrf` cookie value as `X-CSRF-Token`. `HTTP.Session` returns
the public identity and `HTTP.Logout` clears both session and CSRF cookies.

Login uses authorization code, S256 PKCE, a nonce, and a browser-bound state
cookie. Pending state expires after five minutes and is held in a bounded
process-local map. State is consumed atomically before exchanging the code;
failed exchanges and concurrent/replayed callbacks cannot reuse it. Controller
restart invalidates pending login attempts and preserves encrypted sessions
when the session secret is unchanged. One active controller is required unless
sticky routing keeps each login and callback on the same instance.

The session contains only the application subject, roles, name, verified
email, CSRF token and timestamps; OAuth tokens are handled server-side and
discarded after validation. Sessions are encrypted with AES-GCM and expire
after the configured TTL. Logout clears browser cookies; identity-provider
logout, individual stolen-cookie revocation and IdP role revocation are not
automatically propagated to already issued sessions. Rotate the session key
to revoke all existing sessions or set a shorter session TTL as appropriate.

`HTTP.Login` is reserved for an explicitly selected authenticated proxy-header
mode. It never accepts unsigned identity headers. Configure a separate shared
secret of at least 32 bytes with `WithIdentityHeaderSecret`. The trusted proxy
sets `X-Auth-Request-User`, `X-Auth-Request-Role`, and
`X-Auth-Request-Signature` (unpadded base64url HMAC-SHA256 over the trimmed user,
one NUL byte, and the trimmed role). Strip incoming identity headers at the
proxy and use TLS on its upstream channel. This assertion is a reusable
credential and must not be exposed to the browser or logs. The normal session
mode must route login to OIDC, without falling back to headers.

`oidc_test.go` uses a local TLS issuer with a real RSA signing key and JWKS.
It covers discovery, exact authorize/token redirects, PKCE, role mapping,
negative claims/signatures, provider failures, browser binding, state expiry,
capacity and concurrent replay. It does not establish compatibility with a
particular deployed Authentik configuration.
