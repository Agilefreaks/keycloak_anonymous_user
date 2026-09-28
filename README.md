# keycloak-anonymous-user

Make anonymous sessions possible — and traceable — until the user signs up.

An app gets a real token **before anyone has an account**, so every request to its
API carries a verifiable JWT and "public or private" is a claim check rather than
"token or no token". The guest is a PII-free user row; when the person later signs
in, a single-use code carries the guest into that account, and guests nobody uses
are deleted on a timer. The model is Firebase Anonymous Auth or Cognito
unauthenticated identities, inside Keycloak.

Built and tested against **Keycloak 26.7** (`keycloak.version` in `pom.xml`).

## What it provides

| Provider | Provider id | What it does |
|---|---|---|
| `AnonymousGrantType` | `urn:keycloak-anonymous-user:grant-type:anonymous` (configurable) | A token-endpoint grant. With the `anonymous` scope requested, creates a guest and returns its tokens. Guarded per IP, per realm and optionally by app attestation. |
| `AnonymousLinkResource` | `anonymous` | `POST /realms/{realm}/anonymous/link-code`: trades a guest access token for a single-use, 5-minute link code. |
| `AnonymousLinkAuthenticator` | `anonymous-link` | A direct grant step. Consumes an `anon_link_code` from the login request, records the guest on the account and deletes the guest row. No-op without a code. |
| `GuestReaperScheduler` + `GuestReaperTask` | `anonymous-reaper` | Deletes guests nobody has used since a cutoff, on Keycloak's timer. |

The link step identifies nobody and proves nothing: put it **after** the step that
proves the account — a password, or a passwordless code such as
[`keycloak_otp_email`](https://github.com/Agilefreaks/keycloak_otp_email), which pairs
with [`keycloak_email_lookup_or_create`](https://github.com/Agilefreaks/keycloak_email_lookup_or_create)
for an email login-or-signup that native apps drive over the direct grant.

## The token contract

| | guest | signed in |
|---|---|---|
| `sub` | the guest's id, stable for the life of the install | the account's id |
| `realm_access.roles` | includes `anonymous` | never `anonymous` |
| `scope` | includes `anonymous` | whatever the login asked for |
| `email` | absent | present |
| `email_verified` | `false` | as the account has it |
| `anon_subs` | — | every guest subject this account absorbed, newest last, capped at 20 (with a mapper, see below) |

- **The guest marker is the `anonymous` realm role on the user row**, not anything on
  the `anonymous` client scope. A refresh that sends a narrower `scope` drops every
  optional scope it does not name, and a guest token without its marker would read as
  signed in. Realm roles ride on the default `roles` scope, which no `scope` parameter
  removes.
- A guest has no email, no credentials, no default roles and no required actions.
  Because it gets no default roles it gets no `offline_access` either: its refresh
  token belongs to an online session.
- **Authorize on a positive signal of an account** — `email_verified == true`, an
  `email` claim, and no `anonymous` role — never on the absence of the guest role
  alone.
- **Merging is the resource server's job.** For each subject in `anon_subs` whose data
  still sits under the guest, move it to `sub`. The claim is the account's full list
  and arrives on every request, so the merge must be idempotent.
- Anyone with a public client id can mint a guest, and a guest token leaks as easily
  as any public-client token: it must never authorize more than public data.

## The three calls

```bash
KC=https://id.example.com/realms/example
TOKEN=$KC/protocol/openid-connect/token

# 1. Mint a guest — once per install; refresh from then on.
curl -s -X POST "$TOKEN" \
  -d grant_type=urn:keycloak-anonymous-user:grant-type:anonymous \
  -d client_id=my-app -d 'scope=openid anonymous'
# HTTP 200 — access_token / refresh_token / id_token, sub=<guest>, roles include "anonymous"

# 2. When the person starts signing in: trade the guest token for a link code.
curl -s -X POST "$KC/anonymous/link-code" -H "Authorization: Bearer $GUEST_ACCESS_TOKEN"
# HTTP 200 — {"link_code":"1KATGq3pTgsU1Rt1oTb1OBxLIPw0CRiZ","expires_in":300}

# 3. Sign in through the realm's direct grant flow, with the code alongside the credentials.
curl -s -X POST "$TOKEN" -d grant_type=password -d client_id=my-app -d scope=openid \
  -d username=visitor@example.com -d password=… -d anon_link_code=1KATGq3pTgsU1Rt1oTb1OBxLIPw0CRiZ
# HTTP 200 — sub=<account>, anon_subs=[…, <guest>]; the guest row is gone
```

Step 3 is shown against Keycloak's built-in direct grant; with `keycloak_otp_email`
the same call sends `otp=` instead of `password=`, and `anon_link_code` rides on the
call that carries the code.

Why a code and not the guest token: the code is single-use and lives 5 minutes, so one
leaked from a login request is worthless once used or expired, where the guest token
would still be valid. Possession of the guest token is the proof of ownership. A
missing, expired or replayed code never blocks the login — it links nothing and says
so in the event.

A guest of its own grant type rather than a variant of the password grant: the real
login is untouched by guest sessions, and `grant_type` alone says in the logs which of
the two happened. The `link-code` endpoint sends no CORS headers — it is for native
clients.

## Configuration

Everything is a Keycloak SPI option, so it can be a CLI flag, a `keycloak.conf` line or
an environment variable (`--spi-oauth2-grant-type--anonymous--uri=…`,
`spi-oauth2-grant-type--anonymous--uri=…`, `KC_SPI_OAUTH2_GRANT_TYPE__ANONYMOUS__URI=…`).
Options are read at runtime, so they survive `kc.sh build` / `start --optimized`. A
value that cannot be read — not a number, not `true`/`false`, not a URI — stops the
server and names the option; nothing falls back to a default silently. Blank means unset.

### The grant

| Option | Environment | Default | Effect |
|---|---|---|---|
| `uri` | `KC_SPI_OAUTH2_GRANT_TYPE__ANONYMOUS__URI` | `urn:keycloak-anonymous-user:grant-type:anonymous` | The `grant_type` clients send. Must be an absolute URI (RFC 6749 §4.5). |

The options sit under `anonymous`, not under the provider id: Keycloak scopes a
factory's options by its id, and this factory's id is the URN.

### Mint guards

The mint is unauthenticated and writes a user row, so it has limits of its own —
Keycloak's brute-force protection is keyed on a user and never sees these requests.
Each counter takes `0` to turn it off alone.

| Option | Environment | Default | Stops |
|---|---|---|---|
| `max-mints-per-ip-per-hour` | `KC_SPI_OAUTH2_GRANT_TYPE__ANONYMOUS__MAX_MINTS_PER_IP_PER_HOUR` | `30` | A single scripted source. Over budget: `429 {"error":"anonymous_throttled","error_description":…,"retry_after":<seconds>}`. Keep it generous: carriers and offices share addresses. |
| `max-mints-per-realm-per-hour` | `KC_SPI_OAUTH2_GRANT_TYPE__ANONYMOUS__MAX_MINTS_PER_REALM_PER_HOUR` | `2000` | A distributed flood, where every per-IP counter still looks innocent. Over budget: `503 temporarily_unavailable`. This is what bounds the growth of the user table. |
| `start-token-header` | `KC_SPI_OAUTH2_GRANT_TYPE__ANONYMOUS__START_TOKEN_HEADER` | *(empty — off)* | Clients that cannot prove they are your app. When set, a mint needs this header — point it at an App Attest / Play Integrity / reCAPTCHA Enterprise token. Missing: `400 invalid_request`. |
| `start-token-verify-url` | `KC_SPI_OAUTH2_GRANT_TYPE__ANONYMOUS__START_TOKEN_VERIFY_URL` | *(empty — presence is enough)* | Forged attestation tokens. The header's value is POSTed here as `token`; a JSON body with `"success": false`, or a non-200 answer, is `403 access_denied`. Needs `start-token-header`. |

- **Order:** the `anonymous` scope, then Keycloak's check that the client may have it,
  then attestation, then the counters. Neither an unentitled client nor a failed
  attestation spends budget, and every refusal returns before a user row exists.
- **Counters** are fixed one-hour windows in Keycloak's single-use object store (the
  cache action tokens use), keyed by realm and by client IP. They expire on their own;
  a restart resets them.
- **The client IP** is `ClientConnection.getRemoteAddr()`. Behind a reverse proxy or
  load balancer, configure Keycloak's `proxy-headers` (`forwarded` or `xforwarded`), or
  every client shares the proxy's address and its budget.
- **An unreachable verifier does not block the mint** — nor one whose answer is not
  JSON. That is logged at `warn`, the counters still apply, and an outage of the
  verifier does not take guest sessions down with it. The same holds for the OTP
  provider's send step.
- These limits complement an edge rate limit on the token path, they do not replace
  it: an edge limit cannot see `grant_type` in the form body, so it cannot budget
  guests apart from logins.

### The reaper

| Option | Environment | Default | Effect |
|---|---|---|---|
| `enabled` | `KC_SPI_EVENTS_LISTENER__ANONYMOUS_REAPER__ENABLED` | `true` | Deletes guests nobody uses. `false` schedules nothing at all. |
| `max-idle-days` | `KC_SPI_EVENTS_LISTENER__ANONYMOUS_REAPER__MAX_IDLE_DAYS` | `30` | How long a guest that has refreshed may then go without refreshing. |
| `unused-max-idle-days` | `KC_SPI_EVENTS_LISTENER__ANONYMOUS_REAPER__UNUSED_MAX_IDLE_DAYS` | `7` | How long a guest that **never** refreshed survives from creation. |
| `interval-hours` | `KC_SPI_EVENTS_LISTENER__ANONYMOUS_REAPER__INTERVAL_HOURS` | `6` | How often the sweep runs; the first runs one interval after boot. |
| `interval-minutes` | `KC_SPI_EVENTS_LISTENER__ANONYMOUS_REAPER__INTERVAL_MINUTES` | — | Overrides the hours, to watch a sweep without waiting. |
| `batch` | `KC_SPI_EVENTS_LISTENER__ANONYMOUS_REAPER__BATCH` | `500` | Most deletions per sweep per realm. |

- **Idle is measured from the last token refresh, not from the row's age.** With long
  sessions, waiting for a guest's session to disappear means keeping an abandoned
  guest as long as the session lasts; a flat age cap deletes the identity of someone
  still using the app. A guest that comes back after its cutoff finds its refresh
  failing and mints a new one, exactly as after a reinstall.
- **Never refreshed** means no session of the guest was refreshed more than a minute
  after it started, or no session is left — refreshing needs one. Every install mints
  a guest and most are never used again, so those go after `unused-max-idle-days`
  rather than waiting out the full idle window.
- The reaper is an event-listener factory only because `postInit` is the hook an
  extension gets at boot. It needs no enabling on any realm, and sweeps every realm.

## Realm prerequisites

The grant exists as soon as the jar is installed; this is what a realm needs for it
to be usable. Nothing here is created by the provider.

1. **The `anonymous` realm role.** Guests are granted it; the grant refuses to mint in a
   realm without it rather than create a guest without its marker.
2. **The `anonymous` client scope** (OpenID Connect, no mappers needed). Assign it as an
   **optional** scope to each client that may mint guests — requesting it is what makes
   Keycloak check the client is entitled, so that assignment is the on/off switch per
   client. The grant refuses a request that does not ask for it.
3. **The role must reach the token.** With *Full scope allowed* on (the admin-console
   default) it does; with it off, add the `anonymous` role to the client's scope
   mappings.
4. **Disable the `VERIFY_PROFILE` required action.** A guest has no email and the
   default user profile requires one, so the action would fail every guest token
   request. Make `firstName`/`lastName` optional instead if you need profile checks for
   real users.
5. **Add `anonymous-link` to the direct grant flow, after the credential step** (as
   `REQUIRED`; it succeeds without doing anything when no code is sent). It requires a
   user, so placed before the step that identifies one the flow fails. A newly added
   execution lands first in the flow; lower its priority below the credential step.
6. **Enable the event types** you want stored: `LOGIN`, `LOGIN_ERROR`,
   `CLIENT_INITIATED_ACCOUNT_LINKING` and `CLIENT_INITIATED_ACCOUNT_LINKING_ERROR`
   (the link-code endpoint's). A type not in `enabledEventTypes` only reaches the log.
7. **For the `anon_subs` claim**, add a *User Attribute* mapper — attribute and claim
   `anon_subs`, *Multivalued* on, access token — to a **default** client scope of the
   clients whose resource server merges. Default, because an optional scope drops off
   on a narrowed refresh.
8. *Optional:* set the user profile's *Unmanaged attributes* to *Admin can view*
   (`unmanagedAttributePolicy = ADMIN_VIEW`). The providers read and write `anon`,
   `anon_created_at` and `anon_subs` either way, but otherwise the admin console and
   API hide them.

## Events

| Detail | Event | Filed under | Meaning |
|---|---|---|---|
| `anon=true` | `LOGIN` | guest | A guest was minted; `grant_type` is the configured URN. |
| `anon_reject=scope` | `LOGIN_ERROR` (`invalid_request`) | — | The mint did not ask for the `anonymous` scope. |
| `anon_reject=throttled_ip` / `throttled_realm` | `LOGIN_ERROR` (`not_allowed`) | — | A mint counter was spent; `retry_after` in seconds. |
| `anon_reject=attestation_missing` / `attestation` | `LOGIN_ERROR` (`not_allowed`) | — | The attestation header was absent, or the verifier rejected it. |
| `anon_link=code_issued` | `CLIENT_INITIATED_ACCOUNT_LINKING` | guest | `POST link-code` issued a code; `anon_guest` repeats the guest id. |
| `anon_link=refused` | `CLIENT_INITIATED_ACCOUNT_LINKING_ERROR` | the token's user, or none | `reason=invalid_token` (401: no valid bearer) or `not_anonymous` (403: a signed-in user's token). |
| `anon_link=linked` | `LOGIN` | account | The guest was absorbed: `anon_guest`, `anon_guest_created_at` (ISO-8601 UTC) and `anon_guest_age_days` (how long it browsed before signing up). |
| `anon_link=invalid` | `LOGIN` | account | The code was unknown, expired or replayed; the login went ahead, nothing linked. |
| `anon_link=self` | `LOGIN` | account | The code named the account itself; nothing linked. |

One id follows a person from install to account: the guest `sub` is the `userId` of
the minting `LOGIN` and of the `code_issued` event, then `anon_guest` on the account's
linking `LOGIN`, then an entry in the account's `anon_subs`. The guest row is deleted
at link time, so everything filed under the guest is reachable only by that id — in
the admin console, *Events → User events → User ID*, not the *Users* page. The linking
`LOGIN` is read off the guest row just before it is deleted, which is why the
account's own history can date the guest.

Guest deletion — by linking or by the reaper — writes no user event; the reaper logs a
count per sweep (`removed N idle guest user(s) in realm …`).

**The link code borrows `CLIENT_INITIATED_ACCOUNT_LINKING`.** Keycloak has no custom
event types, so the endpoint needs a built-in one, and this is the least misleading: a
client asking to link an identity into an account is what it means, and its only
producer is identity-provider account linking — so in a realm without identity
providers every such event is this provider's. The rejected alternatives each already
have a producer or meaning a reader would trust: `TOKEN_EXCHANGE` (RFC 8693 token
exchange), `FEDERATED_IDENTITY_LINK` (an IdP link written to the user),
`OAUTH2_EXTENSION_GRANT` (tokens issued by a grant), `CUSTOM_REQUIRED_ACTION`. A realm
that also brokers identity providers should filter on `anon_link`.

## Operational notes

- **`getShortcut()` must be exactly two characters**, whatever the SPI javadoc says
  about "3 letters". Keycloak packs `[session][tokenType][grant]` into a fixed
  six-character prefix on every token id; a longer shortcut issues tokens that look
  fine and then throw on *every* later validation, far from the cause. This grant uses
  `an`; taken in 26.7.3: `ac cc pg rt ro te ci dg pc ag`. `ProviderRegistrationTest`
  pins the length.
- **Changing the URN after clients ship is breaking.** The old value answers
  `400 unsupported_grant_type` from the next restart. Pick it before the first release
  of an app, and keep it.
- **One instance.** The reaper is scheduled unguarded on each node's timer; a clustered
  deployment would want `ClusterProvider.executeIfNotExecuted` around the task body. The
  mint counters live in the single-use object store, so they are per node unless that
  store is clustered.
- **Keep events past the event table.** The table expires (`eventsExpiration`), and
  guest histories are long. Keycloak's `jboss-logging` listener writes every event to
  the server log — successes only at `debug` by default, so set
  `KC_SPI_EVENTS_LISTENER__JBOSS_LOGGING__SUCCESS_LEVEL=info` and route the log to a
  sink with the retention you need. Search it by the guest id.
- **Guest and real sessions share token lifetimes.** If guests should expire sooner,
  give them a client of their own with shorter client-session windows.
- **App storage:** keep the guest refresh token device-local (on iOS a
  non-synchronizable Keychain item, or every device on the Apple ID shares one guest),
  and treat a failed refresh — reaped, or the session expired — as the only reason to
  mint again.
- Not provided: guest sessions for a browser client (this is a token-endpoint
  mechanism; a web client would need an authenticator in the browser flow) and DPoP
  binding of guest tokens.
- `OAuth2GrantType` lives in `server-spi-private` and does move — it gained an abstract
  method between 26.5 and 26.7. Expect a recompile on each Keycloak bump, and re-run the
  three calls against a live realm rather than trusting the unit tests.

## Build

No local JDK/Maven required — build in Docker:

```bash
docker compose run --rm build
# -> target/keycloak-anonymous-user.jar  (unit tests and an 80% coverage gate run first)
```

Or with Maven directly: `mvn clean verify`.

## Install

Copy `target/keycloak-anonymous-user.jar` into Keycloak's `/opt/keycloak/providers/`
(before `kc.sh build` for an optimized image, or the providers dir + restart), then
make the realm changes above — via the admin console or your infrastructure-as-code.
Keycloak logs a `KC-SERVICES0047` warning per provider at build: all four SPIs
are internal, which is also why a Keycloak upgrade means a rebuild.

## Test

JUnit 5 + Mockito, 125 tests, with the 80% line gate enforced at `verify`. The rate
counters run against an in-memory store and a hand-advanced clock, so window rollover
is deterministic; the attestation verifier runs against a real local HTTP server
(accepted, rejected, non-200, unreachable, unreadable, unusable URL); every refusal
asserts its status, body, `anon_reject` detail and that no user was created. SPI
options are exercised through Keycloak's own `Config`, whose default provider reads
system properties (`keycloak.oauth2-grant-type.anonymous.uri`). Issuing real tokens is
not unit-tested — drive the three calls against a running realm for that.
`resteasy-core` is a test-scope dependency only, because `Response.status()` wants a
JAX-RS `RuntimeDelegate` outside a server.

## Compatibility

The grant and link-code SPIs are internal to Keycloak and can change in any release.
Bump `keycloak.version` in `pom.xml`, rebuild and re-verify when upgrading Keycloak.

## License

Apache 2.0 — see [LICENSE](LICENSE).
