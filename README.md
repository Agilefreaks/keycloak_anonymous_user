# keycloak-anonymous-user

Guest sessions: a client that asks for the `anonymous` client scope is authenticated as a
PII-free guest identity, that guest is linked to the account it later signs into, and guests
nobody uses are deleted.

Behaviour, token contract and realm configuration are in
[`docs/anonymous-sessions.md`](../docs/anonymous-sessions.md); this file is about the code.

| Provider | id | Role |
|---|---|---|
| `AnonymousGrantType` | `urn:moma:params:oauth:grant-type:anonymous` | Issues a guest session from the token endpoint. |
| `AnonymousLinkAuthenticator` | `anonymous-link` | Consumes an `anon_link_code` and links that guest to the account. |
| `AnonymousLinkResource` | `anonymous` | `POST /realms/{realm}/anonymous/link-code`. |
| `GuestReaperScheduler` + `GuestReaperTask` | `moma-anon-reaper` | Deletes guests unused since the cutoff, on a timer. |

`GuestIdentity` (creation, markers, linking), `LinkCodes` (single-use codes) and `Env` (runtime
config) are the shared pieces. The provider ids above are what `terraform/modules/realm/main.tf`
writes into the realm, so a rename breaks `terraform apply` — `ProviderRegistrationTest` pins them.

Two things worth knowing before changing this:

- **`getShortcut()` must be exactly two characters**, whatever the SPI javadoc says about "3
  letters". Keycloak packs `[session][tokenType][grant]` into a fixed six-character prefix on
  every token id; a longer shortcut issues tokens that look fine and then throw on *every*
  subsequent validation, far from the cause. `ProviderRegistrationTest` pins the length. Taken
  in 26.7.3: `ac cc pg rt ro te ci dg pc ag`.
- **The link-code event borrows `CLIENT_INITIATED_ACCOUNT_LINKING`.** Keycloak has no custom
  event types, so `AnonymousLinkResource` needs a built-in one. This is the least misleading: a
  client asking to link an identity into an account is what it means, and its only producer is
  identity-provider account linking, which this realm (no identity providers) never runs — so
  every such event is ours. The rejected alternatives each already have a producer or meaning a
  reader would trust: `TOKEN_EXCHANGE` (standard RFC 8693 token exchange), `FEDERATED_IDENTITY_LINK`
  (an IdP link written to the user), `OAUTH2_EXTENSION_GRANT` (tokens issued by a grant),
  `CUSTOM_REQUIRED_ACTION`. Adding an identity provider means revisiting this. The type must be
  in the realm's `enabled_event_types`, or the event only reaches the log.
- `OAuth2GrantType` lives in `server-spi-private` and does move — it gained an abstract method
  between 26.5 and 26.7. Expect a recompile on each Keycloak bump, and re-run the flow against a
  live realm rather than trusting the unit tests.

## Config

Nothing per-step: the grant requires the `anonymous` scope, the link step takes no configuration,
and the reaper reads `MOMA_ANON_REAPER_*` from the environment.

## Build

```bash
docker compose run --rm build   # runs tests, produces target/keycloak-anonymous-user.jar
```

Copy the jar into `providers/` and rebuild the image.
