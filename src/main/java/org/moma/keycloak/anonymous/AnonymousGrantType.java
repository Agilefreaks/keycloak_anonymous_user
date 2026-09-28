package org.moma.keycloak.anonymous;

import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

/**
 * Issues a guest session under a grant type of its own, so nothing about it is entangled with the
 * realm's password grant:
 *
 * <pre>
 * POST /realms/{realm}/protocol/openid-connect/token
 *   grant_type=urn:moma:params:oauth:grant-type:anonymous&amp;client_id=…&amp;scope=openid anonymous
 * </pre>
 *
 * <p>The {@code anonymous} client scope is required: being assigned it is what entitles a client to
 * guest sessions at all, and Keycloak refuses the request for a client that lacks it. The guest
 * marker itself is the realm role on the row, not the scope — see {@link GuestIdentity}.
 */
public class AnonymousGrantType extends OAuth2GrantTypeBase {

    public static final String GRANT_TYPE = "urn:moma:params:oauth:grant-type:anonymous";
    static final String ANONYMOUS_SCOPE = GuestIdentity.ROLE;

    @Override
    public Response process(Context context) {
        setContext(context);

        // Two different questions: did the caller ask for the scope, and is the client allowed it.
        // The first is ours to enforce — Keycloak checks the client's entitlement only for scopes
        // that are requested, so without it any client could mint a guest.
        if (!requestsAnonymousScope(formParams.getFirst(OAuth2Constants.SCOPE))) {
            event.detail(Details.REASON, "anonymous scope not requested");
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_SCOPE,
                    "This grant requires the 'anonymous' scope", Response.Status.BAD_REQUEST);
        }
        String scope = getRequestedScopes();

        RootAuthenticationSessionModel rootAuthSession =
                new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);

        UserModel guest = GuestIdentity.create(session, realm);

        authSession.setAuthenticatedUser(guest);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER,
                Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        UserSessionModel userSession = new UserSessionManager(session).createUserSession(
                authSession.getParentSession().getId(), realm, guest, guest.getUsername(),
                clientConnection.getRemoteHost(), GRANT_TYPE, false, null, null,
                UserSessionModel.SessionPersistenceState.PERSISTENT);

        event.user(guest).session(userSession).detail("moma_anon", "true");

        AuthenticationManager.setClientScopesInSession(session, authSession);
        ClientSessionContext clientSessionCtx =
                TokenManager.attachAuthenticationSession(session, userSession, authSession);
        clientSessionCtx.setAttribute(Constants.GRANT_TYPE, context.getGrantType());

        updateUserSessionFromClientAuth(userSession);

        return createTokenResponse(guest, userSession, clientSessionCtx, scope, true, null);
    }

    /** Not {@code Set.of}: it throws on a repeated scope, turning a sloppy client into a 500. */
    static boolean requestsAnonymousScope(String rawScopeParam) {
        return rawScopeParam != null && Arrays.asList(rawScopeParam.split(" ")).contains(ANONYMOUS_SCOPE);
    }

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    /** No credential-bearing parameters, same as the client-credentials and password grants. */
    @Override
    public Set<String> getTokenParameterNames() {
        return Collections.emptySet();
    }

    @Override
    protected boolean useRefreshToken() {
        return true;
    }
}
