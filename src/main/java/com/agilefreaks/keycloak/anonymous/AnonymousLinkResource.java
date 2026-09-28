package com.agilefreaks.keycloak.anonymous;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Map;

/**
 * {@code /realms/{realm}/anonymous} — the guest side of the upgrade handshake.
 *
 * <p>{@code POST link-code} with the guest access token as a bearer returns a single-use code the
 * client then passes as {@code anon_link_code} on the real (email) login request, where
 * {@link AnonymousLinkAuthenticator} consumes it. Intended for native clients; no CORS headers are
 * added, so a browser origin cannot call it.
 */
public class AnonymousLinkResource implements RealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(AnonymousLinkResource.class);

    /**
     * There is no custom event type; this one has no other producer in a realm without identity
     * providers, so it cannot be confused with anything. The provider README has the reasoning.
     */
    static final EventType EVENT_TYPE = EventType.CLIENT_INITIATED_ACCOUNT_LINKING;

    private final KeycloakSession session;

    AnonymousLinkResource(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @POST
    @Path("link-code")
    @Produces(MediaType.APPLICATION_JSON)
    public Response linkCode() {
        EventBuilder event = newEvent().event(EVENT_TYPE);
        AuthenticationManager.AuthResult auth = authenticateBearer();
        if (auth == null || auth.user() == null) {
            refused(event, Errors.INVALID_TOKEN, "invalid_token");
            return error(Response.Status.UNAUTHORIZED, "invalid_token", "a valid guest access token is required");
        }
        event.user(auth.user()).client(auth.client());
        if (!isGuest(auth)) {
            refused(event, Errors.NOT_ALLOWED, "not_anonymous");
            return error(Response.Status.FORBIDDEN, "not_anonymous", "the token does not belong to a guest session");
        }

        UserModel guest = auth.user();
        String code = LinkCodes.issue(session, guest.getId());
        LOG.debugf("issued anonymous link code for guest %s", guest.getId());
        event.detail("moma_anon_link", "code_issued").detail("moma_anon_guest", guest.getId()).success();

        return json(Response.Status.OK, Map.of(
                "link_code", code,
                "expires_in", LinkCodes.TTL_SECONDS));
    }

    /** Seam for the specs. */
    AuthenticationManager.AuthResult authenticateBearer() {
        return new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
    }

    /** Seam for the specs. */
    EventBuilder newEvent() {
        return new EventBuilder(session.getContext().getRealm(), session, session.getContext().getConnection());
    }

    private static void refused(EventBuilder event, String error, String reason) {
        event.detail("moma_anon_link", "refused").detail(Details.REASON, reason).error(error);
    }

    /**
     * A guest by the row's marker or by the token's own role. The marker is the source of truth;
     * the role still recognises a guest whose attributes an admin has edited away.
     *
     * <p>AuthResult is a record: use its canonical accessors, not the getX shims Keycloak deprecated
     * for removal in 26.5.
     */
    private static boolean isGuest(AuthenticationManager.AuthResult auth) {
        if (GuestIdentity.isGuest(auth.user())) {
            return true;
        }
        AccessToken token = auth.token();
        return token != null && token.getRealmAccess() != null && token.getRealmAccess().isUserInRole(GuestIdentity.ROLE);
    }

    private static Response error(Response.Status status, String error, String description) {
        return json(status, Map.of("error", error, "error_description", description));
    }

    private static Response json(Response.Status status, Map<String, Object> body) {
        try {
            return Response.status(status)
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .entity(JsonSerialization.writeValueAsString(body))
                    .build();
        } catch (IOException e) {
            throw new IllegalStateException("failed to serialize response", e);
        }
    }

    @Override
    public void close() {
    }
}
