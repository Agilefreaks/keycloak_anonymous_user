package org.moma.keycloak.anonymous;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;

import java.time.Instant;
import java.util.Map;

/**
 * Links the guest session the client came from to the account it just signed into.
 *
 * <p>The email account stays the account: the guest subject is appended to its {@code anon_subs}
 * attribute, which the API reconciles against to move the guest's data across. That works whether
 * or not the email already had an account.
 *
 * <p>Runs after the step that proves the email — a link code must never move data onto an account
 * before its owner is established — and before CRM enrichment.
 *
 * <p>A missing, expired or replayed code is never fatal: signing in matters more than linking.
 */
public class AnonymousLinkAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(AnonymousLinkAuthenticator.class);

    public static final String LINK_CODE_PARAM = "anon_link_code";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel realUser = context.getUser();
        String code = linkCode(context);

        if (code == null || code.isBlank() || realUser == null) {
            context.success();
            return;
        }

        Map<String, String> notes = LinkCodes.consume(context.getSession(), code);
        String guestSub = notes == null ? null : notes.get(LinkCodes.NOTE_GUEST_SUB);
        if (guestSub == null) {
            LOG.debug("anonymous link code unknown, expired or already used — continuing without linking");
            context.getEvent().detail("moma_anon_link", "invalid");
            context.success();
            return;
        }
        if (guestSub.equals(realUser.getId())) {
            context.getEvent().detail("moma_anon_link", "self");
            context.success();
            return;
        }

        GuestIdentity.recordLink(realUser, guestSub);

        EventBuilder event = context.getEvent().detail("moma_anon_link", "linked").detail("moma_anon_guest", guestSub);
        UserModel guest = context.getSession().users().getUserById(context.getRealm(), guestSub);
        if (GuestIdentity.isGuest(guest)) {
            recordGuestAge(event, guest);
            context.getSession().users().removeUser(context.getRealm(), guest);
        }

        context.success();
    }

    /**
     * The guest's own LOGIN events are filed under its id, which no longer resolves to a user once
     * the row is gone; this is what lets the account's history alone date the guest.
     */
    private static void recordGuestAge(EventBuilder event, UserModel guest) {
        int created = GuestIdentity.createdAt(guest);
        if (created <= 0) {
            return;
        }
        event.detail("moma_anon_guest_created_at", Instant.ofEpochSecond(created).toString())
                .detail("moma_anon_guest_age_days", String.valueOf((Time.currentTime() - created) / 86_400));
    }

    /** The direct grant has no authorize request: the app posts the code with its credentials. */
    private static String linkCode(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        return form == null ? null : form.getFirst(LINK_CODE_PARAM);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No form, so no action callback.
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
