package org.moma.keycloak.anonymous;

import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Creation and recognition of guest identities.
 *
 * <p>A guest is an ordinary user row carrying no email, no credentials and no default roles —
 * only the markers below and the {@code anonymous} realm role. The role has to live on the row:
 * anything carried by a client scope can be dropped by refreshing with a narrower {@code scope},
 * and a guest token without its role reads as a signed-in user. Realm roles ride on the default
 * {@code roles} scope, which no scope parameter can remove while the client keeps "Full scope
 * allowed" on (the admin-console default).
 */
public final class GuestIdentity {

    /** The realm role every guest carries; the API's "this is a guest" signal. */
    public static final String ROLE = "anonymous";
    /** Marks a user as a guest. */
    public static final String ATTR_ANON = "anon";
    /** Unix seconds the guest was created; the reaper's fallback when a guest never had a session. */
    public static final String ATTR_CREATED_AT = "anon_created_at";
    /** On a real user: guest subjects linked into it (multivalued). */
    public static final String ATTR_LINKED_SUBS = "anon_subs";

    private static final String USERNAME_PREFIX = "anon-";

    /** Max {@link #ATTR_LINKED_SUBS} values kept per real user; oldest are dropped. */
    private static final int MAX_LINKED_SUBS = 20;

    private GuestIdentity() {
    }

    /**
     * A user row with no email, no credentials, no default roles or required actions — just the
     * guest role and markers. Refuses to mint a guest at all if the realm lacks the role: a guest
     * without its marker is precisely the escalation this exists to prevent.
     */
    public static UserModel create(KeycloakSession session, RealmModel realm) {
        RoleModel role = realm.getRole(ROLE);
        if (role == null) {
            throw new IllegalStateException("realm '" + realm.getName() + "' has no '" + ROLE + "' role");
        }
        String id = KeycloakModelUtils.generateId();
        UserModel user = session.users().addUser(realm, id, USERNAME_PREFIX + id, false, false);
        user.setEnabled(true);
        user.grantRole(role);
        user.setSingleAttribute(ATTR_ANON, "true");
        user.setSingleAttribute(ATTR_CREATED_AT, String.valueOf(Time.currentTime()));
        return user;
    }

    public static boolean isGuest(UserModel user) {
        return user != null && Boolean.parseBoolean(user.getFirstAttribute(ATTR_ANON));
    }

    /** Unix seconds the guest was created, falling back to the row's own timestamp. */
    public static int createdAt(UserModel user) {
        String marked = user.getFirstAttribute(ATTR_CREATED_AT);
        if (marked != null) {
            try {
                return Integer.parseInt(marked);
            } catch (NumberFormatException ignored) {
                // Fall through to the row's own timestamp.
            }
        }
        Long created = user.getCreatedTimestamp();
        return created == null ? 0 : (int) (created / 1000L);
    }

    /** Records {@code guestSub} on a real user, newest last, capped. Idempotent. */
    public static void recordLink(UserModel realUser, String guestSub) {
        List<String> subs = new ArrayList<>(realUser.getAttributeStream(ATTR_LINKED_SUBS).toList());
        if (subs.contains(guestSub)) {
            return;
        }
        subs.add(guestSub);
        if (subs.size() > MAX_LINKED_SUBS) {
            subs = subs.subList(subs.size() - MAX_LINKED_SUBS, subs.size());
        }
        realUser.setAttribute(ATTR_LINKED_SUBS, subs);
    }
}
