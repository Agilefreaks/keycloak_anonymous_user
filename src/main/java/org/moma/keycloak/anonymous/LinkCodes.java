package org.moma.keycloak.anonymous;

import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.KeycloakSession;

import java.util.Map;

/**
 * Short-lived, single-use codes that carry a guest subject into the real login.
 *
 * <p>Why a code and not the guest token itself: a code is single-use and lives 5 minutes, so one
 * leaked from the login request is worthless once used or expired, where the guest token would
 * stay valid. The client trades its guest token for a code at
 * {@code POST /realms/{realm}/anonymous/link-code} — possession of the token is the proof — and
 * passes the code on the real login request.
 */
final class LinkCodes {

    static final String NOTE_GUEST_SUB = "guest_sub";

    static final int TTL_SECONDS = 300;

    private static final String KEY_PREFIX = "moma.anon.link.";
    private static final int CODE_LENGTH = 32;

    private LinkCodes() {
    }

    static String issue(KeycloakSession session, String guestSub) {
        String code = SecretGenerator.getInstance().randomString(CODE_LENGTH);
        session.singleUseObjects().put(KEY_PREFIX + code, TTL_SECONDS, Map.of(NOTE_GUEST_SUB, guestSub));
        return code;
    }

    /** Returns the code's notes and invalidates it, or null when unknown, expired or already used. */
    static Map<String, String> consume(KeycloakSession session, String code) {
        return session.singleUseObjects().remove(KEY_PREFIX + code);
    }
}
