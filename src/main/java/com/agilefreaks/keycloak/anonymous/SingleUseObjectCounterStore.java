package com.agilefreaks.keycloak.anonymous;

import org.keycloak.models.KeycloakSession;

import java.util.Map;
import java.util.Optional;

/** {@link CounterStore} backed by Keycloak's single-use object store. Entries expire on their own. */
final class SingleUseObjectCounterStore implements CounterStore {

    private final KeycloakSession session;

    SingleUseObjectCounterStore(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Optional<Map<String, String>> get(String key) {
        return Optional.ofNullable(session.singleUseObjects().get(key));
    }

    /**
     * No remove first: Infinispan defers {@code put()} to the transaction commit but applies
     * {@code remove()} at once, so removing would make the counter read as empty to concurrent
     * requests for the rest of this one. Never put the same key twice in a request — the
     * transaction rejects a second task for a key it already holds.
     */
    @Override
    public void put(String key, Map<String, String> notes, long ttlSeconds) {
        session.singleUseObjects().put(key, ttlSeconds, notes);
    }
}
