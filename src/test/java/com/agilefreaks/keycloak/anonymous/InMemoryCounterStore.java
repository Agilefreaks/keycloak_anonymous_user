package com.agilefreaks.keycloak.anonymous;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Test double for the single-use store, expiring entries against a clock the test moves by hand. */
class InMemoryCounterStore implements CounterStore {

    private record Entry(Map<String, String> notes, long expiresAtEpochSeconds) {
    }

    private final Map<String, Entry> entries = new HashMap<>();
    private final MutableClock clock;

    InMemoryCounterStore(MutableClock clock) {
        this.clock = clock;
    }

    int size() {
        return entries.size();
    }

    @Override
    public Optional<Map<String, String>> get(String key) {
        Entry entry = entries.get(key);
        if (entry == null || entry.expiresAtEpochSeconds() <= clock.epochSeconds()) {
            entries.remove(key);
            return Optional.empty();
        }
        return Optional.of(new LinkedHashMap<>(entry.notes()));
    }

    @Override
    public void put(String key, Map<String, String> notes, long ttlSeconds) {
        entries.put(key, new Entry(new LinkedHashMap<>(notes), clock.epochSeconds() + ttlSeconds));
    }
}
