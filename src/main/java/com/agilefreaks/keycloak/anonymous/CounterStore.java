package com.agilefreaks.keycloak.anonymous;

import java.util.Map;
import java.util.Optional;

/** Narrowed to an interface so tests can run against an in-memory fake instead of Infinispan. */
interface CounterStore {

    Optional<Map<String, String>> get(String key);

    void put(String key, Map<String, String> notes, long ttlSeconds);
}
