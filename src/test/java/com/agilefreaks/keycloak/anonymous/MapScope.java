package com.agilefreaks.keycloak.anonymous;

import org.keycloak.Config;

import java.util.Map;
import java.util.Set;

/** A provider's SPI options as Keycloak hands them to {@code init()}, from a plain map. */
final class MapScope extends Config.AbstractScope {

    private final Map<String, String> values;

    MapScope(Map<String, String> values) {
        this.values = values;
    }

    static MapScope of(String... keysAndValues) {
        java.util.HashMap<String, String> values = new java.util.HashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            values.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return new MapScope(values);
    }

    @Override
    public String get(String key) {
        return values.get(key);
    }

    @Override
    public Config.Scope scope(String... scope) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Set<String> getPropertyNames() {
        return values.keySet();
    }

    @Override
    public Config.Scope root() {
        throw new UnsupportedOperationException();
    }
}
