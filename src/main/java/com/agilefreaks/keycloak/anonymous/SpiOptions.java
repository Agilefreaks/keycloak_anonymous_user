package com.agilefreaks.keycloak.anonymous;

import org.keycloak.Config;

/**
 * Reads a provider's SPI options. Blank means unset; a value that cannot be read stops the server,
 * naming the option, rather than quietly running on a default.
 */
final class SpiOptions {

    private final Config.Scope scope;
    private final String prefix;

    SpiOptions(Config.Scope scope, String prefix) {
        this.scope = scope;
        this.prefix = prefix;
    }

    String name(String key) {
        return prefix + key;
    }

    String text(String key, String fallback) {
        String raw = scope.get(key);
        return raw == null || raw.isBlank() ? fallback : raw.trim();
    }

    boolean flag(String key, boolean fallback) {
        String raw = text(key, null);
        if (raw == null) {
            return fallback;
        }
        if (raw.equalsIgnoreCase("true") || raw.equalsIgnoreCase("false")) {
            return Boolean.parseBoolean(raw);
        }
        throw invalid(key, "true or false", raw);
    }

    /** Null when unset. */
    Integer number(String key) {
        String raw = text(key, null);
        if (raw == null) {
            return null;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            throw invalid(key, "a whole number", raw);
        }
    }

    int number(String key, int fallback) {
        Integer value = number(key);
        return value == null ? fallback : value;
    }

    /** A counter limit: zero or more, zero meaning off. */
    int limit(String key, int fallback) {
        int value = number(key, fallback);
        if (value < 0) {
            throw invalid(key, "0 or more (0 turns it off)", String.valueOf(value));
        }
        return value;
    }

    private IllegalArgumentException invalid(String key, String expected, String raw) {
        return new IllegalArgumentException(name(key) + " must be " + expected + ", got '" + raw + "'");
    }
}
