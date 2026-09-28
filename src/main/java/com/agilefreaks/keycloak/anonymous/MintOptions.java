package com.agilefreaks.keycloak.anonymous;

import org.keycloak.Config;

import java.net.URI;
import java.net.URISyntaxException;

/** The mint guards, from the grant's SPI options. Each limit takes 0 to disable that counter alone. */
record MintOptions(
        int maxMintsPerIpPerHour,
        int maxMintsPerRealmPerHour,
        String startTokenHeader,
        String startTokenVerifyUrl) {

    static final int DEFAULT_MAX_MINTS_PER_IP_PER_HOUR = 30;
    static final int DEFAULT_MAX_MINTS_PER_REALM_PER_HOUR = 2000;

    static MintOptions from(Config.Scope scope) {
        SpiOptions options = new SpiOptions(scope,
                "spi-" + AnonymousGrantTypeFactory.SPI + "--" + AnonymousGrantTypeFactory.SCOPE + "--");
        MintOptions parsed = new MintOptions(
                options.limit("max-mints-per-ip-per-hour", DEFAULT_MAX_MINTS_PER_IP_PER_HOUR),
                options.limit("max-mints-per-realm-per-hour", DEFAULT_MAX_MINTS_PER_REALM_PER_HOUR),
                options.text("start-token-header", ""),
                options.text("start-token-verify-url", ""));
        if (!parsed.startTokenVerifyUrl().isEmpty()) {
            if (parsed.startTokenHeader().isEmpty()) {
                throw new IllegalArgumentException(options.name("start-token-verify-url")
                        + " is set but " + options.name("start-token-header") + " is not, so it would never be called");
            }
            requireHttpUrl(options, parsed.startTokenVerifyUrl());
        }
        return parsed;
    }

    private static void requireHttpUrl(SpiOptions options, String value) {
        String invalid = options.name("start-token-verify-url") + " must be an http(s) URL, got '" + value + "'";
        try {
            URI uri = new URI(value);
            if (uri.getHost() == null || !("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))) {
                throw new IllegalArgumentException(invalid);
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(invalid, e);
        }
    }
}
