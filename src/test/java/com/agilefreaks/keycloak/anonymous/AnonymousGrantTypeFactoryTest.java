package com.agilefreaks.keycloak.anonymous;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The grant URN is what clients send as {@code grant_type}, so it is configurable per deployment
 * but never silently replaced: a value that is not an absolute URI stops the server.
 */
class AnonymousGrantTypeFactoryTest {

    // Config's default provider reads system properties as keycloak.<spi>.<provider>.<option>.
    private static final String URI_PROPERTY = "keycloak.oauth2-grant-type.anonymous.uri";

    @AfterEach
    void clearOption() {
        System.clearProperty(URI_PROPERTY);
    }

    @Test
    void withoutTheOptionTheDefaultUrnIsUsed() {
        assertThat(new AnonymousGrantTypeFactory().getId())
                .isEqualTo(AnonymousGrantTypeFactory.DEFAULT_GRANT_TYPE)
                .isEqualTo("urn:keycloak-anonymous-user:grant-type:anonymous");
    }

    @Test
    void theOptionReplacesTheUrn() {
        System.setProperty(URI_PROPERTY, "urn:example:params:oauth:grant-type:guest");

        assertThat(new AnonymousGrantTypeFactory().getId()).isEqualTo("urn:example:params:oauth:grant-type:guest");
    }

    @Test
    void anHttpsUriIsAbsoluteToo() {
        System.setProperty(URI_PROPERTY, "https://id.example.com/grants/anonymous");

        assertThat(new AnonymousGrantTypeFactory().getId()).isEqualTo("https://id.example.com/grants/anonymous");
    }

    @Test
    void theIdIsReadOnceSoItCannotDriftFromTheRegistryKey() {
        AnonymousGrantTypeFactory factory = new AnonymousGrantTypeFactory();
        String first = factory.getId();

        System.setProperty(URI_PROPERTY, "urn:example:changed");

        assertThat(factory.getId()).isEqualTo(first);
    }

    @Test
    void theIdIsKnownBeforeInit() {
        // Keycloak asks for getId() before init() and registers the factory under that answer.
        System.setProperty(URI_PROPERTY, "urn:example:early");

        AnonymousGrantTypeFactory factory = new AnonymousGrantTypeFactory();

        assertThat(factory.getId()).isEqualTo("urn:example:early");
    }

    @Test
    void theGrantItCreatesAnswersToTheConfiguredUrn() {
        System.setProperty(URI_PROPERTY, "urn:example:params:oauth:grant-type:guest");
        AnonymousGrantTypeFactory factory = new AnonymousGrantTypeFactory();
        factory.init(null);

        AnonymousGrantType grant = (AnonymousGrantType) factory.create(null);

        assertThat(grant.grantType()).isEqualTo("urn:example:params:oauth:grant-type:guest");
    }

    @Test
    void aRelativeValueStopsTheServerInsteadOfFallingBack() {
        System.setProperty(URI_PROPERTY, "anonymous");

        assertThatThrownBy(() -> new AnonymousGrantTypeFactory().getId())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("anonymous");
    }

    @Test
    void anUnparsableValueStopsTheServer() {
        System.setProperty(URI_PROPERTY, "urn:has a space");

        assertThatThrownBy(() -> new AnonymousGrantTypeFactory().getId())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aBuiltInGrantNameCannotBeShadowed() {
        System.setProperty(URI_PROPERTY, "password");

        assertThatThrownBy(() -> new AnonymousGrantTypeFactory().getId())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
