package com.agilefreaks.keycloak.anonymous;

import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The names the realm config and the app depend on. A rename here breaks `terraform apply`
 * ("authenticator not found") or the client's token call, neither of which the compiler sees.
 */
class ProviderRegistrationTest {

    private static List<String> serviceFile(String spi) throws IOException {
        try (InputStream in = ProviderRegistrationTest.class.getClassLoader()
                .getResourceAsStream("META-INF/services/" + spi)) {
            assertThat(in).as(spi + " must be registered").isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).lines()
                    .map(String::trim).filter(l -> !l.isEmpty()).collect(Collectors.toList());
        }
    }

    @Test
    void theGrantTypeKeepsItsUrn() {
        assertThat(new AnonymousGrantTypeFactory().getId())
                .isEqualTo("urn:moma:params:oauth:grant-type:anonymous");
    }

    @Test
    void theGrantShortcutIsExactlyTwoCharacters() {
        // Keycloak packs [session][tokenType][grant] into a fixed 6-character token-id prefix.
        // Anything else and every later validation of the token throws — at the far end of the
        // system from the grant that issued it.
        assertThat(new AnonymousGrantTypeFactory().getShortcut()).hasSize(2);
    }

    @Test
    void theLinkStepKeepsTheIdTerraformReferences() {
        assertThat(new AnonymousLinkAuthenticatorFactory().getId()).isEqualTo("anonymous-link");
    }

    @Test
    void theLinkEndpointIsMountedUnderRealmsAnonymous() {
        assertThat(new AnonymousLinkResourceProviderFactory().getId()).isEqualTo("anonymous");
    }

    @Test
    void everyProviderIsDiscoverableThroughItsServiceFile() throws IOException {
        assertThat(serviceFile("org.keycloak.authentication.AuthenticatorFactory"))
                .containsExactly(AnonymousLinkAuthenticatorFactory.class.getName());
        assertThat(serviceFile("org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory"))
                .containsExactly(AnonymousGrantTypeFactory.class.getName());
        assertThat(serviceFile("org.keycloak.services.resource.RealmResourceProviderFactory"))
                .containsExactly(AnonymousLinkResourceProviderFactory.class.getName());
        assertThat(serviceFile("org.keycloak.events.EventListenerProviderFactory"))
                .containsExactly(GuestReaperScheduler.class.getName());
    }

    @Test
    void eachFactoryCreatesItsProviderAndNeedsNoLifecycle() {
        AnonymousGrantTypeFactory grant = new AnonymousGrantTypeFactory();
        grant.init(null);
        grant.postInit(null);
        assertThat(grant.create(null)).isInstanceOf(AnonymousGrantType.class);
        grant.close();

        AnonymousLinkAuthenticatorFactory link = new AnonymousLinkAuthenticatorFactory();
        link.init(null);
        link.postInit(null);
        assertThat(link.create(null)).isInstanceOf(AnonymousLinkAuthenticator.class);
        assertThat(link.getDisplayType()).isNotBlank();
        assertThat(link.getReferenceCategory()).isEqualTo("anonymous");
        assertThat(link.getHelpText()).contains("anon_link_code");
        assertThat(link.isUserSetupAllowed()).isFalse();
        link.close();

        AnonymousLinkResourceProviderFactory resource = new AnonymousLinkResourceProviderFactory();
        resource.init(null);
        resource.postInit(null);
        assertThat(resource.create(null)).isInstanceOf(AnonymousLinkResource.class);
        resource.close();
    }

    @Test
    void theLinkStepHasNothingToConfigureAndCannotBeHalfEnabled() {
        AnonymousLinkAuthenticatorFactory factory = new AnonymousLinkAuthenticatorFactory();
        assertThat(factory.isConfigurable()).isFalse();
        assertThat(factory.getConfigProperties()).isEmpty();
        assertThat(factory.getRequirementChoices())
                .containsExactly(AuthenticationExecutionModel.Requirement.REQUIRED,
                        AuthenticationExecutionModel.Requirement.DISABLED);
    }
}
