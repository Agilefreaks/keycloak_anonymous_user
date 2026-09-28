package com.agilefreaks.keycloak.anonymous;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;

public class AnonymousGrantTypeFactory implements OAuth2GrantTypeFactory {

    public static final String DEFAULT_GRANT_TYPE = "urn:keycloak-anonymous-user:grant-type:anonymous";

    /**
     * The options live under {@code spi-oauth2-grant-type--anonymous--*}, not under this factory's
     * id: Keycloak scopes a factory's config by {@code getId()}, and that is the URN itself.
     */
    static final String SPI = "oauth2-grant-type";
    static final String SCOPE = "anonymous";
    static final String OPTION_URI = "uri";

    private final AttestationVerifier verifier = new HttpAttestationVerifier();

    private String grantType;
    private MintOptions mintOptions;

    static Config.Scope options() {
        return Config.scope(SPI, SCOPE);
    }

    /**
     * Keycloak calls this before {@link #init} and registers the factory under the answer, so the
     * option is read here, once — a second read could disagree with the registry key.
     */
    @Override
    public String getId() {
        if (grantType == null) {
            grantType = absoluteUri(options().get(OPTION_URI, DEFAULT_GRANT_TYPE));
        }
        return grantType;
    }

    /** RFC 6749 §4.5: an extension grant type is an absolute URI, which also keeps it clear of the built-in names. */
    static String absoluteUri(String value) {
        String candidate = value.trim();
        try {
            if (new URI(candidate).isAbsolute()) {
                return candidate;
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(invalid(candidate), e);
        }
        throw new IllegalArgumentException(invalid(candidate));
    }

    private static String invalid(String value) {
        return "spi-" + SPI + "--" + SCOPE + "--" + OPTION_URI + " must be an absolute URI (RFC 6749 §4.5), got '"
                + value + "'";
    }

    /**
     * Two characters, not the "3-letters" the SPI javadoc suggests: Keycloak packs
     * [session][tokenType][grant] into a fixed 6-character prefix on every token id, and anything
     * longer makes the encoder throw when the token is later validated — which is every bearer
     * call, not the issuing call, so it fails far away from the cause. Taken in 26.7.3: ac cc pg rt ro te ci dg pc ag.
     */
    @Override
    public String getShortcut() {
        return "an";
    }

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new AnonymousGrantType(getId(),
                new MintGuard(mintOptions, new SingleUseObjectCounterStore(session), Clock.systemUTC(), verifier));
    }

    /** {@code config} is scoped by {@link #getId()}, the URN; the options live under {@code anonymous}. */
    @Override
    public void init(Config.Scope config) {
        mintOptions = MintOptions.from(options());
    }

    MintOptions mintOptions() {
        return mintOptions;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
