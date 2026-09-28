package com.agilefreaks.keycloak.anonymous;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;

public class AnonymousGrantTypeFactory implements OAuth2GrantTypeFactory {

    @Override
    public String getId() {
        return AnonymousGrantType.GRANT_TYPE;
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
        return new AnonymousGrantType();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
