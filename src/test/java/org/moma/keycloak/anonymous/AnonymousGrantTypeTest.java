package org.moma.keycloak.anonymous;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Contract (docs/anonymous-sessions.md): the grant issues a guest session, and only when the
 * caller asked for the anonymous scope — requesting it is what makes Keycloak check that the
 * client is entitled to guest sessions. Issuing tokens for real is exercised against a running
 * realm, not here.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AnonymousGrantTypeTest {

    @Mock
    KeycloakSession session;
    @Mock
    KeycloakContext keycloakContext;
    @Mock
    RealmModel realm;
    @Mock
    ClientModel client;
    @Mock
    EventBuilder event;
    @Mock
    Cors cors;
    @Mock
    ClientConnection connection;
    @Mock
    HttpRequest httpRequest;
    @Mock
    HttpResponse httpResponse;
    @Mock
    HttpHeaders headers;
    @Mock
    TokenManager tokenManager;

    private final MultivaluedHashMap<String, String> form = new MultivaluedHashMap<>();

    @BeforeEach
    void wireContext() {
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getRealm()).thenReturn(realm);
        when(keycloakContext.getClient()).thenReturn(client);
        when(keycloakContext.getConnection()).thenReturn(connection);
        when(keycloakContext.getHttpRequest()).thenReturn(httpRequest);
        when(keycloakContext.getHttpResponse()).thenReturn(httpResponse);
        when(keycloakContext.getRequestHeaders()).thenReturn(headers);
        when(client.getProtocol()).thenReturn("openid-connect");
        when(event.detail(anyString(), anyString())).thenReturn(event);
        // CorsErrorResponseException builds its response through the Cors provider.
        when(cors.add(any(Response.ResponseBuilder.class)))
                .thenAnswer(i -> i.getArgument(0, Response.ResponseBuilder.class).build());
        form.putSingle(OAuth2Constants.GRANT_TYPE, AnonymousGrantType.GRANT_TYPE);
    }

    private OAuth2GrantType.Context context() {
        return new OAuth2GrantType.Context(session, mock(OIDCAdvancedConfigWrapper.class),
                Map.of(), form, event, cors, tokenManager);
    }

    @Test
    void withoutTheAnonymousScopeTheGrantRefuses() {
        form.putSingle(OAuth2Constants.SCOPE, "openid");

        Throwable thrown = catchThrowable(() -> new AnonymousGrantType().process(context()));

        assertThat(thrown).isInstanceOf(CorsErrorResponseException.class)
                .hasMessageContaining(OAuthErrorException.INVALID_SCOPE);
        assertThat(((CorsErrorResponseException) thrown).getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void aMissingScopeParameterIsRefusedToo() {
        Throwable thrown = catchThrowable(() -> new AnonymousGrantType().process(context()));

        assertThat(thrown).isInstanceOf(CorsErrorResponseException.class)
                .hasMessageContaining(OAuthErrorException.INVALID_SCOPE);
    }

    @Test
    void aScopeMerelyContainingTheWordIsNotEnough() {
        form.putSingle(OAuth2Constants.SCOPE, "openid anonymous-ish");

        assertThat(catchThrowable(() -> new AnonymousGrantType().process(context())))
                .isInstanceOf(CorsErrorResponseException.class);
    }

    @Test
    void aRepeatedScopeIsAcceptedNotCrashed() {
        // Set.of would throw IllegalArgumentException here and surface as an HTTP 500.
        assertThat(AnonymousGrantType.requestsAnonymousScope("openid anonymous openid")).isTrue();
        assertThat(AnonymousGrantType.requestsAnonymousScope("anonymous anonymous")).isTrue();
        assertThat(AnonymousGrantType.requestsAnonymousScope("openid  anonymous")).isTrue();
        assertThat(AnonymousGrantType.requestsAnonymousScope("openid anonymous-ish")).isFalse();
        assertThat(AnonymousGrantType.requestsAnonymousScope(null)).isFalse();
    }

    @Test
    void guestSessionsAreLoggedAsLoginsAndCarryARefreshToken() {
        AnonymousGrantType grant = new AnonymousGrantType();

        assertThat(grant.getEventType()).isEqualTo(EventType.LOGIN);
        assertThat(grant.useRefreshToken()).isTrue();
        assertThat(grant.getTokenParameterNames()).isEmpty();
    }
}
