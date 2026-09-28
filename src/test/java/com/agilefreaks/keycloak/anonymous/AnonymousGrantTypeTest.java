package com.agilefreaks.keycloak.anonymous;

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
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.cors.Cors;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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

    private static final String GRANT_TYPE = AnonymousGrantTypeFactory.DEFAULT_GRANT_TYPE;

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
    @Mock
    UserProvider users;

    private static final String IP = "203.0.113.7";
    private static final String HEADER = "X-App-Attestation";

    private final MutableClock clock = new MutableClock(1_700_000_000L);
    private final InMemoryCounterStore store = new InMemoryCounterStore(clock);
    private boolean attestationAccepted = true;

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
        when(realm.getId()).thenReturn("realm-1");
        when(connection.getRemoteAddr()).thenReturn(IP);
        when(session.users()).thenReturn(users);
        when(event.detail(anyString(), anyString())).thenReturn(event);
        // CorsErrorResponseException builds its response through the Cors provider.
        when(cors.add(any(Response.ResponseBuilder.class)))
                .thenAnswer(i -> i.getArgument(0, Response.ResponseBuilder.class).build());
        form.putSingle(OAuth2Constants.GRANT_TYPE, GRANT_TYPE);
    }

    private MintGuard guard(MintOptions options) {
        return new MintGuard(options, store, clock, (url, token) -> attestationAccepted);
    }

    /** Keycloak's own scope check needs a booted server; here the client is entitled unless told otherwise. */
    private boolean entitled = true;

    private AnonymousGrantType grant(MintOptions options) {
        return new AnonymousGrantType(GRANT_TYPE, guard(options)) {
            @Override
            String entitledScopes() {
                if (!entitled) {
                    throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_SCOPE,
                            "Invalid scopes", Response.Status.BAD_REQUEST);
                }
                return "openid anonymous";
            }
        };
    }

    private AnonymousGrantType grant() {
        return grant(new MintOptions(0, 0, "", ""));
    }

    private OAuth2GrantType.Context context() {
        return new OAuth2GrantType.Context(session, mock(OIDCAdvancedConfigWrapper.class),
                Map.of(), form, event, cors, tokenManager);
    }

    @Test
    void withoutTheAnonymousScopeTheGrantRefuses() {
        form.putSingle(OAuth2Constants.SCOPE, "openid");

        Throwable thrown = catchThrowable(() -> grant().process(context()));

        assertThat(thrown).isInstanceOf(CorsErrorResponseException.class)
                .hasMessageContaining(OAuthErrorException.INVALID_SCOPE);
        assertThat(((CorsErrorResponseException) thrown).getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void aMissingScopeParameterIsRefusedToo() {
        Throwable thrown = catchThrowable(() -> grant().process(context()));

        assertThat(thrown).isInstanceOf(CorsErrorResponseException.class)
                .hasMessageContaining(OAuthErrorException.INVALID_SCOPE);
    }

    @Test
    void aScopeMerelyContainingTheWordIsNotEnough() {
        form.putSingle(OAuth2Constants.SCOPE, "openid anonymous-ish");

        assertThat(catchThrowable(() -> grant().process(context())))
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
        AnonymousGrantType grant = grant();

        assertThat(grant.getEventType()).isEqualTo(EventType.LOGIN);
        assertThat(grant.useRefreshToken()).isTrue();
        assertThat(grant.getTokenParameterNames()).isEmpty();
    }

    @Test
    void aMissingScopeIsRecordedAsAScopeRejection() {
        form.putSingle(OAuth2Constants.SCOPE, "openid");

        catchThrowable(() -> grant().process(context()));

        verify(event).detail("anon_reject", "scope");
        verify(event).error(Errors.INVALID_REQUEST);
    }

    private Response refused(AnonymousGrantType grant) {
        form.putSingle(OAuth2Constants.SCOPE, "openid anonymous");
        Throwable thrown = catchThrowable(() -> grant.process(context()));
        assertThat(thrown).isInstanceOf(ErrorResponseException.class);
        return ((ErrorResponseException) thrown).getResponse();
    }

    private static Map<String, Object> body(Response response) throws IOException {
        return org.keycloak.util.JsonSerialization.readValue((String) response.getEntity(), Map.class);
    }

    private void assertNoGuestCreated() {
        verify(users, never()).addUser(any(), anyString(), anyString(), anyBoolean(), anyBoolean());
        verify(users, never()).addUser(any(), anyString());
    }

    @Test
    void anAddressOverItsHourlyBudgetIsTold429AndWhenToRetry() throws IOException {
        MintOptions onePerIp = new MintOptions(1, 2000, "", "");
        guard(onePerIp).check("realm-1", IP, name -> null);

        Response response = refused(grant(onePerIp));

        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(body(response))
                .containsEntry("error", "anonymous_throttled")
                .containsEntry("retry_after", 3600)
                .containsKey("error_description");
        verify(event).detail("anon_reject", "throttled_ip");
        verify(event).error(Errors.NOT_ALLOWED);
        assertNoGuestCreated();
    }

    @Test
    void theAddressComesFromTheConnectionSoEachClientIsCountedApart() {
        MintOptions onePerIp = new MintOptions(1, 2000, "", "");
        guard(onePerIp).check("realm-1", "198.51.100.4", name -> null);

        // Only the budget of another address is spent; this one reaches guest creation.
        Throwable thrown = catchThrowable(() -> {
            form.putSingle(OAuth2Constants.SCOPE, "openid anonymous");
            grant(onePerIp).process(context());
        });

        assertThat(thrown).isNotInstanceOf(ErrorResponseException.class);
        assertThat(store.get(MintRateGate.ipKey("realm-1", IP))).isPresent();
    }

    @Test
    void aSpentRealmBudgetAnswersTemporarilyUnavailable() throws IOException {
        MintOptions onePerRealm = new MintOptions(0, 1, "", "");
        guard(onePerRealm).check("realm-1", "198.51.100.4", name -> null);

        Response response = refused(grant(onePerRealm));

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(body(response)).containsEntry("error", "temporarily_unavailable");
        verify(event).detail("anon_reject", "throttled_realm");
        assertNoGuestCreated();
    }

    @Test
    void aMissingAttestationHeaderIsAnInvalidRequest() throws IOException {
        when(headers.getHeaderString(HEADER)).thenReturn(null);

        Response response = refused(grant(new MintOptions(30, 2000, HEADER, "")));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(body(response)).containsEntry("error", "invalid_request");
        verify(event).detail("anon_reject", "attestation_missing");
        assertNoGuestCreated();
    }

    @Test
    void aRejectedAttestationIsAccessDenied() throws IOException {
        when(headers.getHeaderString(HEADER)).thenReturn("forged");
        attestationAccepted = false;

        Response response = refused(grant(new MintOptions(30, 2000, HEADER, "https://verify.example.com")));

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(body(response)).containsEntry("error", "access_denied");
        verify(event).detail("anon_reject", "attestation");
        assertNoGuestCreated();
    }

    @Test
    void aClientNotEntitledToTheScopeSpendsNoBudget() {
        entitled = false;
        form.putSingle(OAuth2Constants.SCOPE, "openid anonymous");

        Throwable thrown = catchThrowable(() -> grant(new MintOptions(1, 1, "", "")).process(context()));

        assertThat(thrown).isInstanceOf(CorsErrorResponseException.class);
        assertThat(store.size()).isZero();
        assertNoGuestCreated();
    }

    @Test
    void refusalsAreJson() {
        MintOptions onePerIp = new MintOptions(1, 2000, "", "");
        guard(onePerIp).check("realm-1", IP, name -> null);

        assertThat(refused(grant(onePerIp)).getMediaType().toString()).contains("json");
    }
}
