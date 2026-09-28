package com.agilefreaks.keycloak.anonymous;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.util.JsonSerialization;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Contract (docs/anonymous-sessions.md): POST /realms/{realm}/anonymous/link-code trades a guest
 * access token for a single-use code. Possession of a guest token is the proof — anything else is
 * refused, and no code is minted.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AnonymousLinkResourceTest {

    @Mock
    KeycloakSession session;
    @Mock
    SingleUseObjectProvider singleUse;
    @Mock
    AuthenticationManager.AuthResult authResult;
    @Mock
    UserModel guest;
    @Mock
    ClientModel client;

    private final EventBuilder event = mock(EventBuilder.class, RETURNS_SELF);

    /** The resource under test with the bearer check stubbed to a given outcome. */
    private AnonymousLinkResource resourceReturning(AuthenticationManager.AuthResult result) {
        return new AnonymousLinkResource(session) {
            @Override
            AuthenticationManager.AuthResult authenticateBearer() {
                return result;
            }

            @Override
            EventBuilder newEvent() {
                return event;
            }
        };
    }

    private Map<String, Object> body(Response response) throws IOException {
        return JsonSerialization.readValue((String) response.getEntity(), Map.class);
    }

    @Test
    void withoutAGuestTokenNoCodeIsIssued() throws IOException {
        Response response = resourceReturning(null).linkCode();

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(body(response)).containsEntry("error", "invalid_token");
        verify(singleUse, never()).put(anyString(), anyLong(), anyMap());
    }

    @Test
    void aTokenThatResolvesToNoUserIsRefused() throws IOException {
        when(authResult.user()).thenReturn(null);

        Response response = resourceReturning(authResult).linkCode();

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(body(response)).containsEntry("error", "invalid_token");
        verify(singleUse, never()).put(anyString(), anyLong(), anyMap());
    }

    @Test
    void aRealUsersTokenCannotMintALinkCode() throws IOException {
        when(authResult.user()).thenReturn(guest);
        when(guest.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn(null);
        when(authResult.token()).thenReturn(new AccessToken());

        Response response = resourceReturning(authResult).linkCode();

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(body(response)).containsEntry("error", "not_anonymous");
        verify(singleUse, never()).put(anyString(), anyLong(), anyMap());
    }

    @Test
    void aStoredGuestGetsASingleUseCode() throws IOException {
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(authResult.user()).thenReturn(guest);
        when(guest.getId()).thenReturn("guest-7");
        when(guest.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn("true");

        Response response = resourceReturning(authResult).linkCode();

        assertThat(response.getStatus()).isEqualTo(200);
        Map<String, Object> json = body(response);
        assertThat((String) json.get("link_code")).hasSize(32);
        assertThat(json).containsEntry("expires_in", LinkCodes.TTL_SECONDS);
        verify(singleUse).put(anyString(), anyLong(), anyMap());
    }

    @Test
    void aTokenCarryingTheAnonymousRoleQualifies() throws IOException {
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(authResult.user()).thenReturn(guest);
        when(guest.getId()).thenReturn("lightweight-9");
        // The token says guest even though the row is not marked — that is enough.
        when(guest.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn(null);
        AccessToken token = new AccessToken();
        token.setRealmAccess(new AccessToken.Access().addRole(GuestIdentity.ROLE));
        when(authResult.token()).thenReturn(token);

        Response response = resourceReturning(authResult).linkCode();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat((String) body(response).get("link_code")).isNotBlank();
    }

    @Test
    void theResponseIsJson() {
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(authResult.user()).thenReturn(guest);
        when(guest.getId()).thenReturn("guest-7");
        when(guest.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn("true");

        Response response = resourceReturning(authResult).linkCode();

        assertThat(response.getMediaType().toString()).contains("json");
    }

    @Test
    void issuingACodeIsRecordedOnTheGuest() {
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(authResult.user()).thenReturn(guest);
        when(authResult.client()).thenReturn(client);
        when(guest.getId()).thenReturn("guest-7");
        when(guest.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn("true");

        resourceReturning(authResult).linkCode();

        verify(event).event(EventType.CLIENT_INITIATED_ACCOUNT_LINKING);
        verify(event).user(guest);
        verify(event).client(client);
        verify(event).detail("anon_link", "code_issued");
        verify(event).detail("anon_guest", "guest-7");
        verify(event).success();
        verify(event, never()).error(anyString());
    }

    @Test
    void aMissingTokenIsRecordedAsARefusal() {
        resourceReturning(null).linkCode();

        verify(event).event(EventType.CLIENT_INITIATED_ACCOUNT_LINKING);
        verify(event).detail("anon_link", "refused");
        verify(event).detail(Details.REASON, "invalid_token");
        verify(event).error(Errors.INVALID_TOKEN);
        verify(event, never()).success();
    }

    @Test
    void aRealUsersAttemptIsRecordedAsARefusalOnThatUser() {
        when(authResult.user()).thenReturn(guest);
        when(guest.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn(null);
        when(authResult.token()).thenReturn(new AccessToken());

        resourceReturning(authResult).linkCode();

        verify(event).user(guest);
        verify(event).detail("anon_link", "refused");
        verify(event).detail(Details.REASON, "not_anonymous");
        verify(event).error(Errors.NOT_ALLOWED);
        verify(event, never()).detail(eq("anon_guest"), anyString());
        verify(event, never()).success();
    }
}
