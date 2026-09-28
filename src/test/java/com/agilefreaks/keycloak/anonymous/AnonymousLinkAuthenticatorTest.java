package com.agilefreaks.keycloak.anonymous;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Contract (README): after a guest signs in for real, the email account stays
 * the account, the guest subject is recorded in its `anon_subs`, and the guest row goes away. The
 * code rides on the token request; a missing, expired or replayed one never blocks the login.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AnonymousLinkAuthenticatorTest {

    private static final String CODE = "abc123";
    @Mock
    AuthenticationFlowContext context;
    @Mock
    KeycloakSession session;
    @Mock
    RealmModel realm;
    @Mock
    UserProvider users;
    @Mock
    SingleUseObjectProvider singleUse;
    @Mock
    EventBuilder event;
    @Mock
    HttpRequest httpRequest;
    @Mock
    UserModel realUser;
    @Mock
    UserModel guest;

    private final MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    private final AnonymousLinkAuthenticator authenticator = new AnonymousLinkAuthenticator();

    @BeforeEach
    void wireContext() {
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getEvent()).thenReturn(event);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(form);
        when(event.detail(anyString(), anyString())).thenReturn(event);
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(session.users()).thenReturn(users);
        when(context.getUser()).thenReturn(realUser);
        when(realUser.getId()).thenReturn("real-1");
        when(realUser.getAttributeStream(GuestIdentity.ATTR_LINKED_SUBS)).thenReturn(Stream.empty());
        when(guest.getId()).thenReturn("guest-1");
        when(guest.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn("true");
        when(users.getUserById(realm, "guest-1")).thenReturn(guest);
    }

    private void codeResolves() {
        when(singleUse.remove(anyString())).thenReturn(Map.of(LinkCodes.NOTE_GUEST_SUB, "guest-1"));
    }

    @Test
    void aLoginWithoutALinkCodeIsUntouched() {
        authenticator.authenticate(context);

        verify(context).success();
        verify(singleUse, never()).remove(anyString());
        verify(realUser, never()).setAttribute(anyString(), any());
        verify(event, never()).detail(eq("anon_link"), anyString());
    }

    @Test
    void theCodeIsReadFromTheTokenRequest() {
        // The direct grant has no authorize request; the code rides with the credentials.
        form.putSingle(AnonymousLinkAuthenticator.LINK_CODE_PARAM, CODE);
        codeResolves();

        authenticator.authenticate(context);

        verify(realUser).setAttribute(eq(GuestIdentity.ATTR_LINKED_SUBS), eq(List.of("guest-1")));
    }

    @Test
    void linkingRecordsTheGuestSubjectOnTheAccountAndRemovesTheGuest() {
        form.putSingle(AnonymousLinkAuthenticator.LINK_CODE_PARAM, CODE);
        codeResolves();

        authenticator.authenticate(context);

        verify(realUser).setAttribute(eq(GuestIdentity.ATTR_LINKED_SUBS), eq(List.of("guest-1")));
        verify(users).removeUser(realm, guest);
        verify(event).detail("anon_link", "linked");
        verify(event).detail("anon_guest", "guest-1");
        verify(context).success();
    }

    @Test
    void anExpiredOrReplayedCodeLinksNothingAndStillLetsTheUserIn() {
        form.putSingle(AnonymousLinkAuthenticator.LINK_CODE_PARAM, CODE);
        when(singleUse.remove(anyString())).thenReturn(null);

        authenticator.authenticate(context);

        verify(context).success();
        verify(realUser, never()).setAttribute(anyString(), any());
        verify(event).detail("anon_link", "invalid");
    }

    @Test
    void aGuestThatIsAlreadyGoneIsStillRecordedOnTheAccount() {
        // The row may have been reaped between the code being issued and the login finishing.
        form.putSingle(AnonymousLinkAuthenticator.LINK_CODE_PARAM, CODE);
        codeResolves();
        when(users.getUserById(realm, "guest-1")).thenReturn(null);

        authenticator.authenticate(context);

        verify(realUser).setAttribute(eq(GuestIdentity.ATTR_LINKED_SUBS), eq(List.of("guest-1")));
        verify(users, never()).removeUser(any(), any());
        verify(context).success();
    }

    @Test
    void aCodeNamingTheAccountItselfIsIgnored() {
        form.putSingle(AnonymousLinkAuthenticator.LINK_CODE_PARAM, CODE);
        when(singleUse.remove(anyString())).thenReturn(Map.of(LinkCodes.NOTE_GUEST_SUB, "real-1"));

        authenticator.authenticate(context);

        verify(realUser, never()).setAttribute(anyString(), any());
        verify(users, never()).removeUser(any(), any());
        verify(event).detail("anon_link", "self");
        verify(context).success();
    }

    @Test
    void theLinkingLoginSaysWhenTheGuestWasBornAndHowLongItBrowsed() {
        // Read before removeUser: the account's LOGIN is the only place this survives the guest row.
        int created = Time.currentTime() - 3 * 86_400 - 60;
        when(guest.getFirstAttribute(GuestIdentity.ATTR_CREATED_AT)).thenReturn(String.valueOf(created));
        form.putSingle(AnonymousLinkAuthenticator.LINK_CODE_PARAM, CODE);
        codeResolves();

        authenticator.authenticate(context);

        verify(event).detail("anon_guest_created_at", Instant.ofEpochSecond(created).toString());
        verify(event).detail("anon_guest_age_days", "3");
    }

    @Test
    void aGuestAlreadyGoneLeavesNoBirthDetails() {
        form.putSingle(AnonymousLinkAuthenticator.LINK_CODE_PARAM, CODE);
        codeResolves();
        when(users.getUserById(realm, "guest-1")).thenReturn(null);

        authenticator.authenticate(context);

        verify(event).detail("anon_link", "linked");
        verify(event, never()).detail(eq("anon_guest_created_at"), anyString());
        verify(event, never()).detail(eq("anon_guest_age_days"), anyString());
    }
}
