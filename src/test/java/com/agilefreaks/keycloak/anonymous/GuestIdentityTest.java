package com.agilefreaks.keycloak.anonymous;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Contract (docs/anonymous-sessions.md): a guest is a PII-free row carrying only the guest
 * markers, and the account it later links to keeps a record of the subjects it absorbed.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GuestIdentityTest {

    @Mock
    KeycloakSession session;
    @Mock
    RealmModel realm;
    @Mock
    UserProvider users;
    @Mock
    UserModel user;
    @Mock
    RoleModel anonymousRole;

    @Test
    void aGuestIsMarkedAndGetsNoDefaultRolesOrRequiredActions() {
        when(realm.getRole(GuestIdentity.ROLE)).thenReturn(anonymousRole);
        when(session.users()).thenReturn(users);
        when(users.addUser(any(), anyString(), anyString(), anyBoolean(), anyBoolean())).thenReturn(user);

        UserModel guest = GuestIdentity.create(session, realm);

        assertThat(guest).isSameAs(user);
        ArgumentCaptor<String> id = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> username = ArgumentCaptor.forClass(String.class);
        verify(users).addUser(eq(realm), id.capture(), username.capture(), eq(false), eq(false));
        assertThat(username.getValue()).isEqualTo("anon-" + id.getValue());
        verify(user).setEnabled(true);
        verify(user).setSingleAttribute(GuestIdentity.ATTR_ANON, "true");
        verify(user).setSingleAttribute(eq(GuestIdentity.ATTR_CREATED_AT), anyString());
        verify(user, never()).setEmail(anyString());
    }

    @Test
    void theGuestRoleLivesOnTheRowSoNoScopeParameterCanDropIt() {
        when(realm.getRole(GuestIdentity.ROLE)).thenReturn(anonymousRole);
        when(session.users()).thenReturn(users);
        when(users.addUser(any(), anyString(), anyString(), anyBoolean(), anyBoolean())).thenReturn(user);

        GuestIdentity.create(session, realm);

        verify(user).grantRole(anonymousRole);
    }

    @Test
    void noGuestIsMintedIfTheRealmHasNoGuestRole() {
        when(realm.getRole(GuestIdentity.ROLE)).thenReturn(null);
        when(session.users()).thenReturn(users);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> GuestIdentity.create(session, realm))
                .isInstanceOf(IllegalStateException.class);
        verify(users, never()).addUser(any(), anyString(), anyString(), anyBoolean(), anyBoolean());
    }

    @Test
    void onlyUsersMarkedAnonCountAsGuests() {
        assertThat(GuestIdentity.isGuest(null)).isFalse();

        when(user.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn(null);
        assertThat(GuestIdentity.isGuest(user)).isFalse();

        when(user.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn("false");
        assertThat(GuestIdentity.isGuest(user)).isFalse();

        when(user.getFirstAttribute(GuestIdentity.ATTR_ANON)).thenReturn("true");
        assertThat(GuestIdentity.isGuest(user)).isTrue();
    }

    @Test
    void creationTimeComesFromTheMarker() {
        int marked = Time.currentTime() - 500;
        when(user.getFirstAttribute(GuestIdentity.ATTR_CREATED_AT)).thenReturn(String.valueOf(marked));

        assertThat(GuestIdentity.createdAt(user)).isEqualTo(marked);
    }

    @Test
    void aMissingOrUnreadableMarkerFallsBackToTheRowTimestamp() {
        long rowMillis = (Time.currentTime() - 900L) * 1000L;
        when(user.getCreatedTimestamp()).thenReturn(rowMillis);

        when(user.getFirstAttribute(GuestIdentity.ATTR_CREATED_AT)).thenReturn(null);
        assertThat(GuestIdentity.createdAt(user)).isEqualTo((int) (rowMillis / 1000L));

        when(user.getFirstAttribute(GuestIdentity.ATTR_CREATED_AT)).thenReturn("not-a-number");
        assertThat(GuestIdentity.createdAt(user)).isEqualTo((int) (rowMillis / 1000L));
    }

    @Test
    void recordLinkAppendsNewestLast() {
        when(user.getAttributeStream(GuestIdentity.ATTR_LINKED_SUBS)).thenReturn(Stream.of("first"));

        GuestIdentity.recordLink(user, "second");

        ArgumentCaptor<List<String>> subs = ArgumentCaptor.forClass(List.class);
        verify(user).setAttribute(eq(GuestIdentity.ATTR_LINKED_SUBS), subs.capture());
        assertThat(subs.getValue()).containsExactly("first", "second");
    }

    @Test
    void recordLinkIsIdempotent() {
        when(user.getAttributeStream(GuestIdentity.ATTR_LINKED_SUBS)).thenReturn(Stream.of("already"));

        GuestIdentity.recordLink(user, "already");

        verify(user, never()).setAttribute(anyString(), any());
    }

    @Test
    void recordLinkKeepsOnlyTheMostRecentTwenty() {
        List<String> existing = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            existing.add("sub-" + i);
        }
        when(user.getAttributeStream(GuestIdentity.ATTR_LINKED_SUBS)).thenReturn(existing.stream());

        GuestIdentity.recordLink(user, "newest");

        ArgumentCaptor<List<String>> subs = ArgumentCaptor.forClass(List.class);
        verify(user).setAttribute(eq(GuestIdentity.ATTR_LINKED_SUBS), subs.capture());
        assertThat(subs.getValue()).hasSize(20);
        assertThat(subs.getValue()).last().isEqualTo("newest");
        assertThat(subs.getValue()).doesNotContain("sub-0");
    }
}
