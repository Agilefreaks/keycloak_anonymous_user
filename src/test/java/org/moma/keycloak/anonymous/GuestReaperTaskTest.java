package org.moma.keycloak.anonymous;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Contract (docs/anonymous-sessions.md): guests nobody has used since the cutoff are deleted along
 * with their sessions, at most `batch` per sweep. Idleness is last use, not row age — the realm's
 * sessions outlive any sane cutoff, and a guest still using the app must not lose its identity.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GuestReaperTaskTest {

    @Mock
    KeycloakSession session;
    @Mock
    KeycloakContext keycloakContext;
    @Mock
    RealmProvider realms;
    @Mock
    UserProvider users;
    @Mock
    UserSessionProvider sessions;
    @Mock
    RealmModel realm;

    private final int now = Time.currentTime();

    @BeforeEach
    void wireSession() {
        when(session.getContext()).thenReturn(keycloakContext);
        when(session.realms()).thenReturn(realms);
        when(session.users()).thenReturn(users);
        when(session.sessions()).thenReturn(sessions);
        when(realms.getRealmsStream()).thenReturn(Stream.of(realm));
        when(realm.getName()).thenReturn("moma");
        // thenAnswer, not thenReturn: a Stream is consumed once and every guest triggers a lookup.
        when(sessions.getUserSessionsStream(any(), any(UserModel.class)))
                .thenAnswer(invocation -> Stream.empty());
        when(sessions.getOfflineUserSessionsStream(any(), any(UserModel.class)))
                .thenAnswer(invocation -> Stream.empty());
    }

    private UserModel guest(String id, int createdAt) {
        UserModel u = mock(UserModel.class);
        when(u.getId()).thenReturn(id);
        when(u.getFirstAttribute(GuestIdentity.ATTR_CREATED_AT)).thenReturn(String.valueOf(createdAt));
        return u;
    }

    private void candidates(UserModel... found) {
        List<UserModel> all = List.of(found);
        when(users.searchForUserStream(eq(realm), eq(GuestReaperTask.GUESTS), anyInt(), anyInt()))
                .thenAnswer(invocation -> {
                    int first = invocation.getArgument(2);
                    int max = invocation.getArgument(3);
                    return all.stream().skip(first).limit(max);
                });
    }

    private UserModel[] oldGuests(int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> guest("g" + i, now - 100 * 24 * 3600))
                .toArray(UserModel[]::new);
    }

    private UserSessionModel refreshedAt(int when) {
        UserSessionModel s = mock(UserSessionModel.class);
        when(s.getLastSessionRefresh()).thenReturn(when);
        return s;
    }

    @Test
    void aSweepRunsAgainstTheRealmItIsClearing() {
        candidates();

        new GuestReaperTask(30, 500).run(session);

        // Without a realm on the context the user store throws "Session not bound to a realm".
        verify(keycloakContext).setRealm(realm);
    }

    @Test
    void aGuestNobodyHasUsedSinceTheCutoffIsDeletedWithItsSessions() {
        UserModel abandoned = guest("abandoned", now - 90 * 24 * 3600);
        candidates(abandoned);
        when(sessions.getUserSessionsStream(realm, abandoned))
                .thenAnswer(invocation -> Stream.of(refreshedAt(now - 60 * 24 * 3600)));

        new GuestReaperTask(30, 500).run(session);

        verify(sessions).removeUserSessions(realm, abandoned);
        verify(users).removeUser(realm, abandoned);
    }

    @Test
    void aGuestStillRefreshingItsTokenSurvivesHoweverOldItIs() {
        UserModel active = guest("active", now - 400 * 24 * 3600);
        candidates(active);
        when(sessions.getUserSessionsStream(realm, active))
                .thenAnswer(invocation -> Stream.of(refreshedAt(now - 3600)));

        new GuestReaperTask(30, 500).run(session);

        verify(users, never()).removeUser(any(), any());
    }

    @Test
    void anOfflineSessionCountsAsUseToo() {
        UserModel mobile = guest("mobile", now - 400 * 24 * 3600);
        candidates(mobile);
        when(sessions.getOfflineUserSessionsStream(realm, mobile))
                .thenAnswer(invocation -> Stream.of(refreshedAt(now - 2 * 24 * 3600)));

        new GuestReaperTask(30, 500).run(session);

        verify(users, never()).removeUser(any(), any());
    }

    @Test
    void aGuestThatNeverCameBackAfterBeingCreatedIsJudgedOnItsCreationDate() {
        UserModel young = guest("young", now - 3600);
        UserModel old = guest("old", now - 90 * 24 * 3600);
        candidates(young, old);

        new GuestReaperTask(30, 500).run(session);

        verify(users, never()).removeUser(realm, young);
        verify(users).removeUser(realm, old);
    }

    @Test
    void aGuestYoungerThanTheCutoffCostsNoSessionLookup() {
        UserModel young = guest("young", now - 3600);
        candidates(young);

        new GuestReaperTask(30, 500).run(session);

        verify(sessions, never()).getUserSessionsStream(any(), any(UserModel.class));
        verify(sessions, never()).getOfflineUserSessionsStream(any(), any(UserModel.class));
        verify(users, never()).removeUser(any(), any());
    }

    @Test
    void noMoreThanTheBatchSizeGoesInOneSweep() {
        candidates(guest("a", now - 100 * 24 * 3600),
                guest("b", now - 100 * 24 * 3600),
                guest("c", now - 100 * 24 * 3600));

        new GuestReaperTask(30, 2).run(session);

        verify(users, times(2)).removeUser(eq(realm), any());
    }

    @Test
    void guestsBeyondTheFirstPageAreReachedToo() {
        candidates(oldGuests(GuestReaperTask.PAGE_SIZE + 50));

        new GuestReaperTask(30, 500).run(session);

        verify(users, times(GuestReaperTask.PAGE_SIZE + 50)).removeUser(eq(realm), any());
    }

    @Test
    void pagingStopsOnceTheBatchIsFilled() {
        candidates(oldGuests(GuestReaperTask.PAGE_SIZE + 50));

        new GuestReaperTask(30, 2).run(session);

        verify(users, never()).searchForUserStream(any(), eq(GuestReaperTask.GUESTS), eq(GuestReaperTask.PAGE_SIZE), anyInt());
        verify(users, times(2)).removeUser(eq(realm), any());
    }

    @Test
    void oneStubbornGuestDoesNotStopTheSweep() {
        UserModel bad = guest("bad", now - 100 * 24 * 3600);
        UserModel good = guest("good", now - 100 * 24 * 3600);
        candidates(bad, good);
        org.mockito.Mockito.doThrow(new IllegalStateException("fk violation"))
                .when(users).removeUser(realm, bad);

        new GuestReaperTask(30, 500).run(session);

        verify(users).removeUser(realm, good);
    }
}
