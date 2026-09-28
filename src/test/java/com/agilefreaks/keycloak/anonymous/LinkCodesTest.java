package com.agilefreaks.keycloak.anonymous;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Contract (docs/anonymous-sessions.md): the link code is single-use, short-lived, and carries the
 * guest subject — never the guest token itself, which would outlive a leak.
 */
@ExtendWith(MockitoExtension.class)
class LinkCodesTest {

    @Mock
    KeycloakSession session;
    @Mock
    SingleUseObjectProvider singleUse;

    @Test
    void anIssuedCodeCarriesTheGuestSubject() {
        when(session.singleUseObjects()).thenReturn(singleUse);

        String code = LinkCodes.issue(session, "guest-123");

        assertThat(code).hasSize(32);
        ArgumentCaptor<Map<String, String>> notes = ArgumentCaptor.forClass(Map.class);
        verify(singleUse).put(anyString(), eq((long) LinkCodes.TTL_SECONDS), notes.capture());
        assertThat(notes.getValue()).containsEntry(LinkCodes.NOTE_GUEST_SUB, "guest-123");
    }

    @Test
    void codesAreNamespacedSoTheyCannotCollideWithOtherSingleUseObjects() {
        when(session.singleUseObjects()).thenReturn(singleUse);

        String code = LinkCodes.issue(session, "guest-123");

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(singleUse).put(key.capture(), anyLong(), anyMap());
        assertThat(key.getValue()).isEqualTo("moma.anon.link." + code);
    }

    @Test
    void consumingACodeInvalidatesIt() {
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(singleUse.remove(anyString())).thenReturn(Map.of(LinkCodes.NOTE_GUEST_SUB, "guest-9"));

        Map<String, String> notes = LinkCodes.consume(session, "somecode");

        assertThat(notes).containsEntry(LinkCodes.NOTE_GUEST_SUB, "guest-9");
        verify(singleUse).remove("moma.anon.link.somecode");
    }

    @Test
    void anUnknownOrReplayedCodeYieldsNothing() {
        when(session.singleUseObjects()).thenReturn(singleUse);
        when(singleUse.remove(anyString())).thenReturn(null);

        assertThat(LinkCodes.consume(session, "gone")).isNull();
    }
}
