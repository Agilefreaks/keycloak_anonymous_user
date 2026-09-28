package org.moma.keycloak.anonymous;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Contract (docs/anonymous-sessions.md): the sweep is scheduled at boot unless it is turned off;
 * the interval comes from hours, with a minutes override for exercising it.
 */
@ExtendWith(MockitoExtension.class)
class GuestReaperSchedulerTest {

    @Mock
    KeycloakSessionFactory factory;

    private final GuestReaperScheduler scheduler = new GuestReaperScheduler();

    @AfterEach
    void restoreEnvironment() {
        Env.source = System::getenv;
    }

    private static void env(Map<String, String> values) {
        Env.source = values::get;
    }

    @Test
    void schedulingIsArmedByDefault() {
        env(Map.of());

        scheduler.postInit(factory);

        verify(factory).register(any());
    }

    @Test
    void turningTheReaperOffSchedulesNothingAtAll() {
        env(Map.of(Env.REAPER_ENABLED, "false"));

        scheduler.postInit(factory);

        verify(factory, never()).register(any());
    }

    @Test
    void theDefaultSweepIsEverySixHours() {
        env(Map.of());

        assertThat(GuestReaperScheduler.intervalMinutes()).isEqualTo(6 * 60);
    }

    @Test
    void hoursCanBeChanged() {
        env(Map.of(Env.REAPER_INTERVAL_HOURS, "12"));

        assertThat(GuestReaperScheduler.intervalMinutes()).isEqualTo(12 * 60);
    }

    @Test
    void minutesWinWhenSetSoASweepCanBeExercised() {
        env(Map.of(Env.REAPER_INTERVAL_HOURS, "6", Env.REAPER_INTERVAL_MINUTES, "1"));

        assertThat(GuestReaperScheduler.intervalMinutes()).isEqualTo(1);
    }

    @Test
    void anImpossibleIntervalIsClampedRatherThanBusyLooping() {
        env(Map.of(Env.REAPER_INTERVAL_MINUTES, "0"));

        assertThat(GuestReaperScheduler.intervalMinutes()).isEqualTo(1);
    }

    @Test
    void theListenerItselfDoesNothing() {
        assertThat(scheduler.create(null)).isNotNull();
        assertThat(scheduler.getId()).isEqualTo("moma-anon-reaper");
    }
}
