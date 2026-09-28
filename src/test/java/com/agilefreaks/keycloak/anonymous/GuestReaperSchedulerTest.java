package com.agilefreaks.keycloak.anonymous;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.timer.TimerProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * The sweep is scheduled at boot unless it is turned off, configured through the provider's SPI
 * options ({@code spi-events-listener--anonymous-reaper--*}).
 */
@ExtendWith(MockitoExtension.class)
class GuestReaperSchedulerTest {

    @Mock
    KeycloakSessionFactory factory;
    @Mock
    TimerProvider timer;

    private final GuestReaperScheduler scheduler = new GuestReaperScheduler();

    private static GuestReaperScheduler.Options options(String... keysAndValues) {
        return GuestReaperScheduler.Options.from(MapScope.of(keysAndValues));
    }

    @Test
    void schedulingIsArmedByDefault() {
        scheduler.init(MapScope.of());

        scheduler.postInit(factory);

        verify(factory).register(any());
    }

    @Test
    void turningTheReaperOffSchedulesNothingAtAll() {
        scheduler.init(MapScope.of("enabled", "false"));

        scheduler.postInit(factory);

        verify(factory, never()).register(any());
    }

    @Test
    void theDefaults() {
        GuestReaperScheduler.Options defaults = options();

        assertThat(defaults.enabled()).isTrue();
        assertThat(defaults.maxIdleDays()).isEqualTo(30);
        assertThat(defaults.unusedMaxIdleDays()).isEqualTo(7);
        assertThat(defaults.intervalMinutes()).isEqualTo(6 * 60);
        assertThat(defaults.batch()).isEqualTo(500);
    }

    @Test
    void everyOptionIsRead() {
        GuestReaperScheduler.Options set = options(
                "max-idle-days", "60", "unused-max-idle-days", "2", "interval-hours", "12", "batch", "50");

        assertThat(set.maxIdleDays()).isEqualTo(60);
        assertThat(set.unusedMaxIdleDays()).isEqualTo(2);
        assertThat(set.intervalMinutes()).isEqualTo(12 * 60);
        assertThat(set.batch()).isEqualTo(50);
    }

    @Test
    void minutesWinWhenSetSoASweepCanBeExercised() {
        assertThat(options("interval-hours", "6", "interval-minutes", "1").intervalMinutes()).isEqualTo(1);
    }

    @Test
    void blankValuesMeanTheDefault() {
        GuestReaperScheduler.Options blank = options("max-idle-days", " ", "interval-minutes", "");

        assertThat(blank.maxIdleDays()).isEqualTo(30);
        assertThat(blank.intervalMinutes()).isEqualTo(6 * 60);
    }

    @Test
    void valuesAreTrimmed() {
        assertThat(options("max-idle-days", " 14 ").maxIdleDays()).isEqualTo(14);
    }

    @Test
    void anImpossibleIntervalOrBatchIsClampedRatherThanBusyLooping() {
        assertThat(options("interval-minutes", "0").intervalMinutes()).isEqualTo(1);
        assertThat(options("interval-hours", "0").intervalMinutes()).isEqualTo(60);
        assertThat(options("batch", "0").batch()).isEqualTo(1);
    }

    @Test
    void aNegativeAgeIsClampedToZero() {
        assertThat(options("max-idle-days", "-5").maxIdleDays()).isZero();
        assertThat(options("unused-max-idle-days", "-5").unusedMaxIdleDays()).isZero();
    }

    @Test
    void aValueThatIsNotANumberStopsTheServerAndNamesTheOption() {
        assertThatThrownBy(() -> options("max-idle-days", "thirty"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("max-idle-days")
                .hasMessageContaining("thirty");
    }

    @Test
    void theSwitchTakesOnlyTrueOrFalse() {
        assertThat(options("enabled", "FALSE").enabled()).isFalse();
        assertThat(options("enabled", "true").enabled()).isTrue();
        assertThatThrownBy(() -> options("enabled", "no"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("enabled");
    }

    @Test
    void theSweepIsRegisteredOnTheTimerUnderItsTaskName() {
        GuestReaperScheduler.scheduleOn(timer, options("interval-minutes", "90"));

        verify(timer).scheduleTask(any(GuestReaperTask.class), eq(90 * 60_000L), eq(GuestReaperScheduler.TASK_NAME));
    }

    @Test
    void withoutATimerNothingIsScheduledAndBootCarriesOn() {
        GuestReaperScheduler.scheduleOn(null, options());
    }

    @Test
    void theListenerItselfDoesNothing() {
        assertThat(scheduler.create(null)).isNotNull();
        scheduler.create(null).onEvent(null);
        scheduler.create(null).onEvent(null, false);
        scheduler.create(null).close();
        scheduler.close();
        assertThat(scheduler.getId()).isEqualTo("anonymous-reaper");
        assertThat(GuestReaperScheduler.TASK_NAME).isEqualTo("anonymous-guest-reaper");
    }
}
