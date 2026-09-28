package com.agilefreaks.keycloak.anonymous;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.timer.TimerProvider;

/**
 * Registers {@link GuestReaperTask} on Keycloak's timer at boot.
 *
 * <p>It is an event-listener factory only because {@code postInit} is the hook an extension gets at
 * server start — the listener itself does nothing and does not need enabling on any realm. Scheduled
 * unguarded, so it assumes a single Keycloak instance; a clustered deployment would want
 * {@code ClusterProvider.executeIfNotExecuted} around the task body.
 */
public class GuestReaperScheduler implements EventListenerProviderFactory {

    private static final Logger LOG = Logger.getLogger(GuestReaperScheduler.class);

    public static final String PROVIDER_ID = "anonymous-reaper";
    static final String TASK_NAME = "anonymous-guest-reaper";

    private static final EventListenerProvider NOOP = new EventListenerProvider() {
        @Override
        public void onEvent(org.keycloak.events.Event event) {
        }

        @Override
        public void onEvent(org.keycloak.events.admin.AdminEvent adminEvent, boolean includeRepresentation) {
        }

        @Override
        public void close() {
        }
    };

    private Options options;

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return NOOP;
    }

    @Override
    public void init(Config.Scope config) {
        options = Options.from(config);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        if (!options.enabled()) {
            LOG.info("guest reaper disabled (spi-events-listener--anonymous-reaper--enabled=false)");
            return;
        }
        factory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                KeycloakModelUtils.runJobInTransaction(factory,
                        session -> scheduleOn(session.getProvider(TimerProvider.class), options));
            }
        });
    }

    static void scheduleOn(TimerProvider timer, Options options) {
        if (timer == null) {
            LOG.warn("no timer provider available; guest reaper not scheduled");
            return;
        }
        timer.scheduleTask(new GuestReaperTask(options.maxIdleDays(), options.unusedMaxIdleDays(), options.batch()),
                options.intervalMinutes() * 60L * 1000L, TASK_NAME);
        LOG.infof("guest reaper scheduled every %dm, deleting guests idle for %dd, or %dd if never refreshed (batch %d)",
                options.intervalMinutes(), options.maxIdleDays(), options.unusedMaxIdleDays(), options.batch());
    }

    @Override
    public void close() {
    }

    /** The reaper's SPI options. A malformed value stops the server rather than silently using a default. */
    record Options(boolean enabled, int maxIdleDays, int unusedMaxIdleDays, int intervalMinutes, int batch) {

        static Options from(Config.Scope scope) {
            SpiOptions options = new SpiOptions(scope, "spi-events-listener--" + PROVIDER_ID + "--");
            Integer minutes = options.number("interval-minutes");
            int hours = Math.max(1, options.number("interval-hours", 6));
            return new Options(
                    options.flag("enabled", true),
                    Math.max(0, options.number("max-idle-days", 30)),
                    Math.max(0, options.number("unused-max-idle-days", 7)),
                    Math.max(1, minutes != null ? minutes : hours * 60),
                    Math.max(1, options.number("batch", 500)));
        }
    }
}
