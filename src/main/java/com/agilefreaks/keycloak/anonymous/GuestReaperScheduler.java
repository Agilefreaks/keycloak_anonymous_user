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
            Integer minutes = number(scope, "interval-minutes");
            int hours = Math.max(1, orDefault(number(scope, "interval-hours"), 6));
            return new Options(
                    flag(scope, "enabled", true),
                    Math.max(0, orDefault(number(scope, "max-idle-days"), 30)),
                    Math.max(0, orDefault(number(scope, "unused-max-idle-days"), 7)),
                    Math.max(1, minutes != null ? minutes : hours * 60),
                    Math.max(1, orDefault(number(scope, "batch"), 500)));
        }

        private static String text(Config.Scope scope, String key) {
            String raw = scope.get(key);
            return raw == null || raw.isBlank() ? null : raw.trim();
        }

        private static boolean flag(Config.Scope scope, String key, boolean fallback) {
            String raw = text(scope, key);
            if (raw == null) {
                return fallback;
            }
            if (raw.equalsIgnoreCase("true") || raw.equalsIgnoreCase("false")) {
                return Boolean.parseBoolean(raw);
            }
            throw new IllegalArgumentException(invalid(key, "true or false", raw));
        }

        private static String invalid(String key, String expected, String raw) {
            return "spi-events-listener--" + PROVIDER_ID + "--" + key + " must be " + expected + ", got '" + raw + "'";
        }

        private static Integer number(Config.Scope scope, String key) {
            String raw = text(scope, key);
            if (raw == null) {
                return null;
            }
            try {
                return Integer.parseInt(raw);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(invalid(key, "a whole number", raw), e);
            }
        }

        private static int orDefault(Integer value, int fallback) {
            return value == null ? fallback : value;
        }
    }
}
