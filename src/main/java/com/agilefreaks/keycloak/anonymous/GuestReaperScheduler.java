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
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        if (!Env.flag(Env.REAPER_ENABLED, true)) {
            LOG.infof("guest reaper disabled (%s=false)", Env.REAPER_ENABLED);
            return;
        }
        factory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                schedule(factory);
            }
        });
    }

    /** Minutes win when set, so a sweep can be exercised without waiting out the 6-hour default. */
    static int intervalMinutes() {
        return Math.max(1, Env.number(Env.REAPER_INTERVAL_MINUTES,
                Math.max(1, Env.number(Env.REAPER_INTERVAL_HOURS, 6)) * 60));
    }

    private void schedule(KeycloakSessionFactory factory) {
        int maxIdleDays = Env.number(Env.REAPER_MAX_IDLE_DAYS, 30);
        int intervalMinutes = intervalMinutes();
        int batchSize = Math.max(1, Env.number(Env.REAPER_BATCH, 500));

        KeycloakModelUtils.runJobInTransaction(factory,
                session -> scheduleOn(session.getProvider(TimerProvider.class),
                        maxIdleDays, intervalMinutes, batchSize));
    }

    static void scheduleOn(TimerProvider timer, int maxIdleDays, int intervalMinutes, int batchSize) {
        if (timer == null) {
            LOG.warn("no timer provider available; guest reaper not scheduled");
            return;
        }
        timer.scheduleTask(new GuestReaperTask(maxIdleDays, batchSize),
                intervalMinutes * 60L * 1000L, TASK_NAME);
        LOG.infof("guest reaper scheduled every %dm, deleting guests unused for %dd (batch %d)",
                intervalMinutes, maxIdleDays, batchSize);
    }

    @Override
    public void close() {
    }
}
