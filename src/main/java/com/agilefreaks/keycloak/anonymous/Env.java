package com.agilefreaks.keycloak.anonymous;

import org.jboss.logging.Logger;

import java.util.function.UnaryOperator;

/** Plain environment variables for the reaper, which is not an execution and so has no execution config. */
final class Env {

    private static final Logger LOG = Logger.getLogger(Env.class);

    static final String REAPER_ENABLED = "MOMA_ANON_REAPER_ENABLED";
    static final String REAPER_MAX_IDLE_DAYS = "MOMA_ANON_REAPER_MAX_IDLE_DAYS";
    static final String REAPER_INTERVAL_HOURS = "MOMA_ANON_REAPER_INTERVAL_HOURS";
    /** Overrides the hours when set — for exercising a sweep without waiting hours for it. */
    static final String REAPER_INTERVAL_MINUTES = "MOMA_ANON_REAPER_INTERVAL_MINUTES";
    static final String REAPER_BATCH = "MOMA_ANON_REAPER_BATCH";

    /** Swapped by the tests; production always reads the process environment. */
    static UnaryOperator<String> source = System::getenv;

    private Env() {
    }

    static boolean flag(String name, boolean fallback) {
        String raw = source.apply(name);
        return raw == null || raw.isBlank() ? fallback : Boolean.parseBoolean(raw.trim());
    }

    static int number(String name, int fallback) {
        String raw = source.apply(name);
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            LOG.warnf("%s is not a number ('%s'); using %d", name, raw, fallback);
            return fallback;
        }
    }
}
