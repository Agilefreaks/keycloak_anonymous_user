package com.agilefreaks.keycloak.anonymous;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * The mint-rate guards: per client IP per hour, and a realm-wide hourly budget. {@link #reserve}
 * consumes as well as checks, so a mint that later fails still costs budget.
 */
final class MintRateGate {

    static final long HOUR_SECONDS = 3_600L;

    private static final String PREFIX = "anonymous.mint.";

    private final CounterStore store;
    private final Clock clock;
    private final MintOptions options;

    MintRateGate(CounterStore store, Clock clock, MintOptions options) {
        this.store = store;
        this.clock = clock;
        this.options = options;
    }

    static String ipKey(String realmId, String ip) {
        return PREFIX + "ip." + realmId + ":" + ip;
    }

    static String realmKey(String realmId) {
        return PREFIX + "realm." + realmId;
    }

    Decision reserve(String realmId, String ip) {
        long now = clock.instant().getEpochSecond();

        List<Guard> guards = new ArrayList<>(2);
        if (options.maxMintsPerIpPerHour() > 0 && ip != null && !ip.isBlank()) {
            guards.add(new Guard(ipKey(realmId, ip), options.maxMintsPerIpPerHour(), MintRefusal.THROTTLED_IP));
        }
        if (options.maxMintsPerRealmPerHour() > 0) {
            guards.add(new Guard(realmKey(realmId), options.maxMintsPerRealmPerHour(), MintRefusal.THROTTLED_REALM));
        }

        // Every guard is read before any is written, so a refusal never charges the ones that passed.
        List<CounterRecord> charged = new ArrayList<>(guards.size());
        for (Guard guard : guards) {
            CounterRecord current = currentCount(guard, now);
            if (current.count() >= guard.max()) {
                long elapsed = now - current.windowStartEpochSeconds();
                return new Decision(guard.refusal(), Math.max(HOUR_SECONDS - elapsed, 1));
            }
            charged.add(current.increment());
        }

        for (int i = 0; i < guards.size(); i++) {
            store.put(guards.get(i).key(), charged.get(i).toNotes(), HOUR_SECONDS);
        }
        return Decision.ALLOWED;
    }

    private CounterRecord currentCount(Guard guard, long now) {
        return store.get(guard.key())
                .flatMap(CounterRecord::fromNotes)
                .filter(record -> !record.isExpired(now, HOUR_SECONDS))
                .orElseGet(() -> new CounterRecord(0, now));
    }

    private record Guard(String key, int max, MintRefusal refusal) {
    }

    /** {@code refusal} is null when the mint may go ahead. */
    record Decision(MintRefusal refusal, long retryAfterSeconds) {

        static final Decision ALLOWED = new Decision(null, 0);

        static Decision refused(MintRefusal refusal) {
            return new Decision(refusal, 0);
        }

        boolean allowed() {
            return refusal == null;
        }
    }
}
