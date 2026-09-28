package com.agilefreaks.keycloak.anonymous;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MintRateGateTest {

    private static final long NOW = 1_700_000_000L;
    private static final String REALM = "realm-1";
    private static final String IP = "203.0.113.7";

    private final MutableClock clock = new MutableClock(NOW);
    private final InMemoryCounterStore store = new InMemoryCounterStore(clock);

    private MintRateGate gate(int perIpPerHour, int perRealmPerHour) {
        return new MintRateGate(store, clock, new MintOptions(perIpPerHour, perRealmPerHour, "", ""));
    }

    @Test
    void allowsTheFirstMint() {
        assertThat(gate(30, 2000).reserve(REALM, IP).allowed()).isTrue();
    }

    @Test
    void throttlesOneAddressPastItsHourlyBudget() {
        MintRateGate gate = gate(3, 1000);
        for (int i = 0; i < 3; i++) {
            assertThat(gate.reserve(REALM, IP).allowed()).as("mint " + (i + 1)).isTrue();
        }

        MintRateGate.Decision fourth = gate.reserve(REALM, IP);

        assertThat(fourth.refusal()).isEqualTo(MintRefusal.THROTTLED_IP);
        assertThat(fourth.retryAfterSeconds()).isEqualTo(MintRateGate.HOUR_SECONDS);
    }

    @Test
    void retryAfterCountsDownToTheEndOfTheWindow() {
        MintRateGate gate = gate(1, 1000);
        gate.reserve(REALM, IP);
        clock.advanceSeconds(1_000);

        assertThat(gate.reserve(REALM, IP).retryAfterSeconds()).isEqualTo(MintRateGate.HOUR_SECONDS - 1_000);
    }

    @Test
    void anotherAddressHasItsOwnBudget() {
        MintRateGate gate = gate(1, 1000);
        gate.reserve(REALM, IP);

        assertThat(gate.reserve(REALM, IP).allowed()).isFalse();
        assertThat(gate.reserve(REALM, "198.51.100.4").allowed()).isTrue();
    }

    @Test
    void theAddressBudgetComesBackOnceTheHourIsOver() {
        MintRateGate gate = gate(1, 1000);
        gate.reserve(REALM, IP);
        clock.advanceSeconds(MintRateGate.HOUR_SECONDS - 1);
        assertThat(gate.reserve(REALM, IP).allowed()).isFalse();

        clock.advanceSeconds(1);

        assertThat(gate.reserve(REALM, IP).allowed()).isTrue();
    }

    @Test
    void theWindowIsFixedNotSliding() {
        // A refused request does not push the window out: the budget returns an hour after the first mint.
        MintRateGate gate = gate(1, 1000);
        gate.reserve(REALM, IP);
        clock.advanceSeconds(3_000);
        gate.reserve(REALM, IP);
        clock.advanceSeconds(600);

        assertThat(gate.reserve(REALM, IP).allowed()).isTrue();
    }

    @Test
    void theRealmBudgetCatchesADistributedFlood() {
        MintRateGate gate = gate(1000, 3);
        for (int i = 0; i < 3; i++) {
            assertThat(gate.reserve(REALM, "10.0.0." + i).allowed()).isTrue();
        }

        MintRateGate.Decision refused = gate.reserve(REALM, "10.0.0.99");

        assertThat(refused.refusal()).isEqualTo(MintRefusal.THROTTLED_REALM);
        assertThat(refused.retryAfterSeconds()).isPositive();
    }

    @Test
    void theRealmBudgetIsPerRealm() {
        MintRateGate gate = gate(0, 1);
        gate.reserve(REALM, IP);

        assertThat(gate.reserve(REALM, IP).refusal()).isEqualTo(MintRefusal.THROTTLED_REALM);
        assertThat(gate.reserve("realm-2", IP).allowed()).isTrue();
    }

    @Test
    void theRealmBudgetComesBackOnceTheHourIsOver() {
        MintRateGate gate = gate(0, 1);
        gate.reserve(REALM, IP);
        clock.advanceSeconds(MintRateGate.HOUR_SECONDS);

        assertThat(gate.reserve(REALM, IP).allowed()).isTrue();
    }

    @Test
    void zeroDisablesOnlyThatCounter() {
        MintRateGate onlyRealm = gate(0, 2);

        assertThat(onlyRealm.reserve(REALM, IP).allowed()).isTrue();
        assertThat(onlyRealm.reserve(REALM, IP).allowed()).isTrue();
        assertThat(onlyRealm.reserve(REALM, IP).refusal()).isEqualTo(MintRefusal.THROTTLED_REALM);
    }

    @Test
    void bothCountersDisabledNeverRefusesAndStoresNothing() {
        MintRateGate open = gate(0, 0);
        for (int i = 0; i < 50; i++) {
            assertThat(open.reserve(REALM, IP).allowed()).isTrue();
        }
        assertThat(store.size()).isZero();
    }

    @Test
    void aRefusalChargesNoOtherCounter() {
        MintRateGate gate = gate(1, 2);
        gate.reserve(REALM, IP);
        gate.reserve(REALM, IP); // refused on the address

        assertThat(gate.reserve(REALM, "198.51.100.4").allowed()).isTrue();
    }

    @Test
    void anUnknownAddressSkipsTheAddressCounter() {
        MintRateGate gate = gate(1, 1000);

        assertThat(gate.reserve(REALM, null).allowed()).isTrue();
        assertThat(gate.reserve(REALM, " ").allowed()).isTrue();
        assertThat(gate.reserve(REALM, null).allowed()).isTrue();
    }

    @Test
    void anUnreadableCounterStartsAFreshWindow() {
        store.put(MintRateGate.ipKey(REALM, IP), Map.of("count", "lots"), 3600);

        assertThat(gate(1, 1000).reserve(REALM, IP).allowed()).isTrue();
    }

    @Test
    void countersAreNamespacedInTheSharedStore() {
        assertThat(MintRateGate.ipKey(REALM, IP)).isEqualTo("anonymous.mint.ip." + REALM + ":" + IP);
        assertThat(MintRateGate.realmKey(REALM)).isEqualTo("anonymous.mint.realm." + REALM);
    }
}
